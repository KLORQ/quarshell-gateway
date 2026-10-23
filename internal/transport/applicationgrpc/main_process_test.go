package applicationgrpc

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	runtimev1 "github.com/KLORQ/quarshell-proto/gen/go/cautem/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type mainProcessRuntime struct {
	terminal *mainProcessTerminal
	cols     uint32
	rows     uint32
	signal   driver.ExecProcessSignal
}

func (r *mainProcessRuntime) Create(context.Context, sandboxruntime.Sandbox) (string, error) {
	return "runtime-id", nil
}
func (*mainProcessRuntime) Start(context.Context, sandboxruntime.Sandbox) error { return nil }
func (*mainProcessRuntime) Stop(context.Context, sandboxruntime.Sandbox) error  { return nil }
func (*mainProcessRuntime) Delete(context.Context, sandboxruntime.Sandbox) error {
	return nil
}
func (*mainProcessRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{Status: "running"}, nil
}
func (r *mainProcessRuntime) PTY(context.Context, sandboxruntime.Sandbox, uint32, uint32) (io.ReadWriteCloser, error) {
	return r.terminal, nil
}
func (r *mainProcessRuntime) ResizePTY(_ context.Context, _ sandboxruntime.Sandbox, cols, rows uint32) error {
	r.cols, r.rows = cols, rows
	r.terminal.markReady()
	return nil
}
func (*mainProcessRuntime) WaitMainProcess(context.Context, sandboxruntime.Sandbox) (int, error) {
	return 13, nil
}
func (r *mainProcessRuntime) SignalMainProcess(_ context.Context, _ sandboxruntime.Sandbox, signal driver.ExecProcessSignal) error {
	r.signal = signal
	return nil
}

type mainProcessTerminal struct {
	mu       sync.Mutex
	stdin    bytes.Buffer
	output   *bytes.Reader
	ready    chan struct{}
	readyOne sync.Once
}

func TestSignalMainProcessRPCUsesWorkspaceScopedCanonicalProcess(t *testing.T) {
	runtime := &mainProcessRuntime{terminal: newMainProcessTerminal()}
	sandboxes, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	sandboxes.Runtime = runtime
	if _, _, err := sandboxes.Create(context.Background(), sandboxapp.Request{
		Workspace: "team", Sandbox: "agent", Generation: domain.Generation(1),
		Image: "alpine:3.22", Command: []string{"sleep", "30"}, TTY: true, IdempotencyKey: "create-signal-main",
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{Sandboxes: sandboxes}
	_, err = server.Signal(context.Background(), &runtimev1.MainProcessServiceSignalRequest{
		Workspace: "team", Sandbox: "agent", Signal: runtimev1.MainProcessSignal_MAIN_PROCESS_SIGNAL_INTERRUPT,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.signal != driver.ExecSignalInterrupt {
		t.Fatalf("main-process signal=%q, want %q", runtime.signal, driver.ExecSignalInterrupt)
	}
}

func newMainProcessTerminal() *mainProcessTerminal {
	return &mainProcessTerminal{output: bytes.NewReader([]byte("canonical-output")), ready: make(chan struct{})}
}
func (t *mainProcessTerminal) markReady() { t.readyOne.Do(func() { close(t.ready) }) }
func (t *mainProcessTerminal) Read(p []byte) (int, error) {
	<-t.ready
	return t.output.Read(p)
}
func (t *mainProcessTerminal) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, err := t.stdin.Write(p)
	return n, err
}
func (*mainProcessTerminal) Close() error { return nil }

func TestAttachTTYStreamsCanonicalMainProcessAndExit(t *testing.T) {
	terminal := newMainProcessTerminal()
	runtime := &mainProcessRuntime{terminal: terminal}
	sandboxes, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	sandboxes.Runtime = runtime
	_, _, err = sandboxes.Create(context.Background(), sandboxapp.Request{
		Workspace: "team", Sandbox: "agent", Generation: domain.Generation(1),
		Image: "alpine:3.22", Command: []string{"/bin/sh"}, TTY: true, IdempotencyKey: "create-main-process",
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	application := &Server{Sandboxes: sandboxes}
	runtimev1.RegisterMainProcessServiceServer(server, application)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	stream, err := runtimev1.NewMainProcessServiceClient(connection).AttachTTY(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&runtimev1.MainProcessServiceAttachTTYRequest{Payload: &runtimev1.MainProcessServiceAttachTTYRequest_Start{Start: &runtimev1.MainProcessTTYStart{Workspace: "team", Sandbox: "agent", Cols: 80, Rows: 24}}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&runtimev1.MainProcessServiceAttachTTYRequest{Payload: &runtimev1.MainProcessServiceAttachTTYRequest_Stdin{Stdin: []byte("hello\n")}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&runtimev1.MainProcessServiceAttachTTYRequest{Payload: &runtimev1.MainProcessServiceAttachTTYRequest_Resize{Resize: &runtimev1.MainProcessTTYResize{Cols: 101, Rows: 41}}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	var output []byte
	var exitCode int32 = -1
	for {
		event, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		switch payload := event.GetPayload().(type) {
		case *runtimev1.MainProcessServiceAttachTTYResponse_Stdout:
			output = append(output, payload.Stdout...)
		case *runtimev1.MainProcessServiceAttachTTYResponse_ExitCode:
			exitCode = payload.ExitCode
		}
	}
	if string(output) != "canonical-output" || exitCode != 13 || runtime.cols != 101 || runtime.rows != 41 || terminal.stdin.String() != "hello\n" {
		t.Fatalf("attach output=%q exit=%d resize=%dx%d stdin=%q", output, exitCode, runtime.cols, runtime.rows, terminal.stdin.String())
	}
}
