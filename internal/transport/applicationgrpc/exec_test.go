package applicationgrpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type execTestRuntime struct {
	request           driver.ExecRequest
	execCalls         int
	result            driver.ExecResult
	err               error
	terminalRequest   driver.ExecTerminalRequest
	terminal          driver.ExecTerminalSession
	terminalOpenCalls int
	streamRequest     driver.ExecTerminalRequest
	stream            driver.ExecStreamSession
	streamCalls       int
	streamAttach      driver.ExecStreamSession
	streamAttachID    string
	streamAttachCalls int
}

type execTimeoutRuntime struct{ execTestRuntime }

func (r *execTimeoutRuntime) Exec(ctx context.Context, _ sandboxruntime.Sandbox, _ driver.ExecRequest) (driver.ExecResult, error) {
	<-ctx.Done()
	return driver.ExecResult{}, ctx.Err()
}

func (*execTestRuntime) Create(context.Context, sandboxruntime.Sandbox) (string, error) {
	return "", nil
}
func (*execTestRuntime) Start(context.Context, sandboxruntime.Sandbox) error  { return nil }
func (*execTestRuntime) Stop(context.Context, sandboxruntime.Sandbox) error   { return nil }
func (*execTestRuntime) Delete(context.Context, sandboxruntime.Sandbox) error { return nil }
func (*execTestRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{}, nil
}
func (r *execTestRuntime) Exec(_ context.Context, _ sandboxruntime.Sandbox, request driver.ExecRequest) (driver.ExecResult, error) {
	r.execCalls++
	r.request = request
	return r.result, r.err
}
func (r *execTestRuntime) OpenExecTerminal(_ context.Context, _ sandboxruntime.Sandbox, request driver.ExecTerminalRequest) (driver.ExecTerminalSession, error) {
	r.terminalRequest = request
	r.terminalOpenCalls++
	return r.terminal, r.err
}
func (r *execTestRuntime) OpenExecStream(_ context.Context, _ sandboxruntime.Sandbox, request driver.ExecTerminalRequest) (driver.ExecStreamSession, error) {
	r.streamRequest = request
	r.streamCalls++
	return r.stream, r.err
}
func (r *execTestRuntime) AttachExecStream(_ context.Context, _ sandboxruntime.Sandbox, sessionID string) (driver.ExecStreamSession, error) {
	r.streamAttachID = sessionID
	r.streamAttachCalls++
	return r.streamAttach, r.err
}

type execTestStreamSession struct {
	outputs     []driver.ExecStreamOutput
	stdin       bytes.Buffer
	stdinClosed chan struct{}
	sessionID   string
	readErr     error
	errReturned bool
}

func (s *execTestStreamSession) Write(payload []byte) (int, error) { return s.stdin.Write(payload) }
func (s *execTestStreamSession) ReadOutput() (driver.ExecStreamOutput, error) {
	if len(s.outputs) == 0 {
		if s.readErr != nil && !s.errReturned {
			s.errReturned = true
			return driver.ExecStreamOutput{}, s.readErr
		}
		return driver.ExecStreamOutput{}, io.EOF
	}
	output := s.outputs[0]
	s.outputs = s.outputs[1:]
	return output, nil
}
func (s *execTestStreamSession) CloseStdin() error {
	select {
	case <-s.stdinClosed:
	default:
		close(s.stdinClosed)
	}
	return nil
}
func (*execTestStreamSession) Close() error        { return nil }
func (s *execTestStreamSession) SessionID() string { return s.sessionID }

type execTestStream struct {
	grpc.ServerStreamingServer[gatewayv1.ExecSandboxEvent]
	ctx    context.Context
	events []*gatewayv1.ExecSandboxEvent
}

func (s *execTestStream) Context() context.Context { return s.ctx }
func (s *execTestStream) Send(event *gatewayv1.ExecSandboxEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestExecSandboxRPC(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	runtime := &execTestRuntime{result: driver.ExecResult{ExitCode: 7, Stdout: []byte("out"), Stderr: []byte("err")}}
	sandboxes.Runtime = runtime
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	stream := &execTestStream{ctx: ctx}
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	err = server.ExecSandbox(&gatewayv1.ExecSandboxRequest{
		WorkspaceScope: selector, Sandbox: "sb", Command: []string{"printf", "hello"},
		Workdir: "/workspace", Environment: map[string]string{"Z": "last", "A": "first"},
		Stdin: []byte("input"), Tty: true, Cols: 100, Rows: 40, NoLoginShell: true, ExecutionTimeout: durationpb.New(5 * time.Second),
	}, stream)
	if err != nil {
		t.Fatalf("ExecSandbox: %v", err)
	}
	if !reflect.DeepEqual(runtime.request.Argv, []string{"printf", "hello"}) || !reflect.DeepEqual(runtime.request.Env, []string{"A=first", "Z=last"}) || string(runtime.request.Stdin) != "input" || !runtime.request.TTY || runtime.request.Columns != 100 || runtime.request.Rows != 40 || !runtime.request.NoLoginShell || runtime.request.WorkDir != "/workspace" {
		t.Fatalf("driver request = %+v", runtime.request)
	}
	if len(stream.events) != 3 || string(stream.events[0].GetStdout().GetData()) != "out" || string(stream.events[1].GetStderr().GetData()) != "err" || stream.events[2].GetExit().GetExitCode() != 7 {
		t.Fatalf("events = %+v", stream.events)
	}
	requestID := "286175e2-d5f4-45bd-99dc-48f8d1032ca8"
	request := &gatewayv1.ExecSandboxRequest{WorkspaceScope: selector, Sandbox: "sb", Command: []string{"true"}, RequestId: requestID}
	completed := &execTestStream{ctx: ctx}
	if err := server.ExecSandbox(request, completed); err != nil {
		t.Fatalf("ExecSandbox with durable request ID: %v", err)
	}
	callsAfterFirstRequest := runtime.execCalls
	if err := server.ExecSandbox(request, &execTestStream{ctx: ctx}); status.Code(err) != codes.Aborted {
		t.Fatalf("completed duplicate request ID status = %v, want Aborted", err)
	}
	if runtime.execCalls != callsAfterFirstRequest {
		t.Fatalf("runtime was invoked for a duplicate completed request ID")
	}
}

func TestExecSandboxExecutionTimeoutCancelsRuntime(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	sandboxes.Runtime = &execTimeoutRuntime{}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	err = server.ExecSandbox(&gatewayv1.ExecSandboxRequest{
		WorkspaceScope: selector, Sandbox: "sb", Command: []string{"sleep", "forever"},
		ExecutionTimeout: durationpb.New(20 * time.Millisecond),
	}, &execTestStream{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("ExecSandbox timeout status = %v, want DeadlineExceeded", err)
	}
}

func TestExecSandboxRPCValidationAndErrors(t *testing.T) {
	server := New("test", nil, nil, nil, nil, nil, nil, nil)
	stream := &execTestStream{ctx: context.Background()}
	if err := server.ExecSandbox(&gatewayv1.ExecSandboxRequest{}, stream); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing sandbox service status = %v", err)
	}

	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(context.Background(), sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	runtime := &execTestRuntime{err: domain.ErrUnavailable}
	sandboxes.Runtime = runtime
	server.Sandboxes = sandboxes
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	request := &gatewayv1.ExecSandboxRequest{WorkspaceScope: selector, Sandbox: "sb", Command: []string{"true"}}
	if err := server.ExecSandbox(request, &execTestStream{ctx: context.Background()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("runtime error status = %v", err)
	}
	request.Environment = map[string]string{"BAD=KEY": "value"}
	if err := server.ExecSandbox(request, &execTestStream{ctx: context.Background()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid environment status = %v", err)
	}
	request.Environment = nil
	request.ExecutionTimeout = durationpb.New(-1)
	if err := server.ExecSandbox(request, &execTestStream{ctx: context.Background()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid timeout status = %v", err)
	}
	request.ExecutionTimeout = nil
	request.RequestId = "d9d0ab40-6110-4d53-9fa8-a2a13b52bc99"
	callsBeforeAdmission := runtime.execCalls
	if err := server.ExecSandbox(request, &execTestStream{ctx: context.Background()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("first request_id execution status = %v", err)
	}
	if err := server.ExecSandbox(request, &execTestStream{ctx: context.Background()}); status.Code(err) != codes.Aborted {
		t.Fatalf("duplicate request_id status = %v", err)
	}
	if runtime.execCalls != callsBeforeAdmission+1 {
		t.Fatalf("runtime executions after duplicate request_id = %d, want one admission", runtime.execCalls-callsBeforeAdmission)
	}
	request.RequestId = ""
	request.Cols = 80
	if err := server.ExecSandbox(request, &execTestStream{ctx: context.Background()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("dimensions without tty status = %v", err)
	}
}

type interactiveExecTestStream struct {
	grpc.ServerStream
	ctx     context.Context
	inputs  chan *gatewayv1.ExecSandboxInput
	sendErr error
	mu      sync.Mutex
	events  []*gatewayv1.ExecSandboxEvent
}

func (s *interactiveExecTestStream) Context() context.Context { return s.ctx }
func (s *interactiveExecTestStream) Recv() (*gatewayv1.ExecSandboxInput, error) {
	input, ok := <-s.inputs
	if !ok {
		return nil, io.EOF
	}
	return input, nil
}
func (s *interactiveExecTestStream) Send(event *gatewayv1.ExecSandboxEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return s.sendErr
}

type interactiveExecTestSession struct {
	output        *bytes.Reader
	sessionID     string
	readImmediate bool
	stdin         bytes.Buffer
	columns, rows uint32
	stdinClosed   bool
	inputDone     chan struct{}
	closeOnce     sync.Once
}

func (s *interactiveExecTestSession) Read(p []byte) (int, error) {
	if s.readImmediate {
		select {
		case <-s.inputDone:
			return 0, io.EOF
		default:
		}
	} else {
		<-s.inputDone
	}
	return s.output.Read(p)
}
func (s *interactiveExecTestSession) Write(p []byte) (int, error) { return s.stdin.Write(p) }
func (s *interactiveExecTestSession) Resize(_ context.Context, columns, rows uint32) error {
	s.columns, s.rows = columns, rows
	return nil
}
func (s *interactiveExecTestSession) Wait(context.Context) (int, error) { return 7, nil }
func (s *interactiveExecTestSession) SessionID() string                 { return s.sessionID }
func (s *interactiveExecTestSession) CloseStdin() error {
	s.stdinClosed = true
	s.closeOnce.Do(func() { close(s.inputDone) })
	return nil
}
func (*interactiveExecTestSession) Close() error { return nil }

type execAttachTestRuntime struct {
	*execTestRuntime
	attachedSession driver.ExecTerminalSession
	attachCalls     int
}

func (r *execAttachTestRuntime) AttachExecTerminal(_ context.Context, _ sandboxruntime.Sandbox, sessionID string) (driver.ExecTerminalSession, error) {
	r.attachCalls++
	if sessionID != "retained-session-id" {
		return nil, status.Error(codes.NotFound, "retained terminal was not found")
	}
	return r.attachedSession, nil
}

func TestExecSandboxInteractiveRelaysInputResizeOutputAndExit(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	session := &interactiveExecTestSession{output: bytes.NewReader([]byte("terminal output")), inputDone: make(chan struct{})}
	runtime := &execTestRuntime{terminal: session}
	sandboxes.Runtime = runtime
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	stream := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 3)}
	stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: &gatewayv1.ExecSandboxRequest{
		WorkspaceScope: selector, Sandbox: "sb", Command: []string{"sh", "-i"}, Tty: true,
		Cols: 100, Rows: 40, Stdin: []byte("initial"), Environment: map[string]string{"Z": "last", "A": "first"},
	}}}
	stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Stdin{Stdin: []byte(" input")}}
	stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Resize{Resize: &gatewayv1.ExecSandboxWindowResize{Cols: 120, Rows: 50}}}
	close(stream.inputs)
	if err := server.ExecSandboxInteractive(stream); err != nil {
		t.Fatalf("interactive exec: %v", err)
	}
	if !reflect.DeepEqual(runtime.terminalRequest.Argv, []string{"sh", "-i"}) || !reflect.DeepEqual(runtime.terminalRequest.Env, []string{"A=first", "Z=last"}) || runtime.terminalRequest.Columns != 100 || runtime.terminalRequest.Rows != 40 {
		t.Fatalf("terminal request = %+v", runtime.terminalRequest)
	}
	if got := session.stdin.String(); got != "initial input" || !session.stdinClosed || session.columns != 120 || session.rows != 50 {
		t.Fatalf("session stdin=%q closed=%v size=%dx%d", got, session.stdinClosed, session.columns, session.rows)
	}
	if len(stream.events) != 2 || string(stream.events[0].GetStdout().GetData()) != "terminal output" || stream.events[1].GetExit().GetExitCode() != 7 {
		t.Fatalf("events = %+v", stream.events)
	}
}

func TestExecSandboxInteractiveReattachesOnDuplicateTTYRequestID(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	first := &interactiveExecTestSession{output: bytes.NewReader([]byte("initial output")), sessionID: "retained-session-id", readImmediate: true, inputDone: make(chan struct{})}
	resumed := &interactiveExecTestSession{output: bytes.NewReader([]byte("resumed output")), sessionID: "retained-session-id", readImmediate: true, inputDone: make(chan struct{})}
	runtime := &execAttachTestRuntime{execTestRuntime: &execTestRuntime{terminal: first}, attachedSession: resumed}
	sandboxes.Runtime = runtime
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	request := &gatewayv1.ExecSandboxRequest{
		WorkspaceScope: selector, Sandbox: "sb", Command: []string{"sh", "-i"}, Tty: true,
		RequestId: "ea4a6087-1a5e-4c44-87e8-bde6f764dd69",
	}
	firstStream := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 1), sendErr: io.ErrClosedPipe}
	firstStream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	close(firstStream.inputs)
	if err := server.ExecSandboxInteractive(firstStream); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("first interactive stream error = %v, want closed-pipe disconnect", err)
	}
	if runtime.terminalOpenCalls != 1 {
		t.Fatalf("initial process launches=%d, want 1", runtime.terminalOpenCalls)
	}

	resumedStream := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 1)}
	resumedStream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	close(resumedStream.inputs)
	if err := server.ExecSandboxInteractive(resumedStream); err != nil {
		t.Fatalf("reattach interactive stream: %v", err)
	}
	if runtime.terminalOpenCalls != 1 || runtime.attachCalls != 1 {
		t.Fatalf("process launches=%d attach calls=%d, want one launch and one attach", runtime.terminalOpenCalls, runtime.attachCalls)
	}
	if len(resumedStream.events) != 2 || string(resumedStream.events[0].GetStdout().GetData()) != "resumed output" || resumedStream.events[1].GetExit().GetExitCode() != 7 {
		t.Fatalf("resumed interactive events = %+v", resumedStream.events)
	}
}

func TestExecSandboxInteractiveStreamsNonTTYAndFencesDuplicate(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	session := &execTestStreamSession{
		outputs:     []driver.ExecStreamOutput{{Stdout: []byte("out")}, {Stderr: []byte("err")}, {ExitCode: 9, Exited: true}},
		stdinClosed: make(chan struct{}),
	}
	runtime := &execTestRuntime{stream: session}
	sandboxes.Runtime = runtime
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	request := &gatewayv1.ExecSandboxRequest{
		WorkspaceScope: selector, Sandbox: "sb", Command: []string{"cat"}, Stdin: []byte("first"),
		RequestId: "c32a780e-faba-4b8a-8ce9-1cf9e82d520d",
	}
	stream := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 2)}
	stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Stdin{Stdin: []byte(" second")}}
	close(stream.inputs)
	if err := server.ExecSandboxInteractive(stream); err != nil {
		t.Fatalf("non-TTY interactive exec: %v", err)
	}
	<-session.stdinClosed
	if got := session.stdin.String(); got != "first second" {
		t.Fatalf("interactive stdin=%q", got)
	}
	if runtime.streamRequest.Argv[0] != "cat" || runtime.streamCalls != 1 {
		t.Fatalf("stream request=%+v calls=%d", runtime.streamRequest, runtime.streamCalls)
	}
	if len(stream.events) != 3 || string(stream.events[0].GetStdout().GetData()) != "out" || string(stream.events[1].GetStderr().GetData()) != "err" || stream.events[2].GetExit().GetExitCode() != 9 {
		t.Fatalf("non-TTY interactive events=%+v", stream.events)
	}
	duplicate := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 1)}
	duplicate.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	close(duplicate.inputs)
	if err := server.ExecSandboxInteractive(duplicate); status.Code(err) != codes.Aborted {
		t.Fatalf("duplicate completed stream request status=%v, want Aborted", err)
	}
	if runtime.streamCalls != 1 {
		t.Fatalf("duplicate launched another stream process; calls=%d", runtime.streamCalls)
	}
}

func TestExecSandboxInteractiveReattachesRetainedNonTTYProcess(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	const sessionID = "0123456789abcdef0123456789abcdef"
	first := &execTestStreamSession{
		sessionID:   sessionID,
		outputs:     []driver.ExecStreamOutput{{Stdout: []byte("before disconnect")}},
		readErr:     io.ErrUnexpectedEOF,
		stdinClosed: make(chan struct{}),
	}
	reattached := &execTestStreamSession{
		sessionID: sessionID,
		outputs: []driver.ExecStreamOutput{
			{Stdout: []byte("retained output")},
			{ExitCode: 7, Exited: true},
		},
		stdinClosed: make(chan struct{}),
	}
	runtime := &execTestRuntime{stream: first, streamAttach: reattached}
	sandboxes.Runtime = runtime
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	request := &gatewayv1.ExecSandboxRequest{
		WorkspaceScope: selector, Sandbox: "sb", Command: []string{"cat"},
		RequestId: "c32a780e-faba-4b8a-8ce9-1cf9e82d520d",
	}
	firstStream := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 1)}
	firstStream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	close(firstStream.inputs)
	if err := server.ExecSandboxInteractive(firstStream); err == nil {
		t.Fatal("first stream ended without reporting its transport loss")
	}

	retry := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 1)}
	retry.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	close(retry.inputs)
	if err := server.ExecSandboxInteractive(retry); err != nil {
		t.Fatalf("reattach retained non-TTY process: %v", err)
	}
	if runtime.streamCalls != 1 || runtime.streamAttachCalls != 1 || runtime.streamAttachID != sessionID {
		t.Fatalf("exec launches=%d attaches=%d attach ID=%q", runtime.streamCalls, runtime.streamAttachCalls, runtime.streamAttachID)
	}
	if len(retry.events) != 2 || string(retry.events[0].GetStdout().GetData()) != "retained output" || retry.events[1].GetExit().GetExitCode() != 7 {
		t.Fatalf("reattached non-TTY events=%+v", retry.events)
	}
}

func TestExecSandboxInteractiveRejectsInvalidStarts(t *testing.T) {
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	valid := func() *gatewayv1.ExecSandboxRequest {
		return &gatewayv1.ExecSandboxRequest{Sandbox: "sb", Command: []string{"true"}, Tty: true}
	}
	cases := []struct {
		name  string
		start *gatewayv1.ExecSandboxRequest
		want  codes.Code
	}{
		{name: "missing start", want: codes.InvalidArgument},
		{name: "non-TTY dimensions are rejected", start: func() *gatewayv1.ExecSandboxRequest { r := valid(); r.Tty = false; r.Cols = 80; return r }(), want: codes.InvalidArgument},
		{name: "request ID must be a UUID", start: func() *gatewayv1.ExecSandboxRequest { r := valid(); r.RequestId = "launch-key"; return r }(), want: codes.InvalidArgument},
		{name: "dimension limit", start: func() *gatewayv1.ExecSandboxRequest { r := valid(); r.Cols = 65536; return r }(), want: codes.InvalidArgument},
		{name: "invalid environment", start: func() *gatewayv1.ExecSandboxRequest {
			r := valid()
			r.Environment = map[string]string{"BAD=KEY": "value"}
			return r
		}(), want: codes.InvalidArgument},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stream := &interactiveExecTestStream{ctx: context.Background(), inputs: make(chan *gatewayv1.ExecSandboxInput, 1)}
			if test.start != nil {
				stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: test.start}}
			}
			close(stream.inputs)
			if err := server.ExecSandboxInteractive(stream); status.Code(err) != test.want {
				t.Fatalf("status = %v, want %s", err, test.want)
			}
		})
	}
}

var _ sandboxruntime.Runtime = (*execTestRuntime)(nil)
