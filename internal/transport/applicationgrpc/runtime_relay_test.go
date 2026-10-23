package applicationgrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/sshrelay"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type relayServerStream struct {
	grpc.ServerStream
	ctx       context.Context
	first     *gatewayv1.RelayFrame
	firstRead bool
	sent      chan *gatewayv1.RelayFrame
}

func (stream *relayServerStream) Context() context.Context { return stream.ctx }
func (stream *relayServerStream) Send(frame *gatewayv1.RelayFrame) error {
	select {
	case stream.sent <- frame:
		return nil
	case <-stream.ctx.Done():
		return stream.ctx.Err()
	}
}
func (stream *relayServerStream) Recv() (*gatewayv1.RelayFrame, error) {
	if !stream.firstRead {
		stream.firstRead = true
		return stream.first, nil
	}
	<-stream.ctx.Done()
	return nil, stream.ctx.Err()
}

func TestRelayStreamReturnsWhenGuestTargetCloses(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start-1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	hub := sshrelay.NewHub()
	opened := make(chan string, 1)
	done := make(chan struct{})
	unregister, err := hub.RegisterSupervisor("sb", "instance-1", 1, func(channel, _ string) error {
		opened <- channel
		return nil
	}, done, nil)
	if err != nil {
		t.Fatalf("RegisterSupervisor: %v", err)
	}
	defer unregister()
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, started.RuntimeGenerationOrInitial(), started.CredentialEpochOrInitial(), "session-instance-1-1", "instance-1", 1); err != nil {
		t.Fatalf("ClaimSupervisorSession: %v", err)
	}

	clientResult := make(chan net.Conn, 1)
	clientErr := make(chan error, 1)
	go func() {
		conn, err := hub.OpenChannel(ctx, "sb", "tcp://127.0.0.1:8080")
		if err != nil {
			clientErr <- err
			return
		}
		clientResult <- conn
	}()
	var channel string
	select {
	case channel = <-opened:
	case <-time.After(time.Second):
		t.Fatal("supervisor was not asked to open a relay")
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamCtx = context.WithValue(streamCtx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", workspace: ref.Workspace, sandbox: ref.Sandbox, generation: 2, credentialEpoch: 2,
	})
	stream := &relayServerStream{
		ctx: streamCtx,
		first: &gatewayv1.RelayFrame{Payload: &gatewayv1.RelayFrame_Init{Init: &gatewayv1.RelayInit{
			ChannelId: channel,
		}}},
		sent: make(chan *gatewayv1.RelayFrame, 1),
	}
	server := &Server{Sandboxes: sandboxes, SupervisorHub: hub}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.RelayStream(stream) }()
	var client net.Conn
	select {
	case client = <-clientResult:
	case err := <-clientErr:
		t.Fatalf("OpenChannel: %v", err)
	case <-time.After(time.Second):
		t.Fatal("relay channel was not accepted")
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write relay data: %v", err)
	}
	select {
	case frame := <-stream.sent:
		if got := string(frame.GetData()); got != "hello" {
			t.Fatalf("relay data = %q, want hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("relay data was not forwarded")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close relay client: %v", err)
	}
	select {
	case err := <-serverErr:
		if err != nil && err != io.EOF {
			t.Fatalf("RelayStream after guest close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RelayStream did not finish after guest target closed")
	}
}

func TestRelayStreamRejectsPendingChannelFromStaleGatewayOwner(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, started.RuntimeGenerationOrInitial(), started.CredentialEpochOrInitial(), "session-1", "instance-1", 1); err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	opened := make(chan string, 1)
	done := make(chan struct{})
	unregister, err := hub.RegisterSupervisor("sb", "instance-1", 1, func(channel, _ string) error {
		opened <- channel
		return nil
	}, done, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	defer close(done)

	openResult := make(chan error, 1)
	go func() {
		connection, err := hub.OpenChannel(ctx, "sb", "tcp://127.0.0.1:8080")
		if connection != nil {
			_ = connection.Close()
		}
		openResult <- err
	}()
	channel := <-opened
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, started.RuntimeGenerationOrInitial(), started.CredentialEpochOrInitial(), "session-2", "instance-1", 2); err != nil {
		t.Fatalf("claim replacement connection epoch: %v", err)
	}

	streamCtx := context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", workspace: ref.Workspace, sandbox: ref.Sandbox,
		generation: started.RuntimeGenerationOrInitial(), credentialEpoch: started.CredentialEpochOrInitial(),
	})
	stream := &relayServerStream{
		ctx:   streamCtx,
		first: &gatewayv1.RelayFrame{Payload: &gatewayv1.RelayFrame_Init{Init: &gatewayv1.RelayInit{ChannelId: channel}}},
		sent:  make(chan *gatewayv1.RelayFrame, 1),
	}
	server := &Server{Sandboxes: sandboxes, SupervisorHub: hub}
	if err := server.RelayStream(stream); status.Code(err) != codes.Aborted {
		t.Fatalf("stale relay status=%s err=%v; want Aborted", status.Code(err), err)
	}
	hub.RejectRelay("sb", channel, errors.New("durable supervisor owner changed"))
	if err := <-openResult; err == nil {
		t.Fatal("stale supervisor relay channel unexpectedly opened")
	}
}

func TestActiveSupervisorRelayIsClosedAfterDurableOwnerHandoff(t *testing.T) {
	ctx := context.Background()
	sandboxes, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	generation := started.RuntimeGenerationOrInitial()
	epoch := started.CredentialEpochOrInitial()
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, generation, epoch, "session-1", "instance-1", 1); err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	defer close(done)
	unregister, err := hub.RegisterSupervisor("sb", "instance-1", 1, func(string, string) error { return nil }, done, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	server := &Server{Sandboxes: sandboxes, SupervisorHub: hub}
	closed := make(chan struct{})
	stopMonitor, ownerLost := server.monitorSupervisorRelayOwner(ctx, ref, generation, epoch, func() { close(closed) })
	defer stopMonitor()
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, generation, epoch, "session-2", "instance-1", 2); err != nil {
		t.Fatalf("claim replacement owner epoch: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("active relay was not closed after durable owner handoff")
	}
	select {
	case <-ownerLost:
	case <-time.After(time.Second):
		t.Fatal("owner monitor did not report the durable handoff")
	}
}

type supervisorConnectStream struct {
	grpc.ServerStream
	ctx  context.Context
	recv chan *gatewayv1.SupervisorMessage
	sent chan *gatewayv1.GatewayMessage
}

func (stream *supervisorConnectStream) Context() context.Context { return stream.ctx }
func (stream *supervisorConnectStream) Send(message *gatewayv1.GatewayMessage) error {
	select {
	case stream.sent <- message:
		return nil
	case <-stream.ctx.Done():
		return stream.ctx.Err()
	}
}
func (stream *supervisorConnectStream) Recv() (*gatewayv1.SupervisorMessage, error) {
	select {
	case message := <-stream.recv:
		return message, nil
	case <-stream.ctx.Done():
		return nil, stream.ctx.Err()
	}
}

func TestConnectSupervisorOwnerLeaseSurvivesGatewayReopen(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	store, err := lifecycle.NewSQLiteStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start-1")
	if err != nil {
		t.Fatal(err)
	}
	principal := authenticatedPrincipal{
		identityProvider: "sandbox-token", workspace: ref.Workspace, sandbox: ref.Sandbox,
		generation: started.RuntimeGenerationOrInitial(), credentialEpoch: started.CredentialEpochOrInitial(),
	}
	newStream := func(instance string, epoch uint64) (*supervisorConnectStream, context.CancelFunc) {
		streamCtx, cancel := context.WithCancel(context.WithValue(ctx, principalContextKey{}, principal))
		stream := &supervisorConnectStream{ctx: streamCtx, recv: make(chan *gatewayv1.SupervisorMessage, 1), sent: make(chan *gatewayv1.GatewayMessage, 4)}
		stream.recv <- &gatewayv1.SupervisorMessage{Payload: &gatewayv1.SupervisorMessage_Hello{Hello: &gatewayv1.SupervisorHello{
			SandboxId: string(ref.Sandbox), InstanceId: instance, ConnectionEpoch: epoch,
		}}}
		return stream, cancel
	}
	waitResult := func(done <-chan error) {
		t.Helper()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("ConnectSupervisor returned %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("ConnectSupervisor did not stop after stream cancellation")
		}
	}

	server1 := New("gateway-1", nil, sandboxes, nil, nil, nil, nil, nil)
	first, cancelFirst := newStream("instance-1", 1)
	firstDone := make(chan error, 1)
	go func() { firstDone <- server1.ConnectSupervisor(first) }()
	var firstAccepted *gatewayv1.SessionAccepted
	select {
	case message := <-first.sent:
		firstAccepted = message.GetSessionAccepted()
	case <-time.After(time.Second):
		t.Fatal("first supervisor session was not accepted")
	}
	if firstAccepted == nil {
		t.Fatalf("first supervisor response=%+v", firstAccepted)
	}
	cancelFirst()
	waitResult(firstDone)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := lifecycle.NewSQLiteStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restartedSandboxes, err := sandboxapp.NewService(reopened)
	if err != nil {
		t.Fatal(err)
	}
	server2 := New("gateway-2", nil, restartedSandboxes, nil, nil, nil, nil, nil)
	other, cancelOther := newStream("instance-2", 1)
	otherDone := make(chan error, 1)
	go func() { otherDone <- server2.ConnectSupervisor(other) }()
	select {
	case message := <-other.sent:
		if message.GetSessionRejected() == nil {
			t.Fatalf("different instance acquired durable owner lease: %+v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("durable owner rejection was not sent")
	}
	waitResult(otherDone)
	cancelOther()

	reconnect, cancelReconnect := newStream("instance-1", 2)
	reconnectDone := make(chan error, 1)
	go func() { reconnectDone <- server2.ConnectSupervisor(reconnect) }()
	select {
	case message := <-reconnect.sent:
		accepted := message.GetSessionAccepted()
		if accepted == nil || accepted.GetSessionId() == firstAccepted.GetSessionId() {
			t.Fatalf("higher-epoch reconnect response=%+v; want a fresh durable session ID", message)
		}
	case <-time.After(time.Second):
		t.Fatal("higher-epoch supervisor reconnect was not accepted")
	}
	cancelReconnect()
	waitResult(reconnectDone)
}
