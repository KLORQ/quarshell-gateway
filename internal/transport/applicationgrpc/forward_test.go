package applicationgrpc

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/token"
	"github.com/KLORQ/quarshell-gateway/internal/sshrelay"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/metadata"
)

type forwardStream struct {
	ctx  context.Context
	recv chan *gatewayv1.TcpForwardFrame
	sent chan *gatewayv1.TcpForwardFrame
}

func (s *forwardStream) Recv() (*gatewayv1.TcpForwardFrame, error) {
	frame, ok := <-s.recv
	if !ok {
		return nil, io.EOF
	}
	return frame, nil
}
func (s *forwardStream) Send(frame *gatewayv1.TcpForwardFrame) error {
	s.sent <- frame
	return nil
}
func (s *forwardStream) Context() context.Context     { return s.ctx }
func (s *forwardStream) SetHeader(metadata.MD) error  { return nil }
func (s *forwardStream) SendHeader(metadata.MD) error { return nil }
func (s *forwardStream) SetTrailer(metadata.MD)       {}
func (s *forwardStream) SendMsg(any) error            { return nil }
func (s *forwardStream) RecvMsg(any) error            { return nil }

func TestForwardTcpEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sandboxes, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"}); err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	defer close(done)
	if _, err := hub.RegisterSupervisor("sb", "instance", 1, func(channel, target string) error {
		go func() {
			stream, err := hub.AcceptRelay("sb", channel)
			if err != nil {
				return
			}
			defer stream.Close()
			buffer := make([]byte, 1024)
			for {
				n, err := stream.Read(buffer)
				if n > 0 {
					_, _ = stream.Write(buffer[:n])
				}
				if err != nil {
					return
				}
			}
		}()
		return nil
	}, done, func() {}); err != nil {
		t.Fatal(err)
	}
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, started.RuntimeGenerationOrInitial(), started.CredentialEpochOrInitial(), "session-instance-1-1", "instance", 1); err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.SupervisorHub = hub
	stream := &forwardStream{ctx: ctx, recv: make(chan *gatewayv1.TcpForwardFrame, 4), sent: make(chan *gatewayv1.TcpForwardFrame, 4)}
	ctx = context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "operator", workspace: "ws", sandbox: "sb",
	})
	stream.ctx = ctx
	go func() {
		stream.recv <- &gatewayv1.TcpForwardFrame{Payload: &gatewayv1.TcpForwardFrame_Init{Init: &gatewayv1.TcpForwardInit{
			Sandbox: "sb", Workspace: "ws", Target: &gatewayv1.TcpForwardInit_Tcp{Tcp: &gatewayv1.TcpRelayTarget{Host: "127.0.0.1", Port: 8080}},
		}}}
		stream.recv <- &gatewayv1.TcpForwardFrame{Payload: &gatewayv1.TcpForwardFrame_Data{Data: []byte("ping")}}
	}()
	runErr := make(chan error, 1)
	go func() { runErr <- server.ForwardTcp(stream) }()
	select {
	case frame := <-stream.sent:
		if string(frame.GetData()) != "ping" {
			t.Fatalf("echo = %q", frame.GetData())
		}
	case err := <-runErr:
		t.Fatalf("ForwardTcp: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for echo")
	}
	if _, err := sandboxes.Get(ctx, domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}); err != nil {
		t.Fatal(err)
	}
}

func TestSshSessionTokenAllowsForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sandboxes, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	defer close(done)
	if _, err := hub.RegisterSupervisor("sb", "instance", 1, func(channel, target string) error {
		go func() {
			stream, err := hub.AcceptRelay("sb", channel)
			if err != nil {
				return
			}
			defer stream.Close()
			_, _ = io.Copy(stream, stream)
		}()
		return nil
	}, done, func() {}); err != nil {
		t.Fatal(err)
	}
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, started.RuntimeGenerationOrInitial(), started.CredentialEpochOrInitial(), "session-instance-1-1", "instance", 1); err != nil {
		t.Fatal(err)
	}
	tokens, _ := token.NewService([]byte("0123456789abcdef"), time.Hour)
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.SupervisorHub = hub
	server.Tokens = tokens
	ctx = context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{identityProvider: "operator", workspace: "ws"})
	session, err := server.CreateSshSession(ctx, &gatewayv1.CreateSshSessionRequest{
		WorkspaceScope: &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}},
		Sandbox:        "sb",
	})
	if err != nil || session.GetToken() == "" {
		t.Fatalf("CreateSshSession = %+v err=%v", session, err)
	}
	stream := &forwardStream{ctx: ctx, recv: make(chan *gatewayv1.TcpForwardFrame, 4), sent: make(chan *gatewayv1.TcpForwardFrame, 4)}
	go func() {
		stream.recv <- &gatewayv1.TcpForwardFrame{Payload: &gatewayv1.TcpForwardFrame_Init{Init: &gatewayv1.TcpForwardInit{
			Sandbox: "sb", AuthorizationToken: session.GetToken(), Target: &gatewayv1.TcpForwardInit_Ssh{Ssh: &gatewayv1.SshRelayTarget{}},
		}}}
		stream.recv <- &gatewayv1.TcpForwardFrame{Payload: &gatewayv1.TcpForwardFrame_Data{Data: []byte("ssh")}}
	}()
	go func() { _ = server.ForwardTcp(stream) }()
	select {
	case frame := <-stream.sent:
		if string(frame.GetData()) != "ssh" {
			t.Fatalf("echo = %q", frame.GetData())
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for ssh echo")
	}
	if _, err := server.RevokeSshSession(ctx, &gatewayv1.RevokeSshSessionRequest{Token: session.GetToken()}); err != nil {
		t.Fatalf("RevokeSshSession: %v", err)
	}
}
