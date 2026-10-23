package applicationgrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/KLORQ/quarshell-core/domain"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ForwardTcp proxies one byte stream to a sandbox supervisor relay channel.
func (s *Server) ForwardTcp(stream gatewayv1.OpenShell_ForwardTcpServer) error {
	principal, ok := principalFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	if s.SupervisorHub == nil || s.Sandboxes == nil {
		return status.Error(codes.Unavailable, "sandbox relay is not configured")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil {
		return status.Error(codes.InvalidArgument, "first frame must be init")
	}
	sandbox := strings.TrimSpace(init.GetSandbox())
	if sandbox == "" {
		return status.Error(codes.InvalidArgument, "sandbox is required")
	}
	workspace := domain.WorkspaceID(init.GetWorkspace())
	if token := strings.TrimSpace(init.GetAuthorizationToken()); token != "" {
		session, ok := s.sshSession(token)
		if !ok {
			return status.Error(codes.Unauthenticated, "ssh session token is invalid or expired")
		}
		if session.sandbox != domain.SandboxID(sandbox) {
			return status.Error(codes.PermissionDenied, "ssh session does not match sandbox")
		}
		workspace = session.workspace
	} else if principal.sandbox != "" && principal.sandbox != domain.SandboxID(sandbox) {
		return status.Error(codes.PermissionDenied, "sandbox does not match authenticated principal")
	}
	if workspace == "" && principal.workspace != "" {
		workspace = principal.workspace
	}
	if workspace == "" {
		return status.Error(codes.InvalidArgument, "workspace is required")
	}
	ref := domain.SandboxRef{Workspace: workspace, Sandbox: domain.SandboxID(sandbox)}
	current, err := s.Sandboxes.Get(stream.Context(), ref)
	if err != nil {
		return grpcError(err)
	}
	if current.State != "running" {
		return status.Error(codes.FailedPrecondition, "sandbox is not running")
	}
	if err := s.validateSupervisorRelayOwner(stream.Context(), ref, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial()); err != nil {
		return err
	}
	target, err := forwardTarget(init)
	if err != nil {
		return err
	}
	connection, err := s.SupervisorHub.OpenChannel(stream.Context(), sandbox, target)
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	if err := s.validateSupervisorRelayOwner(stream.Context(), ref, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial()); err != nil {
		return err
	}
	var closeOnce sync.Once
	closeConnection := func() { closeOnce.Do(func() { _ = connection.Close() }) }
	stopOwnerMonitor, ownerLost := s.monitorSupervisorRelayOwner(stream.Context(), ref, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial(), closeConnection)
	defer func() { stopOwnerMonitor(); closeConnection() }()

	ctx := stream.Context()
	writeErr := make(chan error, 1)
	go func() {
		for {
			frame, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				if closer, ok := connection.(interface{ CloseWrite() error }); ok {
					_ = closer.CloseWrite()
					writeErr <- nil
					return
				}
				writeErr <- nil
				return
			}
			if err != nil {
				writeErr <- err
				return
			}
			data := frame.GetData()
			if len(data) == 0 {
				continue
			}
			if _, err := connection.Write(data); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	readErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, err := connection.Read(buffer)
			if n > 0 {
				if sendErr := stream.Send(&gatewayv1.TcpForwardFrame{Payload: &gatewayv1.TcpForwardFrame_Data{Data: append([]byte(nil), buffer[:n]...)}}); sendErr != nil {
					readErr <- sendErr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					readErr <- nil
				} else {
					readErr <- err
				}
				return
			}
		}
	}()

	var once sync.Once
	finish := func(err error) error {
		once.Do(closeConnection)
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return nil
		}
		return status.Error(codes.Unavailable, err.Error())
	}
	select {
	case err := <-readErr:
		return finish(err)
	case <-writeErr:
		select {
		case read := <-readErr:
			return finish(read)
		case <-ownerLost:
			return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
		case <-ctx.Done():
			return finish(ctx.Err())
		}
	case <-ownerLost:
		return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
	}
}

func forwardTarget(init *gatewayv1.TcpForwardInit) (string, error) {
	if init.GetSsh() != nil {
		return "ssh", nil
	}
	tcp := init.GetTcp()
	if tcp == nil {
		return "", status.Error(codes.InvalidArgument, "forward target is required")
	}
	host := strings.Trim(strings.TrimSpace(tcp.GetHost()), "[]")
	if host == "" {
		host = "127.0.0.1"
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", status.Error(codes.InvalidArgument, "forward target must be loopback")
		}
	}
	if tcp.GetPort() == 0 || tcp.GetPort() > 65535 {
		return "", status.Error(codes.InvalidArgument, "forward port must be 1..65535")
	}
	return fmt.Sprintf("tcp://%s:%d", host, tcp.GetPort()), nil
}
