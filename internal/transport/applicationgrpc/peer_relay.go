package applicationgrpc

import (
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

// PeerRelay proxies a replica-to-sandbox relay through the supervisor hub.
func (s *Server) PeerRelay(stream gatewayv1.OpenShell_PeerRelayServer) error {
	principal, ok := principalFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	if s.SupervisorHub == nil || s.Sandboxes == nil {
		return status.Error(codes.Unavailable, "peer relay is not configured")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil || init.GetRelayOpen() == nil {
		return status.Error(codes.InvalidArgument, "first frame must carry relay_open")
	}
	sandbox := strings.TrimSpace(init.GetSandboxId())
	if sandbox == "" {
		return status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if principal.sandbox != "" && principal.sandbox != domain.SandboxID(sandbox) {
		return status.Error(codes.PermissionDenied, "peer relay sandbox does not match principal")
	}
	if principal.workspace == "" {
		return status.Error(codes.InvalidArgument, "workspace is required")
	}
	ref := domain.SandboxRef{Workspace: principal.workspace, Sandbox: domain.SandboxID(sandbox)}
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
	target, err := relayTarget(init.GetRelayOpen())
	if err != nil {
		return err
	}
	connection, err := s.SupervisorHub.OpenChannel(stream.Context(), sandbox, target)
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	var closeOnce sync.Once
	closeConnection := func() { closeOnce.Do(func() { _ = connection.Close() }) }
	stopOwnerMonitor, ownerLost := s.monitorSupervisorRelayOwner(stream.Context(), ref, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial(), closeConnection)
	defer func() { stopOwnerMonitor(); closeConnection() }()
	if err := s.validateSupervisorRelayOwner(stream.Context(), ref, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial()); err != nil {
		return err
	}

	writeErr := make(chan error, 1)
	go func() {
		for {
			frame, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				writeErr <- nil
				return
			}
			if err != nil {
				writeErr <- err
				return
			}
			if len(frame.GetData()) == 0 {
				continue
			}
			if _, err := connection.Write(frame.GetData()); err != nil {
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
				if sendErr := stream.Send(&gatewayv1.PeerRelayFrame{Payload: &gatewayv1.PeerRelayFrame_Data{Data: append([]byte(nil), buffer[:n]...)}}); sendErr != nil {
					readErr <- sendErr
					return
				}
			}
			if err != nil {
				readErr <- err
				return
			}
		}
	}()
	select {
	case <-ownerLost:
		return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
	case err := <-readErr:
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return status.Error(codes.Unavailable, err.Error())
	case err := <-writeErr:
		if err == nil || errors.Is(err, io.EOF) {
			return nil
		}
		return status.Error(codes.Unavailable, err.Error())
	}
}

func relayTarget(open *gatewayv1.RelayOpen) (string, error) {
	if open.GetSsh() != nil {
		return "ssh", nil
	}
	tcp := open.GetTcp()
	if tcp == nil {
		return "", status.Error(codes.InvalidArgument, "relay target is required")
	}
	host := strings.Trim(strings.TrimSpace(tcp.GetHost()), "[]")
	if host == "" {
		host = "127.0.0.1"
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", status.Error(codes.InvalidArgument, "relay target must be loopback")
		}
	}
	if tcp.GetPort() == 0 || tcp.GetPort() > 65535 {
		return "", status.Error(codes.InvalidArgument, "relay port must be 1..65535")
	}
	return fmt.Sprintf("tcp://%s:%d", host, tcp.GetPort()), nil
}
