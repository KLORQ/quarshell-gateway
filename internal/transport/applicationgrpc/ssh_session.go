package applicationgrpc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sshSession struct {
	sandbox   domain.SandboxID
	workspace domain.WorkspaceID
	expiresAt time.Time
}

// CreateSshSession mints a short-lived token for an SSH relay.
func (s *Server) CreateSshSession(ctx context.Context, request *gatewayv1.CreateSshSessionRequest) (*gatewayv1.CreateSshSessionResponse, error) {
	if s.Sandboxes == nil || s.SupervisorHub == nil || s.Tokens == nil {
		return nil, status.Error(codes.Unavailable, "ssh session runtime is not configured")
	}
	if request == nil || request.GetSandbox() == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox is required")
	}
	workspace := workspaceID(request.GetWorkspaceScope())
	if workspace == "" {
		if principal, ok := principalFromContext(ctx); ok {
			workspace = principal.workspace
		}
	}
	if workspace == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace is required")
	}
	current, err := s.Sandboxes.Get(ctx, domain.SandboxRef{Workspace: workspace, Sandbox: domain.SandboxID(request.GetSandbox())})
	if err != nil {
		return nil, grpcError(err)
	}
	if current.State != "running" || !s.SupervisorHub.Connected(string(current.Sandbox)) {
		return nil, status.Error(codes.FailedPrecondition, "sandbox is not ready: supervisor relay not connected")
	}
	if err := s.validateSupervisorRelayOwner(ctx, domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial()); err != nil {
		return nil, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, status.Error(codes.Internal, "mint ssh session token")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expires := s.now().Add(5 * time.Minute)
	s.sshMu.Lock()
	if s.sshSessions == nil {
		s.sshSessions = make(map[string]sshSession)
	}
	s.sshSessions[token] = sshSession{sandbox: current.Sandbox, workspace: current.Workspace, expiresAt: expires}
	s.sshMu.Unlock()
	host := s.GatewayHost
	if host == "" {
		host = "127.0.0.1"
	}
	port := s.GatewayPort
	if port == 0 {
		port = 7443
	}
	scheme := s.GatewayScheme
	if scheme == "" {
		scheme = "http"
	}
	return &gatewayv1.CreateSshSessionResponse{
		SandboxId: string(current.Sandbox), Token: token, GatewayHost: host, GatewayPort: uint32(port), GatewayScheme: scheme,
		ExpirationTime: timestamppb.New(expires),
	}, nil
}

// RevokeSshSession removes a session token.
func (s *Server) RevokeSshSession(_ context.Context, request *gatewayv1.RevokeSshSessionRequest) (*gatewayv1.RevokeSshSessionResponse, error) {
	token := request.GetToken()
	s.sshMu.Lock()
	_, exists := s.sshSessions[token]
	delete(s.sshSessions, token)
	s.sshMu.Unlock()
	if !exists && !request.GetAllowMissing() {
		return nil, status.Error(codes.NotFound, "ssh session not found")
	}
	outcome := gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED
	if !exists {
		outcome = gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT
	}
	return &gatewayv1.RevokeSshSessionResponse{Outcome: outcome}, nil
}

func (s *Server) sshSession(token string) (sshSession, bool) {
	s.sshMu.RLock()
	session, ok := s.sshSessions[token]
	s.sshMu.RUnlock()
	if !ok || !s.now().Before(session.expiresAt) {
		return sshSession{}, false
	}
	return session, true
}
