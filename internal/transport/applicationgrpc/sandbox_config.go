package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	sandboxv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/sandbox/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// GetSandboxConfig returns the active policy and effective settings.
func (s *Server) GetSandboxConfig(ctx context.Context, request *sandboxv1.GetSandboxConfigRequest) (*sandboxv1.GetSandboxConfigResponse, error) {
	if s.Sandboxes == nil || s.PolicyRevisions == nil {
		return nil, status.Error(codes.Unavailable, "sandbox config runtime is not configured")
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
	ref := domain.SandboxRef{Workspace: workspace, Sandbox: domain.SandboxID(request.GetName())}
	if _, err := s.Sandboxes.Get(ctx, ref); err != nil {
		return nil, grpcError(err)
	}
	scope := policyapp.Scope{Workspace: workspace, Sandbox: domain.SandboxID(request.GetName())}
	response := &sandboxv1.GetSandboxConfigResponse{Policy: &sandboxv1.SandboxPolicy{}}
	if active, found, err := s.PolicyRevisions.Active(ctx, scope); err != nil {
		return nil, grpcError(err)
	} else if found {
		policy := &sandboxv1.SandboxPolicy{}
		if err := protojson.Unmarshal(active.Source, policy); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy is not protobuf JSON")
		}
		response.Policy = policy
		response.Version = uint32(active.Number)
		response.PolicyHash = active.Hash
		response.PolicySource = sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX
		response.ConfigRevision = active.Number
	}
	return response, nil
}
