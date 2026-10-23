package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReportProviderReadiness applies one supervisor readiness observation.
func (s *Server) ReportProviderReadiness(ctx context.Context, request *gatewayv1.ReportProviderReadinessRequest) (*gatewayv1.ReportProviderReadinessResponse, error) {
	if s.Sandboxes == nil || s.ProviderBindings == nil {
		return nil, status.Error(codes.Unavailable, "provider readiness runtime is not configured")
	}
	ref, err := s.sandboxByID(ctx, request.GetSandboxId())
	if err != nil {
		return nil, err
	}
	bindings, err := s.ProviderBindings.List(ctx, ref)
	if err != nil {
		return nil, grpcError(err)
	}
	observation := request.GetObservation()
	ready := observation.GetCredentialsInstalled() && observation.GetPolicyActive() && observation.GetLaunchEnvironmentInstalled()
	for _, binding := range bindings {
		if ready {
			_, err = s.ProviderBindings.Ack(ctx, ref, binding.Provider, binding.Revision)
		} else {
			_, err = s.ProviderBindings.Fail(ctx, ref, binding.Provider, binding.Revision, "provider readiness incomplete")
		}
		if err != nil {
			return nil, grpcError(err)
		}
	}
	return &gatewayv1.ReportProviderReadinessResponse{AcceptedSequence: observation.GetSequence()}, nil
}

// ReportEndpointStatus accepts an endpoint observation batch.
func (s *Server) ReportEndpointStatus(ctx context.Context, request *gatewayv1.ReportEndpointStatusRequest) (*gatewayv1.ReportEndpointStatusResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "endpoint status runtime is not configured")
	}
	if _, err := s.sandboxByID(ctx, request.GetSandboxId()); err != nil {
		return nil, err
	}
	return &gatewayv1.ReportEndpointStatusResponse{}, nil
}

// ReportSandboxConfiguration accepts a sandbox configuration admission report.
func (s *Server) ReportSandboxConfiguration(ctx context.Context, request *gatewayv1.ReportSandboxConfigurationRequest) (*gatewayv1.ReportSandboxConfigurationResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox configuration runtime is not configured")
	}
	if _, err := s.sandboxByID(ctx, request.GetSandboxId()); err != nil {
		return nil, err
	}
	return &gatewayv1.ReportSandboxConfigurationResponse{}, nil
}

// GetSandboxProviderEnvironment reports the bound provider environment revision.
func (s *Server) GetSandboxProviderEnvironment(ctx context.Context, request *gatewayv1.GetSandboxProviderEnvironmentRequest) (*gatewayv1.GetSandboxProviderEnvironmentResponse, error) {
	if s.Sandboxes == nil || s.ProviderBindings == nil {
		return nil, status.Error(codes.Unavailable, "provider environment runtime is not configured")
	}
	ref, err := s.sandboxByID(ctx, request.GetSandboxId())
	if err != nil {
		return nil, err
	}
	bindings, err := s.ProviderBindings.List(ctx, ref)
	if err != nil {
		return nil, grpcError(err)
	}
	environment := make(map[string]string)
	var revision uint64
	withheldCredentials := false
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	for _, binding := range bindings {
		if binding.Revision > revision {
			revision = binding.Revision
		}
		secrets, err := s.Credentials.List(ctx, ref.Workspace, binding.Provider)
		if err != nil {
			return nil, grpcError(err)
		}
		for _, secret := range secrets {
			if secret.ExpiresAt.IsZero() || s.now().Before(secret.ExpiresAt) {
				// Provider credential records do not yet carry validated endpoint
				// bindings. Returning a secret as ordinary environment would make it
				// usable at every destination, so keep it withheld until the policy
				// and supervisor binding contract is wired end to end.
				withheldCredentials = true
			}
		}
	}
	readiness := gatewayv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_UNSPECIFIED
	if withheldCredentials {
		readiness = gatewayv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_CREDENTIALS_WITHHELD
	}
	return &gatewayv1.GetSandboxProviderEnvironmentResponse{
		Environment: environment, ProviderEnvRevision: revision, ReadinessReason: readiness,
	}, nil
}

func (s *Server) sandboxByID(ctx context.Context, id string) (domain.SandboxRef, error) {
	if id == "" {
		return domain.SandboxRef{}, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	principal, ok := sandboxPrincipalFromContext(ctx)
	if !ok {
		return domain.SandboxRef{}, status.Error(codes.Unauthenticated, "sandbox principal required")
	}
	if string(principal.sandbox) != id {
		return domain.SandboxRef{}, status.Error(codes.PermissionDenied, "sandbox does not match authenticated principal")
	}
	current, err := s.Sandboxes.GetBySandboxID(ctx, principal.sandbox)
	if err != nil {
		return domain.SandboxRef{}, grpcError(err)
	}
	if current.State != "running" || current.RuntimeGenerationOrInitial() != principal.generation || current.CredentialEpochOrInitial() != principal.credentialEpoch {
		return domain.SandboxRef{}, status.Error(codes.FailedPrecondition, "sandbox credential does not match the active runtime generation")
	}
	return domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, nil
}
