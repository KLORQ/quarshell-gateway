package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const platformProvider domain.ProviderID = "platform"

func (s *Server) ensurePlatformProvider(ctx context.Context) error {
	if s.Providers == nil {
		return status.Error(codes.Unavailable, "provider registry is not configured")
	}
	if _, err := s.Providers.Get(ctx, platformProvider); err == nil {
		return nil
	} else if !domainCodeNotFound(err) {
		return grpcError(err)
	}
	_, _, err := s.Providers.Create(ctx, provider.CreateRequest{
		ID: platformProvider, Name: "platform", Driver: "platform", IdempotencyKey: "profile-platform-provider",
	})
	if err != nil && !domainCodeConflict(err) {
		return grpcError(err)
	}
	return nil
}

func profileInputs(items []*gatewayv1.ProviderProfileImportItem) []provider.ProfileInput {
	out := make([]provider.ProfileInput, 0, len(items))
	for _, item := range items {
		profile := item.GetProfile()
		if profile == nil {
			continue
		}
		encoded, _ := protojson.Marshal(profile)
		out = append(out, provider.ProfileInput{ID: profile.GetId(), Name: profile.GetDisplayName(), Config: encoded})
	}
	return out
}

func profilesProto(profiles []provider.Profile) []*gatewayv1.ProviderProfile {
	out := make([]*gatewayv1.ProviderProfile, 0, len(profiles))
	for _, item := range profiles {
		profile := &gatewayv1.ProviderProfile{}
		if len(item.Config) > 0 {
			_ = protojson.Unmarshal(item.Config, profile)
		}
		profile.Id = item.ID
		profile.DisplayName = item.Name
		profile.ResourceVersion = item.Revision
		out = append(out, profile)
	}
	return out
}

// ImportProviderProfiles upserts platform provider profiles.
func (s *Server) ImportProviderProfiles(ctx context.Context, request *gatewayv1.ImportProviderProfilesRequest) (*gatewayv1.ImportProviderProfilesResponse, error) {
	if err := s.ensurePlatformProvider(ctx); err != nil {
		return nil, err
	}
	profiles, _, err := s.Providers.ImportProfiles(ctx, platformProvider, profileInputs(request.GetProfiles()), domain.OperationID(request.GetRequestId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ImportProviderProfilesResponse{Profiles: profilesProto(profiles), Imported: true}, nil
}

// UpdateProviderProfiles upserts one profile with revision checking.
func (s *Server) UpdateProviderProfiles(ctx context.Context, request *gatewayv1.UpdateProviderProfilesRequest) (*gatewayv1.UpdateProviderProfilesResponse, error) {
	if err := s.ensurePlatformProvider(ctx); err != nil {
		return nil, err
	}
	input := profileInputs([]*gatewayv1.ProviderProfileImportItem{request.GetProfile()})
	if len(input) != 1 || input[0].ID == "" {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}
	current, err := s.Providers.GetProfile(ctx, platformProvider, input[0].ID)
	expected := request.GetExpectedResourceVersion()
	if expected == 0 && request.GetProfile().GetProfile() != nil {
		expected = request.GetProfile().GetProfile().GetResourceVersion()
	}
	if err == nil && expected != 0 && current.Revision != expected {
		return nil, status.Error(codes.Aborted, "provider profile revision conflict")
	}
	if err != nil && !domainCodeNotFound(err) {
		return nil, grpcError(err)
	}
	profiles, _, err := s.Providers.ImportProfiles(ctx, platformProvider, input, domain.OperationID(request.GetRequestId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.UpdateProviderProfilesResponse{Profile: profilesProto(profiles)[0]}, nil
}

// LintProviderProfiles validates profiles without writing.
func (s *Server) LintProviderProfiles(ctx context.Context, request *gatewayv1.LintProviderProfilesRequest) (*gatewayv1.LintProviderProfilesResponse, error) {
	if err := s.ensurePlatformProvider(ctx); err != nil {
		return nil, err
	}
	issues, err := s.Providers.LintProfiles(ctx, platformProvider, profileInputs(request.GetProfiles()))
	if err != nil {
		return nil, grpcError(err)
	}
	out := make([]*gatewayv1.ProviderProfileDiagnostic, 0, len(issues))
	for _, issue := range issues {
		out = append(out, &gatewayv1.ProviderProfileDiagnostic{ProfileId: issue.Profile, Field: issue.Field, Message: issue.Message, Severity: "error"})
	}
	return &gatewayv1.LintProviderProfilesResponse{Diagnostics: out, Valid: len(out) == 0}, nil
}

// DeleteProviderProfile removes a platform profile.
func (s *Server) DeleteProviderProfile(ctx context.Context, request *gatewayv1.DeleteProviderProfileRequest) (*gatewayv1.DeleteProviderProfileResponse, error) {
	if err := s.ensurePlatformProvider(ctx); err != nil {
		return nil, err
	}
	if request.GetAllowMissing() {
		if _, err := s.Providers.GetProfile(ctx, platformProvider, request.GetId()); err != nil {
			if domainCodeNotFound(err) {
				return &gatewayv1.DeleteProviderProfileResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
			}
			return nil, grpcError(err)
		}
	}
	if err := s.Providers.DeleteProfile(ctx, platformProvider, request.GetId(), domain.OperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.DeleteProviderProfileResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

// AttachSandboxProvider binds one provider to a sandbox.
func (s *Server) AttachSandboxProvider(ctx context.Context, request *gatewayv1.AttachSandboxProviderRequest) (*gatewayv1.AttachSandboxProviderResponse, error) {
	if s.Sandboxes == nil || s.ProviderBindings == nil || s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider binding runtime is not configured")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	current, err := s.Sandboxes.Get(ctx, ref)
	if err != nil {
		return nil, grpcError(err)
	}
	providerID := domain.ProviderID(request.GetProvider())
	if _, err := s.Providers.Get(ctx, providerID); err != nil {
		return nil, grpcError(err)
	}
	_, existingErr := s.ProviderBindings.Get(ctx, ref, providerID)
	if existingErr != nil && !domainCodeNotFound(existingErr) {
		return nil, grpcError(existingErr)
	}
	revision := uint64(request.GetExpectedResourceVersion())
	if revision == 0 {
		revision = uint64(current.Generation)
	}
	binding, _, err := s.ProviderBindings.Bind(ctx, provider.BindRequest{
		Sandbox: ref, Provider: providerID, Revision: revision,
		IdempotencyKey: domain.OperationID(request.GetRequestId()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.AttachSandboxProviderResponse{
		Sandbox: sandboxProto(current, nil), Attached: domainCodeNotFound(existingErr),
		Receipt: &gatewayv1.ProviderMutationReceipt{
			ReceiptId: string(binding.Provider) + ":" + request.GetRequestId(), Provider: string(binding.Provider),
			Workspace: string(ref.Workspace), Kind: gatewayv1.ProviderMutationKind_PROVIDER_MUTATION_KIND_ATTACH, PersistedTime: timestamppb.New(binding.CreatedAt),
		},
	}, nil
}

// DetachSandboxProvider removes a provider binding.
func (s *Server) DetachSandboxProvider(ctx context.Context, request *gatewayv1.DetachSandboxProviderRequest) (*gatewayv1.DetachSandboxProviderResponse, error) {
	if s.Sandboxes == nil || s.ProviderBindings == nil {
		return nil, status.Error(codes.Unavailable, "provider binding runtime is not configured")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	_, getErr := s.ProviderBindings.Get(ctx, ref, domain.ProviderID(request.GetProvider()))
	if getErr != nil && !domainCodeNotFound(getErr) {
		return nil, grpcError(getErr)
	}
	if err := s.ProviderBindings.Unbind(ctx, ref, domain.ProviderID(request.GetProvider()), domain.OperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	current, err := s.Sandboxes.Get(ctx, ref)
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.DetachSandboxProviderResponse{Sandbox: sandboxProto(current, nil), Detached: getErr == nil}, nil
}

// GetSandboxProviderStatus reports provider readiness for a sandbox.
func (s *Server) GetSandboxProviderStatus(ctx context.Context, request *gatewayv1.GetSandboxProviderStatusRequest) (*gatewayv1.GetSandboxProviderStatusResponse, error) {
	if s.ProviderBindings == nil {
		return nil, status.Error(codes.Unavailable, "provider binding runtime is not configured")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	binding, err := s.ProviderBindings.Get(ctx, ref, domain.ProviderID(request.GetProvider()))
	if err != nil {
		return nil, grpcError(err)
	}
	state := gatewayv1.ProviderReadinessState_PROVIDER_READINESS_STATE_PENDING
	switch binding.Readiness {
	case provider.ReadinessReady:
		state = gatewayv1.ProviderReadinessState_PROVIDER_READINESS_STATE_READY
	case provider.ReadinessFailed:
		state = gatewayv1.ProviderReadinessState_PROVIDER_READINESS_STATE_FAILED
	}
	return &gatewayv1.GetSandboxProviderStatusResponse{Status: &gatewayv1.ProviderReadinessStatus{
		Receipt: &gatewayv1.ProviderMutationReceipt{Provider: string(binding.Provider), Workspace: string(ref.Workspace), PersistedTime: timestamppb.New(binding.CreatedAt)},
		State:   state, EvaluatedTime: timestamppb.New(binding.UpdatedAt),
	}}, nil
}

func domainCodeConflict(err error) bool { return domain.CodeOf(err) == domain.CodeConflict }
