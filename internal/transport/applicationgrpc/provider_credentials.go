package applicationgrpc

import (
	"context"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/providercred"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func credentialStrategy(value gatewayv1.ProviderCredentialRefreshStrategy) string {
	return value.String()
}

func credentialStrategyValue(value string) gatewayv1.ProviderCredentialRefreshStrategy {
	return gatewayv1.ProviderCredentialRefreshStrategy(gatewayv1.ProviderCredentialRefreshStrategy_value[value])
}

func credentialStatus(secret providercred.Secret) *gatewayv1.ProviderCredentialRefreshStatus {
	out := &gatewayv1.ProviderCredentialRefreshStatus{
		Provider: string(secret.Provider), ProviderId: string(secret.Workspace) + "/" + string(secret.Provider),
		CredentialKey: secret.Key, Strategy: credentialStrategyValue(secret.Strategy), Status: "ready",
		LastRefreshTime: timestamppb.New(secret.UpdatedAt),
	}
	if !secret.ExpiresAt.IsZero() {
		out.ExpirationTime = timestamppb.New(secret.ExpiresAt)
	}
	return out
}

// ConfigureProviderRefresh stores refresh material for one provider credential.
func (s *Server) ConfigureProviderRefresh(ctx context.Context, request *gatewayv1.ConfigureProviderRefreshRequest) (*gatewayv1.ConfigureProviderRefreshResponse, error) {
	workspace := workspaceID(request.GetWorkspaceScope())
	if workspace == "" || request.GetProvider() == "" || request.GetCredentialKey() == "" || len(request.GetMaterial()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "workspace, provider, credential_key and material are required")
	}
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	var expires time.Time
	if request.GetExpirationTime() != nil {
		if err := request.GetExpirationTime().CheckValid(); err != nil {
			return nil, status.Error(codes.InvalidArgument, "expiration_time is invalid")
		}
		expires = request.GetExpirationTime().AsTime()
	}
	if strings.TrimSpace(request.GetMaterial()[request.GetCredentialKey()]) == "" {
		return nil, status.Error(codes.InvalidArgument, "credential_key is not present in material")
	}
	for name, value := range request.GetMaterial() {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if err := s.Credentials.Put(ctx, providercred.Secret{
			Workspace: workspace, Provider: domain.ProviderID(request.GetProvider()), Key: name, Value: value,
			ExpiresAt: expires, Strategy: credentialStrategy(request.GetStrategy()),
		}); err != nil {
			return nil, grpcError(err)
		}
	}
	secret, err := s.Credentials.Get(ctx, workspace, domain.ProviderID(request.GetProvider()), request.GetCredentialKey())
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ConfigureProviderRefreshResponse{Status: credentialStatus(secret)}, nil
}

// RotateProviderCredential marks a configured credential as refreshed.
func (s *Server) RotateProviderCredential(ctx context.Context, request *gatewayv1.RotateProviderCredentialRequest) (*gatewayv1.RotateProviderCredentialResponse, error) {
	workspace := workspaceID(request.GetWorkspaceScope())
	if workspace == "" || request.GetProvider() == "" || request.GetCredentialKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace, provider and credential_key are required")
	}
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	secret, err := s.Credentials.Get(ctx, workspace, domain.ProviderID(request.GetProvider()), request.GetCredentialKey())
	if err != nil {
		return nil, grpcError(err)
	}
	secret.UpdatedAt = s.now().UTC()
	if err := s.Credentials.Put(ctx, secret); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.RotateProviderCredentialResponse{Status: credentialStatus(secret)}, nil
}

// GetProviderRefreshStatus returns refresh status for one or all credentials.
func (s *Server) GetProviderRefreshStatus(ctx context.Context, request *gatewayv1.GetProviderRefreshStatusRequest) (*gatewayv1.GetProviderRefreshStatusResponse, error) {
	workspace := workspaceID(request.GetWorkspaceScope())
	if workspace == "" || request.GetProvider() == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace and provider are required")
	}
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	secrets, err := s.Credentials.List(ctx, workspace, domain.ProviderID(request.GetProvider()))
	if err != nil {
		return nil, grpcError(err)
	}
	out := make([]*gatewayv1.ProviderCredentialRefreshStatus, 0, len(secrets))
	for _, secret := range secrets {
		if request.GetCredentialKey() != "" && request.GetCredentialKey() != secret.Key {
			continue
		}
		out = append(out, credentialStatus(secret))
	}
	return &gatewayv1.GetProviderRefreshStatusResponse{Credentials: out}, nil
}

// DeleteProviderRefresh removes a configured credential.
func (s *Server) DeleteProviderRefresh(ctx context.Context, request *gatewayv1.DeleteProviderRefreshRequest) (*gatewayv1.DeleteProviderRefreshResponse, error) {
	workspace := workspaceID(request.GetWorkspaceScope())
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	_, err := s.Credentials.Get(ctx, workspace, domain.ProviderID(request.GetProvider()), request.GetCredentialKey())
	exists := err == nil
	if err != nil && !domainCodeNotFound(err) {
		return nil, grpcError(err)
	}
	if exists {
		if err := s.Credentials.Delete(ctx, workspace, domain.ProviderID(request.GetProvider()), request.GetCredentialKey()); err != nil {
			return nil, grpcError(err)
		}
	}
	if !exists && !request.GetAllowMissing() {
		return nil, status.Error(codes.NotFound, "provider credential is not configured")
	}
	outcome := gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED
	if !exists {
		outcome = gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT
	}
	return &gatewayv1.DeleteProviderRefreshResponse{Outcome: outcome}, nil
}

// GetProviderCredentials returns requested credential values atomically.
func (s *Server) GetProviderCredentials(ctx context.Context, request *gatewayv1.GetProviderCredentialsRequest) (*gatewayv1.GetProviderCredentialsResponse, error) {
	workspace := workspaceID(request.GetWorkspaceScope())
	if workspace == "" || request.GetName() == "" || len(request.GetCredentialKeys()) == 0 || len(request.GetCredentialKeys()) > 32 {
		return nil, status.Error(codes.InvalidArgument, "workspace, provider and 1..32 credential_keys are required")
	}
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	out := make(map[string]*gatewayv1.ProviderCredentialValue, len(request.GetCredentialKeys()))
	for _, name := range request.GetCredentialKeys() {
		secret, err := s.Credentials.Get(ctx, workspace, domain.ProviderID(request.GetName()), name)
		if err != nil {
			return nil, grpcError(err)
		}
		if !secret.ExpiresAt.IsZero() && !s.now().Before(secret.ExpiresAt) {
			return nil, status.Error(codes.NotFound, "provider credential is expired: "+name)
		}
		value := &gatewayv1.ProviderCredentialValue{Value: secret.Value}
		if !secret.ExpiresAt.IsZero() {
			value.ExpirationTime = timestamppb.New(secret.ExpiresAt)
		}
		out[name] = value
	}
	return &gatewayv1.GetProviderCredentialsResponse{Credentials: out}, nil
}

// ExchangeProviderSubjectToken trades a supervisor JWT-SVID for a provider token.
func (s *Server) ExchangeProviderSubjectToken(ctx context.Context, request *gatewayv1.ExchangeProviderSubjectTokenRequest) (*gatewayv1.ExchangeProviderSubjectTokenResponse, error) {
	if s.OAuthExchange == nil {
		return nil, status.Error(codes.Unimplemented, "provider subject token exchange requires an OAuth client")
	}
	if request.GetSandboxId() == "" || request.GetProvider() == "" || request.GetCredentialKey() == "" || request.GetSupervisorJwtSvid() == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id, provider, credential_key and supervisor_jwt_svid are required")
	}
	if s.Credentials == nil {
		return nil, status.Error(codes.Unavailable, "credential store is not configured")
	}
	ref, err := s.sandboxByID(ctx, request.GetSandboxId())
	if err != nil {
		return nil, err
	}
	if _, err := s.Credentials.Get(ctx, ref.Workspace, domain.ProviderID(request.GetProvider()), request.GetCredentialKey()); err != nil {
		return nil, grpcError(err)
	}
	issued, err := s.OAuthExchange.Exchange(ctx, request.GetSupervisorJwtSvid())
	if err != nil {
		return nil, grpcError(err)
	}
	response := &gatewayv1.ExchangeProviderSubjectTokenResponse{AccessToken: issued.Value, TokenType: "Bearer"}
	if !issued.ExpiresAt.IsZero() {
		response.ExpiresAfter = durationpb.New(time.Until(issued.ExpiresAt))
	}
	return response, nil
}
