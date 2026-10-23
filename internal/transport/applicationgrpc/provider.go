package applicationgrpc

import (
	"context"
	"encoding/json"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateProvider creates one provider definition.
func (s *Server) CreateProvider(ctx context.Context, request *gatewayv1.CreateProviderRequest) (*gatewayv1.ProviderResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	input := request.GetProvider()
	if input == nil {
		return nil, status.Error(codes.InvalidArgument, "provider is required")
	}
	config, err := json.Marshal(input.GetConfig())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid provider config")
	}
	created, _, err := s.Providers.Create(ctx, provider.CreateRequest{
		ID: domain.ProviderID(input.GetMetadata().GetName()), Name: input.GetMetadata().GetName(), Driver: input.GetType(),
		Config: config, IdempotencyKey: domain.OperationID(request.GetRequestId()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ProviderResponse{Provider: providerProto(created)}, nil
}

// GetProvider returns one provider.
func (s *Server) GetProvider(ctx context.Context, request *gatewayv1.GetProviderRequest) (*gatewayv1.ProviderResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	found, err := s.Providers.Get(ctx, domain.ProviderID(request.GetName()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ProviderResponse{Provider: providerProto(found)}, nil
}

// ListProviders returns a bounded page.
func (s *Server) ListProviders(ctx context.Context, request *gatewayv1.ListProvidersRequest) (*gatewayv1.ListProvidersResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	items, err := s.Providers.List(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(items), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*datamodelv1.Provider, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, providerProto(item))
	}
	return &gatewayv1.ListProvidersResponse{Providers: out, NextPageToken: next}, nil
}

// UpdateProvider replaces provider fields at the expected revision.
func (s *Server) UpdateProvider(ctx context.Context, request *gatewayv1.UpdateProviderRequest) (*gatewayv1.ProviderResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	input := request.GetProvider()
	if input == nil {
		return nil, status.Error(codes.InvalidArgument, "provider is required")
	}
	config, err := json.Marshal(input.GetConfig())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid provider config")
	}
	updated, err := s.Providers.Update(ctx, provider.UpdateRequest{
		ID: domain.ProviderID(input.GetMetadata().GetName()), Name: input.GetMetadata().GetName(), Driver: input.GetType(),
		Config: config, ExpectedRevision: input.GetMetadata().GetResourceVersion(), IdempotencyKey: domain.OperationID(request.GetRequestId()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ProviderResponse{Provider: providerProto(updated)}, nil
}

// DeleteProvider removes a provider.
func (s *Server) DeleteProvider(ctx context.Context, request *gatewayv1.DeleteProviderRequest) (*gatewayv1.DeleteProviderResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	id := domain.ProviderID(request.GetName())
	if request.GetAllowMissing() {
		if _, err := s.Providers.Get(ctx, id); err != nil {
			if domainCodeNotFound(err) {
				return &gatewayv1.DeleteProviderResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
			}
			return nil, grpcError(err)
		}
	}
	if err := s.Providers.Delete(ctx, id, domain.OperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.DeleteProviderResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

// ListProviderProfiles returns profiles across providers.
func (s *Server) ListProviderProfiles(ctx context.Context, request *gatewayv1.ListProviderProfilesRequest) (*gatewayv1.ListProviderProfilesResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	providers, err := s.Providers.List(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	all := make([]*gatewayv1.ProviderProfile, 0)
	for _, item := range providers {
		profiles, err := s.Providers.ListProfiles(ctx, item.ID)
		if err != nil {
			return nil, grpcError(err)
		}
		for _, profile := range profiles {
			all = append(all, profileProto(profile))
		}
	}
	start, end, next, err := page(len(all), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	return &gatewayv1.ListProviderProfilesResponse{Profiles: all[start:end], NextPageToken: next}, nil
}

// GetProviderProfile finds a profile by ID across providers.
func (s *Server) GetProviderProfile(ctx context.Context, request *gatewayv1.GetProviderProfileRequest) (*gatewayv1.ProviderProfileResponse, error) {
	if s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "provider registry is not configured")
	}
	providers, err := s.Providers.List(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	for _, item := range providers {
		profile, err := s.Providers.GetProfile(ctx, item.ID, request.GetId())
		if err == nil {
			return &gatewayv1.ProviderProfileResponse{Profile: profileProto(profile)}, nil
		}
		if !domainCodeNotFound(err) {
			return nil, grpcError(err)
		}
	}
	return nil, status.Error(codes.NotFound, "provider profile not found")
}

func providerProto(item provider.Provider) *datamodelv1.Provider {
	config := map[string]string{}
	if len(item.Config) > 0 {
		_ = json.Unmarshal(item.Config, &config)
	}
	return &datamodelv1.Provider{
		Metadata: &datamodelv1.ObjectMeta{Id: string(item.ID), Name: item.Name, CreatedTime: timestamppb.New(item.CreatedAt), ResourceVersion: item.Revision},
		Type:     item.Driver, Config: config,
	}
}

func profileProto(item provider.Profile) *gatewayv1.ProviderProfile {
	var config map[string]any
	_ = json.Unmarshal(item.Config, &config)
	return &gatewayv1.ProviderProfile{Id: item.ID, DisplayName: item.Name, ResourceVersion: item.Revision}
}
