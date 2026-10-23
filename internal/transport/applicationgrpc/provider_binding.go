package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	"github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ListSandboxProviders returns the provider definitions attached to one
// sandbox. Bindings are durable and scoped to the workspace/sandbox pair.
func (s *Server) ListSandboxProviders(ctx context.Context, request *gatewayv1.ListSandboxProvidersRequest) (*gatewayv1.ListSandboxProvidersResponse, error) {
	if s.Sandboxes == nil || s.ProviderBindings == nil || s.Providers == nil {
		return nil, status.Error(codes.Unavailable, "sandbox provider services are not configured")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	if _, err := s.Sandboxes.Get(ctx, ref); err != nil {
		return nil, grpcError(err)
	}
	bindings, err := s.ProviderBindings.List(ctx, ref)
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(bindings), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	providers := make([]*datamodelv1.Provider, 0, end-start)
	for _, binding := range bindings[start:end] {
		item, err := s.Providers.Get(ctx, binding.Provider)
		if err != nil {
			if domain.CodeOf(err) == domain.CodeNotFound {
				return nil, status.Error(codes.FailedPrecondition, "sandbox references a missing provider definition")
			}
			return nil, grpcError(err)
		}
		providers = append(providers, providerProto(item))
	}
	return &gatewayv1.ListSandboxProvidersResponse{Providers: providers, NextPageToken: next}, nil
}
