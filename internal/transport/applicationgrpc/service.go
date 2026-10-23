package applicationgrpc

import (
	"context"
	"fmt"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/endpoint"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ExposeService exposes one sandbox port.
func (s *Server) ExposeService(ctx context.Context, request *gatewayv1.ExposeServiceRequest) (*gatewayv1.ServiceEndpointResponse, error) {
	if s.Services == nil {
		return nil, status.Error(codes.Unavailable, "service registry is not configured")
	}
	if request.GetTargetPort() == 0 || request.GetTargetPort() > 65535 {
		return nil, status.Error(codes.InvalidArgument, "target_port is required")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	service, _, err := s.Services.Expose(ctx, ref, request.GetName(), request.GetName(),
		fmt.Sprintf("http://127.0.0.1:%d", request.GetTargetPort()), uint16(request.GetTargetPort()), "tcp", authMode(request.GetAuthorizationMode()), domain.OperationID(request.GetRequestId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return serviceResponse(service), nil
}

// GetService returns one exposed service.
func (s *Server) GetService(ctx context.Context, request *gatewayv1.GetServiceRequest) (*gatewayv1.ServiceEndpointResponse, error) {
	if s.Services == nil {
		return nil, status.Error(codes.Unavailable, "service registry is not configured")
	}
	service, err := s.Services.Get(ctx, sandboxRef(request.GetWorkspaceScope(), request.GetSandbox()), request.GetName())
	if err != nil {
		return nil, grpcError(err)
	}
	return serviceResponse(service), nil
}

// ListServices returns a bounded page.
func (s *Server) ListServices(ctx context.Context, request *gatewayv1.ListServicesRequest) (*gatewayv1.ListServicesResponse, error) {
	if s.Services == nil {
		return nil, status.Error(codes.Unavailable, "service registry is not configured")
	}
	if request.GetSandbox() == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox is required")
	}
	items, err := s.Services.List(ctx, sandboxRef(request.GetWorkspaceScope(), request.GetSandbox()))
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(items), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*gatewayv1.ServiceEndpointResponse, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, serviceResponse(item))
	}
	return &gatewayv1.ListServicesResponse{Services: out, NextPageToken: next}, nil
}

// DeleteService removes an exposed service.
func (s *Server) DeleteService(ctx context.Context, request *gatewayv1.DeleteServiceRequest) (*gatewayv1.DeleteServiceResponse, error) {
	if s.Services == nil {
		return nil, status.Error(codes.Unavailable, "service registry is not configured")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	if request.GetAllowMissing() {
		if _, err := s.Services.Get(ctx, ref, request.GetName()); err != nil {
			if domainCodeNotFound(err) {
				return &gatewayv1.DeleteServiceResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
			}
			return nil, grpcError(err)
		}
	}
	if err := s.Services.Delete(ctx, ref, request.GetName(), domain.OperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.DeleteServiceResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

func serviceResponse(service endpoint.Service) *gatewayv1.ServiceEndpointResponse {
	mode := gatewayv1.ServiceAuthorizationMode_SERVICE_AUTHORIZATION_MODE_STRIP
	if service.AuthMode == "bearer" {
		mode = gatewayv1.ServiceAuthorizationMode_SERVICE_AUTHORIZATION_MODE_BEARER_PASSTHROUGH
	}
	return &gatewayv1.ServiceEndpointResponse{
		Endpoint: &gatewayv1.ServiceEndpoint{
			Metadata: &datamodelv1.ObjectMeta{Id: service.ID, Name: service.Name, CreatedTime: timestamppb.New(service.CreatedAt)},
			Sandbox:  string(service.Sandbox.Sandbox), Name: service.Name, TargetPort: uint32(service.Port),
			AuthorizationMode: mode,
		},
		Url: service.URL,
	}
}

func authMode(mode gatewayv1.ServiceAuthorizationMode) string {
	if mode == gatewayv1.ServiceAuthorizationMode_SERVICE_AUTHORIZATION_MODE_BEARER_PASSTHROUGH {
		return "bearer"
	}
	return "strip"
}
