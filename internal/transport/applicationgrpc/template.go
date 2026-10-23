package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/template"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateSandboxTemplate creates one workload template.
func (s *Server) CreateSandboxTemplate(ctx context.Context, request *gatewayv1.CreateSandboxTemplateRequest) (*gatewayv1.SandboxTemplateResponse, error) {
	if s.Templates == nil {
		return nil, status.Error(codes.Unavailable, "template service is not configured")
	}
	input := request.GetTemplate()
	if input == nil {
		return nil, status.Error(codes.InvalidArgument, "template is required")
	}
	id := input.GetMetadata().GetId()
	name := input.GetMetadata().GetName()
	if id == "" {
		id = name
	}
	spec, err := protojson.Marshal(input.GetSpec())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid template spec")
	}
	created, _, err := s.Templates.Create(ctx, workspaceID(request.GetWorkspaceScope()), id, name, spec, domainOperationID(request.GetRequestId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.SandboxTemplateResponse{Template: templateProto(created)}, nil
}

// GetSandboxTemplate returns one template.
func (s *Server) GetSandboxTemplate(ctx context.Context, request *gatewayv1.GetSandboxTemplateRequest) (*gatewayv1.SandboxTemplateResponse, error) {
	if s.Templates == nil {
		return nil, status.Error(codes.Unavailable, "template service is not configured")
	}
	found, err := s.Templates.Get(ctx, workspaceID(request.GetWorkspaceScope()), request.GetName())
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.SandboxTemplateResponse{Template: templateProto(found)}, nil
}

// ListSandboxTemplates returns a bounded page for one workspace.
func (s *Server) ListSandboxTemplates(ctx context.Context, request *gatewayv1.ListSandboxTemplatesRequest) (*gatewayv1.ListSandboxTemplatesResponse, error) {
	if s.Templates == nil {
		return nil, status.Error(codes.Unavailable, "template service is not configured")
	}
	if workspaceID(request.GetWorkspaceScope()) == "" {
		return nil, status.Error(codes.InvalidArgument, "named workspace scope is required")
	}
	items, err := s.Templates.List(ctx, workspaceID(request.GetWorkspaceScope()))
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(items), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*gatewayv1.SandboxWorkloadTemplate, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, templateProto(item))
	}
	return &gatewayv1.ListSandboxTemplatesResponse{Templates: out, NextPageToken: next}, nil
}

// DeleteSandboxTemplate removes a template.
func (s *Server) DeleteSandboxTemplate(ctx context.Context, request *gatewayv1.DeleteSandboxTemplateRequest) (*gatewayv1.DeleteSandboxTemplateResponse, error) {
	if s.Templates == nil {
		return nil, status.Error(codes.Unavailable, "template service is not configured")
	}
	workspace := workspaceID(request.GetWorkspaceScope())
	if request.GetAllowMissing() {
		if _, err := s.Templates.Get(ctx, workspace, request.GetName()); err != nil {
			if domainCodeNotFound(err) {
				return &gatewayv1.DeleteSandboxTemplateResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
			}
			return nil, grpcError(err)
		}
	}
	if err := s.Templates.Delete(ctx, workspace, request.GetName(), domainOperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.DeleteSandboxTemplateResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

func domainCodeNotFound(err error) bool { return domain.CodeOf(err) == domain.CodeNotFound }

func templateProto(item template.Template) *gatewayv1.SandboxWorkloadTemplate {
	spec := &gatewayv1.SandboxWorkloadTemplateSpec{}
	_ = protojson.Unmarshal(item.Spec, spec)
	return &gatewayv1.SandboxWorkloadTemplate{
		Metadata: &datamodelv1.ObjectMeta{Id: item.ID, Name: item.Name, CreatedTime: timestamppb.New(item.CreatedAt), ResourceVersion: item.Revision},
		Spec:     spec,
	}
}
