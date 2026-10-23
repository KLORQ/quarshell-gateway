package applicationgrpc

import (
	"context"
	"errors"
	"strconv"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateWorkspace creates a workspace owned by the gateway principal.
func (s *Server) CreateWorkspace(ctx context.Context, request *gatewayv1.CreateWorkspaceRequest) (*gatewayv1.CreateWorkspaceResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	created, _, err := s.Workspaces.Create(ctx, workspace.CreateRequest{
		ID: domain.WorkspaceID(request.GetName()), Name: request.GetName(), Labels: request.GetLabels(),
		Owner: "gateway", IdempotencyKey: domain.OperationID(request.GetRequestId()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.CreateWorkspaceResponse{Workspace: workspaceProto(created)}, nil
}

// GetWorkspace returns one workspace.
func (s *Server) GetWorkspace(ctx context.Context, request *gatewayv1.GetWorkspaceRequest) (*gatewayv1.GetWorkspaceResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	found, err := s.Workspaces.Get(ctx, domain.WorkspaceID(request.GetName()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.GetWorkspaceResponse{Workspace: workspaceProto(found)}, nil
}

// ListWorkspaces returns a bounded page.
func (s *Server) ListWorkspaces(ctx context.Context, request *gatewayv1.ListWorkspacesRequest) (*gatewayv1.ListWorkspacesResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	items, err := s.Workspaces.List(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(items), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*datamodelv1.Workspace, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, workspaceProto(item))
	}
	return &gatewayv1.ListWorkspacesResponse{Workspaces: out, NextPageToken: next}, nil
}

// DeleteWorkspace removes a workspace idempotently.
func (s *Server) DeleteWorkspace(ctx context.Context, request *gatewayv1.DeleteWorkspaceRequest) (*gatewayv1.DeleteWorkspaceResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	err := s.Workspaces.Delete(ctx, domain.WorkspaceID(request.GetName()), domain.OperationID(request.GetRequestId()))
	if err != nil {
		if request.GetAllowMissing() && domain.CodeOf(err) == domain.CodeNotFound {
			return &gatewayv1.DeleteWorkspaceResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
		}
		return nil, grpcError(err)
	}
	return &gatewayv1.DeleteWorkspaceResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

// AddWorkspaceMember adds or updates a membership.
func (s *Server) AddWorkspaceMember(ctx context.Context, request *gatewayv1.AddWorkspaceMemberRequest) (*gatewayv1.AddWorkspaceMemberResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	member, _, err := s.Workspaces.AddMember(ctx, domain.WorkspaceID(request.GetWorkspaceScope().GetWorkspace()), request.GetPrincipalSubject(), roleFromProto(request.GetRole()), domain.OperationID(request.GetRequestId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.AddWorkspaceMemberResponse{Member: memberProto(member)}, nil
}

// RemoveWorkspaceMember removes a membership.
func (s *Server) RemoveWorkspaceMember(ctx context.Context, request *gatewayv1.RemoveWorkspaceMemberRequest) (*gatewayv1.RemoveWorkspaceMemberResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	err := s.Workspaces.RemoveMember(ctx, domain.WorkspaceID(request.GetWorkspaceScope().GetWorkspace()), request.GetPrincipalSubject(), domain.OperationID(request.GetRequestId()))
	if err != nil {
		if request.GetAllowMissing() && domain.CodeOf(err) == domain.CodeNotFound {
			return &gatewayv1.RemoveWorkspaceMemberResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
		}
		return nil, grpcError(err)
	}
	return &gatewayv1.RemoveWorkspaceMemberResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

// ListWorkspaceMembers returns a bounded page.
func (s *Server) ListWorkspaceMembers(ctx context.Context, request *gatewayv1.ListWorkspaceMembersRequest) (*gatewayv1.ListWorkspaceMembersResponse, error) {
	if s.Workspaces == nil {
		return nil, status.Error(codes.Unavailable, "workspace service is not configured")
	}
	items, err := s.Workspaces.ListMembers(ctx, domain.WorkspaceID(request.GetWorkspaceScope().GetWorkspace()))
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(items), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*gatewayv1.WorkspaceMember, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, memberProto(item))
	}
	return &gatewayv1.ListWorkspaceMembersResponse{Members: out, NextPageToken: next}, nil
}

func workspaceProto(item workspace.Workspace) *datamodelv1.Workspace {
	return &datamodelv1.Workspace{
		Metadata: &datamodelv1.ObjectMeta{Id: string(item.ID), Name: item.Name, Labels: item.Labels, CreatedTime: timestamppb.New(item.CreatedAt)},
		Status:   &datamodelv1.WorkspaceStatus{Phase: datamodelv1.WorkspacePhase_WORKSPACE_PHASE_ACTIVE},
	}
}

func memberProto(item workspace.Member) *gatewayv1.WorkspaceMember {
	return &gatewayv1.WorkspaceMember{
		Metadata:         &datamodelv1.ObjectMeta{Id: item.Subject, CreatedTime: timestamppb.New(item.AddedAt)},
		PrincipalSubject: item.Subject,
		Role:             roleToProto(item.Role),
	}
}

func roleFromProto(role gatewayv1.WorkspaceRole) workspace.Role {
	if role == gatewayv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN {
		return workspace.RoleAdmin
	}
	return workspace.RoleMember
}

func roleToProto(role workspace.Role) gatewayv1.WorkspaceRole {
	if role == workspace.RoleOwner || role == workspace.RoleAdmin {
		return gatewayv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN
	}
	return gatewayv1.WorkspaceRole_WORKSPACE_ROLE_USER
}

func page(total int, size int32, token string) (int, int, string, error) {
	if size < 0 {
		return 0, 0, "", status.Error(codes.InvalidArgument, "page_size must not be negative")
	}
	if size == 0 || size > 1000 {
		size = 100
	}
	start := 0
	if token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 || parsed > total {
			return 0, 0, "", status.Error(codes.InvalidArgument, "invalid page_token")
		}
		start = parsed
	}
	end := start + int(size)
	if end > total {
		end = total
	}
	next := ""
	if end < total {
		next = strconv.Itoa(end)
	}
	return start, end, next, nil
}

func grpcError(err error) error {
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "operation canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "operation deadline exceeded")
	}
	switch domain.CodeOf(err) {
	case domain.CodeNotFound:
		return status.Error(codes.NotFound, err.Error())
	case domain.CodeConflict:
		return status.Error(codes.Aborted, err.Error())
	case domain.CodeInvalid:
		return status.Error(codes.InvalidArgument, err.Error())
	case domain.CodeUnauthorized:
		return status.Error(codes.Unauthenticated, err.Error())
	case domain.CodePermissionDenied:
		return status.Error(codes.PermissionDenied, err.Error())
	case domain.CodeUnavailable:
		return status.Error(codes.Unavailable, err.Error())
	case domain.CodeUnsupported:
		return status.Error(codes.Unimplemented, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
