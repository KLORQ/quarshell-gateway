package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

var workspaceSelector = datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}

func TestWorkspaceRPC(t *testing.T) {
	workspaces, err := workspace.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server := New("test", workspaces, nil, nil, nil, nil, nil, nil)
	ctx := context.Background()
	created, err := server.CreateWorkspace(ctx, &gatewayv1.CreateWorkspaceRequest{Name: "ws", RequestId: "create-ws"})
	if err != nil || created.GetWorkspace().GetMetadata().GetName() != "ws" {
		t.Fatalf("CreateWorkspace = %+v err=%v", created, err)
	}
	got, err := server.GetWorkspace(ctx, &gatewayv1.GetWorkspaceRequest{Name: "ws"})
	if err != nil || got.GetWorkspace().GetMetadata().GetId() != "ws" {
		t.Fatalf("GetWorkspace = %+v err=%v", got, err)
	}
	list, err := server.ListWorkspaces(ctx, &gatewayv1.ListWorkspacesRequest{PageSize: 1})
	if err != nil || len(list.GetWorkspaces()) != 1 {
		t.Fatalf("ListWorkspaces = %+v err=%v", list, err)
	}
	added, err := server.AddWorkspaceMember(ctx, &gatewayv1.AddWorkspaceMemberRequest{
		WorkspaceScope: &workspaceSelector, PrincipalSubject: "alice", Role: gatewayv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
	})
	if err != nil || added.GetMember().GetPrincipalSubject() != "alice" {
		t.Fatalf("AddWorkspaceMember = %+v err=%v", added, err)
	}
	members, err := server.ListWorkspaceMembers(ctx, &gatewayv1.ListWorkspaceMembersRequest{WorkspaceScope: &workspaceSelector})
	if err != nil || len(members.GetMembers()) != 2 {
		t.Fatalf("ListWorkspaceMembers = %+v err=%v", members, err)
	}
	if _, err := server.RemoveWorkspaceMember(ctx, &gatewayv1.RemoveWorkspaceMemberRequest{WorkspaceScope: &workspaceSelector, PrincipalSubject: "alice"}); err != nil {
		t.Fatalf("RemoveWorkspaceMember: %v", err)
	}
	deleted, err := server.DeleteWorkspace(ctx, &gatewayv1.DeleteWorkspaceRequest{Name: "ws"})
	if err != nil || deleted.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("DeleteWorkspace = %+v err=%v", deleted, err)
	}
}
