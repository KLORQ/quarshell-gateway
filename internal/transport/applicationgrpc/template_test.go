package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/template"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

func TestTemplateRPC(t *testing.T) {
	templates, err := template.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server := New("test", nil, nil, nil, templates, nil, nil, nil)
	ctx := context.Background()
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	created, err := server.CreateSandboxTemplate(ctx, &gatewayv1.CreateSandboxTemplateRequest{
		WorkspaceScope: selector,
		Template:       &gatewayv1.SandboxWorkloadTemplate{Metadata: &datamodelv1.ObjectMeta{Name: "tpl"}, Spec: &gatewayv1.SandboxWorkloadTemplateSpec{}},
	})
	if err != nil || created.GetTemplate().GetMetadata().GetName() != "tpl" {
		t.Fatalf("Create = %+v err=%v", created, err)
	}
	if _, err := server.GetSandboxTemplate(ctx, &gatewayv1.GetSandboxTemplateRequest{WorkspaceScope: selector, Name: "tpl"}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	list, err := server.ListSandboxTemplates(ctx, &gatewayv1.ListSandboxTemplatesRequest{WorkspaceScope: selector})
	if err != nil || len(list.GetTemplates()) != 1 {
		t.Fatalf("List = %+v err=%v", list, err)
	}
	if _, err := server.DeleteSandboxTemplate(ctx, &gatewayv1.DeleteSandboxTemplateRequest{WorkspaceScope: selector, Name: "tpl"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	missing, err := server.DeleteSandboxTemplate(ctx, &gatewayv1.DeleteSandboxTemplateRequest{WorkspaceScope: selector, Name: "tpl", AllowMissing: true})
	if err != nil || missing.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT {
		t.Fatalf("Delete missing = %+v err=%v", missing, err)
	}
}
