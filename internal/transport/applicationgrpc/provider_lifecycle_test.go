package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

func TestProviderProfilesAndBindings(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	registry, _ := provider.NewRegistry(store)
	bindings, _ := provider.NewService(store)
	sandboxes, _ := sandboxapp.NewService(store)
	server := New("test", nil, sandboxes, nil, nil, nil, registry, nil)
	server.ProviderBindings = bindings
	ctx := context.Background()
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Create(ctx, provider.CreateRequest{ID: "p", Name: "p", Driver: "api"}); err != nil {
		t.Fatal(err)
	}
	attached, err := server.AttachSandboxProvider(ctx, &gatewayv1.AttachSandboxProviderRequest{WorkspaceScope: selector, Sandbox: "sb", Provider: "p"})
	if err != nil || !attached.GetAttached() {
		t.Fatalf("Attach = %+v err=%v", attached, err)
	}
	attachedAgain, err := server.AttachSandboxProvider(ctx, &gatewayv1.AttachSandboxProviderRequest{WorkspaceScope: selector, Sandbox: "sb", Provider: "p"})
	if err != nil || attachedAgain.GetAttached() {
		t.Fatalf("repeat Attach = %+v err=%v, want already attached", attachedAgain, err)
	}
	status, err := server.GetSandboxProviderStatus(ctx, &gatewayv1.GetSandboxProviderStatusRequest{WorkspaceScope: selector, Sandbox: "sb", Provider: "p"})
	if err != nil || status.GetStatus() == nil {
		t.Fatalf("Status = %+v err=%v", status, err)
	}
	detached, err := server.DetachSandboxProvider(ctx, &gatewayv1.DetachSandboxProviderRequest{WorkspaceScope: selector, Sandbox: "sb", Provider: "p"})
	if err != nil || !detached.GetDetached() {
		t.Fatalf("Detach = %+v err=%v", detached, err)
	}
	item := &gatewayv1.ProviderProfileImportItem{Profile: &gatewayv1.ProviderProfile{Id: "prof", DisplayName: "Prof"}}
	imported, err := server.ImportProviderProfiles(ctx, &gatewayv1.ImportProviderProfilesRequest{Profiles: []*gatewayv1.ProviderProfileImportItem{item}})
	if err != nil || !imported.GetImported() || len(imported.GetProfiles()) != 1 {
		t.Fatalf("Import = %+v err=%v", imported, err)
	}
	linted, err := server.LintProviderProfiles(ctx, &gatewayv1.LintProviderProfilesRequest{Profiles: []*gatewayv1.ProviderProfileImportItem{{Profile: &gatewayv1.ProviderProfile{Id: "", DisplayName: ""}}}})
	if err != nil || linted.GetValid() {
		t.Fatalf("Lint = %+v err=%v", linted, err)
	}
	deleted, err := server.DeleteProviderProfile(ctx, &gatewayv1.DeleteProviderProfileRequest{Id: "prof"})
	if err != nil || deleted.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("Delete = %+v err=%v", deleted, err)
	}
}
