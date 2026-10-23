package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	"github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListSandboxProvidersReturnsBoundDefinitionsWithPagination(t *testing.T) {
	ctx := context.Background()
	store := lifecycle.NewMemoryStore()
	workspaces, err := workspace.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	sandboxes, err := sandbox.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := provider.NewRegistry(store)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := provider.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := workspaces.Create(ctx, workspace.CreateRequest{ID: "ws", Name: "ws", Owner: "operator"}); err != nil {
		t.Fatal(err)
	}
	server := New("test", workspaces, sandboxes, nil, nil, nil, definitions, nil)
	server.ProviderBindings = bindings
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	if _, err := server.CreateSandbox(ctx, &gatewayv1.CreateSandboxRequest{
		WorkspaceScope: selector,
		Name:           "sb",
		Spec:           &gatewayv1.SandboxSpec{Template: &gatewayv1.SandboxTemplate{Image: "ubuntu:24.04"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if _, err := server.CreateProvider(ctx, &gatewayv1.CreateProviderRequest{
			Provider: &datamodelv1.Provider{Metadata: &datamodelv1.ObjectMeta{Name: name}, Type: "api"},
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := bindings.Bind(ctx, provider.BindRequest{
			Sandbox:  domain.SandboxRef{Workspace: "ws", Sandbox: "sb"},
			Provider: domain.ProviderID(name), Revision: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := server.ListSandboxProviders(ctx, &gatewayv1.ListSandboxProvidersRequest{
		WorkspaceScope: selector, Sandbox: "sb", PageSize: 1,
	})
	if err != nil || len(first.GetProviders()) != 1 || first.GetNextPageToken() == "" {
		t.Fatalf("first page = %+v, err=%v", first, err)
	}
	second, err := server.ListSandboxProviders(ctx, &gatewayv1.ListSandboxProvidersRequest{
		WorkspaceScope: selector, Sandbox: "sb", PageSize: 1, PageToken: first.GetNextPageToken(),
	})
	if err != nil || len(second.GetProviders()) != 1 || second.GetNextPageToken() != "" {
		t.Fatalf("second page = %+v, err=%v", second, err)
	}
	if first.GetProviders()[0].GetMetadata().GetName() != "alpha" || second.GetProviders()[0].GetMetadata().GetName() != "beta" {
		t.Fatalf("unexpected pages: first=%q second=%q", first.GetProviders()[0].GetMetadata().GetName(), second.GetProviders()[0].GetMetadata().GetName())
	}
}

func TestListSandboxProvidersRequiresExistingSandbox(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	sandboxes, _ := sandbox.NewService(store)
	definitions, _ := provider.NewRegistry(store)
	bindings, _ := provider.NewService(store)
	server := New("test", nil, sandboxes, nil, nil, nil, definitions, nil)
	server.ProviderBindings = bindings
	_, err := server.ListSandboxProviders(context.Background(), &gatewayv1.ListSandboxProvidersRequest{
		WorkspaceScope: &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}},
		Sandbox:        "missing",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("missing sandbox error = %v, want NotFound", err)
	}
}
