package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/endpoint"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

func TestServiceRPC(t *testing.T) {
	services, err := endpoint.NewServiceRegistry(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewServiceRegistry: %v", err)
	}
	server := New("test", nil, nil, nil, nil, nil, nil, services)
	ctx := context.Background()
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	exposed, err := server.ExposeService(ctx, &gatewayv1.ExposeServiceRequest{
		WorkspaceScope: selector, Sandbox: "sb", Name: "web", TargetPort: 8080,
	})
	if err != nil || exposed.GetEndpoint().GetName() != "web" {
		t.Fatalf("ExposeService = %+v err=%v", exposed, err)
	}
	if _, err := server.GetService(ctx, &gatewayv1.GetServiceRequest{WorkspaceScope: selector, Sandbox: "sb", Name: "web"}); err != nil {
		t.Fatalf("GetService: %v", err)
	}
	list, err := server.ListServices(ctx, &gatewayv1.ListServicesRequest{WorkspaceScope: selector, Sandbox: "sb"})
	if err != nil || len(list.GetServices()) != 1 {
		t.Fatalf("ListServices = %+v err=%v", list, err)
	}
	if _, err := server.DeleteService(ctx, &gatewayv1.DeleteServiceRequest{WorkspaceScope: selector, Sandbox: "sb", Name: "web"}); err != nil {
		t.Fatalf("DeleteService: %v", err)
	}
	missing, err := server.DeleteService(ctx, &gatewayv1.DeleteServiceRequest{WorkspaceScope: selector, Sandbox: "sb", Name: "web", AllowMissing: true})
	if err != nil || missing.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT {
		t.Fatalf("Delete missing = %+v err=%v", missing, err)
	}
}
