package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

func TestProviderRPC(t *testing.T) {
	registry, err := provider.NewRegistry(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	server := New("test", nil, nil, nil, nil, nil, registry, nil)
	ctx := context.Background()
	created, err := server.CreateProvider(ctx, &gatewayv1.CreateProviderRequest{
		Provider: &datamodelv1.Provider{Metadata: &datamodelv1.ObjectMeta{Name: "p"}, Type: "api", Config: map[string]string{"base_url": "https://example.com"}},
	})
	if err != nil || created.GetProvider().GetMetadata().GetName() != "p" {
		t.Fatalf("CreateProvider = %+v err=%v", created, err)
	}
	if _, err := server.GetProvider(ctx, &gatewayv1.GetProviderRequest{Name: "p"}); err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	list, err := server.ListProviders(ctx, &gatewayv1.ListProvidersRequest{})
	if err != nil || len(list.GetProviders()) != 1 {
		t.Fatalf("ListProviders = %+v err=%v", list, err)
	}
	updated, err := server.UpdateProvider(ctx, &gatewayv1.UpdateProviderRequest{
		Provider: &datamodelv1.Provider{Metadata: &datamodelv1.ObjectMeta{Name: "p", ResourceVersion: 1}, Type: "api", Config: map[string]string{}},
	})
	if err != nil || updated.GetProvider().GetMetadata().GetResourceVersion() != 2 {
		t.Fatalf("UpdateProvider = %+v err=%v", updated, err)
	}
	if _, _, err := registry.ImportProfiles(ctx, "p", []provider.ProfileInput{{ID: "default", Name: "Default"}}, "import"); err != nil {
		t.Fatalf("ImportProfiles: %v", err)
	}
	profiles, err := server.ListProviderProfiles(ctx, &gatewayv1.ListProviderProfilesRequest{})
	if err != nil || len(profiles.GetProfiles()) != 1 {
		t.Fatalf("ListProviderProfiles = %+v err=%v", profiles, err)
	}
	if _, err := server.GetProviderProfile(ctx, &gatewayv1.GetProviderProfileRequest{Id: "default"}); err != nil {
		t.Fatalf("GetProviderProfile: %v", err)
	}
	if _, err := server.DeleteProvider(ctx, &gatewayv1.DeleteProviderRequest{Name: "p"}); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	missing, err := server.DeleteProvider(ctx, &gatewayv1.DeleteProviderRequest{Name: "p", AllowMissing: true})
	if err != nil || missing.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT {
		t.Fatalf("Delete missing = %+v err=%v", missing, err)
	}
}
