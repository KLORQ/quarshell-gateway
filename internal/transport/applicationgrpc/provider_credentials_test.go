package applicationgrpc

import (
	"context"
	"testing"

	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConfigureProviderRefreshRequiresCredentialFromCurrentMaterial(t *testing.T) {
	server := New("test", nil, nil, nil, nil, nil, nil, nil)
	request := &gatewayv1.ConfigureProviderRefreshRequest{
		WorkspaceScope: &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}},
		Provider:       "p", CredentialKey: "access_token", Material: map[string]string{"access_token": "first"},
	}
	if _, err := server.ConfigureProviderRefresh(context.Background(), request); err != nil {
		t.Fatalf("configure initial credential: %v", err)
	}
	request.Material = map[string]string{"refresh_token": "second"}
	if _, err := server.ConfigureProviderRefresh(context.Background(), request); err == nil {
		t.Fatal("accepted credential key from an earlier request")
	}
}

func TestConfigureProviderRefreshRejectsInvalidExpiration(t *testing.T) {
	server := New("test", nil, nil, nil, nil, nil, nil, nil)
	_, err := server.ConfigureProviderRefresh(context.Background(), &gatewayv1.ConfigureProviderRefreshRequest{
		WorkspaceScope: &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}},
		Provider:       "p", CredentialKey: "access_token", Material: map[string]string{"access_token": "value"},
		ExpirationTime: &timestamppb.Timestamp{Nanos: 1_000_000_000},
	})
	if err == nil {
		t.Fatal("accepted invalid expiration timestamp")
	}
}
