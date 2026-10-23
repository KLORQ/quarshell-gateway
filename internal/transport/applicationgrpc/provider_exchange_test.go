package applicationgrpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KLORQ/quarshell-credentials"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

func TestExchangeProviderSubjectToken(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		if request.Form.Get("subject_token") != "svid" || request.Form.Get("audience") != "aud" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "token", "expires_in": 60})
	}))
	defer endpoint.Close()
	exchange, err := credentials.NewOAuthExchange(credentials.OAuthConfig{Endpoint: endpoint.URL, Audience: "aud"})
	if err != nil {
		t.Fatal(err)
	}
	sandboxes, _ := sandboxapp.NewService(lifecycle.NewMemoryStore())
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.OAuthExchange = exchange
	ctx := context.Background()
	ref := sandboxappRef("ws", "sb")
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start-sb")
	if err != nil {
		t.Fatal(err)
	}
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	if _, err := server.ConfigureProviderRefresh(ctx, &gatewayv1.ConfigureProviderRefreshRequest{
		WorkspaceScope: selector, Provider: "p", CredentialKey: "access_token", Material: map[string]string{"access_token": "value"},
	}); err != nil {
		t.Fatal(err)
	}
	sandboxCtx := context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: ref.Sandbox,
		generation: started.RuntimeGeneration, credentialEpoch: started.CredentialEpoch,
	})
	response, err := server.ExchangeProviderSubjectToken(sandboxCtx, &gatewayv1.ExchangeProviderSubjectTokenRequest{
		SandboxId: "sb", Provider: "p", CredentialKey: "access_token", SupervisorJwtSvid: "svid",
	})
	if err != nil || response.GetAccessToken() != "token" {
		t.Fatalf("Exchange = %+v err=%v", response, err)
	}
}
