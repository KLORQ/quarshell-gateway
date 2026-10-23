package applicationhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/endpoint"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func newResourceClient(t *testing.T) *client {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	providers, _ := provider.NewService(store)
	services, _ := endpoint.NewServiceRegistry(store)
	forwards, _ := endpoint.NewForwardRegistry(store)
	server, err := New(workspaces, sandboxes, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.Providers = providers
	server.Services = services
	server.Forwards = forwards
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &client{base: httpServer.URL, token: "secret"}
}

func TestProviderHTTP(t *testing.T) {
	client := newResourceClient(t)
	base := "/v1/workspaces/ws/sandboxes/sb/providers"
	response, body := client.do(t, http.MethodPost, base, map[string]any{
		"provider": "github", "revision": 1, "config": map[string]any{"token": "ref"},
	}, map[string]string{"Idempotency-Key": "bind"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("bind = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, base, nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"providers":[`) {
		t.Fatalf("list = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, base+"/github/ack", map[string]any{"revision": 1}, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"readiness":"ready"`) {
		t.Fatalf("ack = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, base+"/github", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("get = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, base+"/github", nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unbind = %d", response.StatusCode)
	}
}

func TestServiceAndForwardHTTP(t *testing.T) {
	client := newResourceClient(t)
	services := "/v1/workspaces/ws/sandboxes/sb/services"
	response, body := client.do(t, http.MethodPost, services, map[string]any{
		"id": "web", "name": "Web", "url": "https://sandbox.example/", "port": 8080, "protocol": "http", "auth_mode": "strip",
	}, map[string]string{"Idempotency-Key": "expose"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expose = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, services, nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"services":[`) {
		t.Fatalf("services list = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, services+"/web", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("service get = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, services+"/web", nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("service delete = %d", response.StatusCode)
	}

	forwards := "/v1/workspaces/ws/sandboxes/sb/forwards"
	response, body = client.do(t, http.MethodPost, forwards, map[string]any{
		"id": "db", "local_port": 15432, "remote_host": "db.internal", "remote_port": 5432, "protocol": "tcp",
	}, map[string]string{"Idempotency-Key": "forward"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("forward = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, forwards, nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"forwards":[`) {
		t.Fatalf("forwards list = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, forwards+"/db", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("forward get = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, forwards+"/db", nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("forward delete = %d", response.StatusCode)
	}
}
