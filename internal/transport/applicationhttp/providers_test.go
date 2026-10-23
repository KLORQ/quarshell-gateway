package applicationhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func newProviderClient(t *testing.T) *client {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	registry, err := provider.NewRegistry(store)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	server, err := New(workspaces, sandboxes, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.ProviderDefs = registry
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &client{base: httpServer.URL, token: "secret"}
}

func TestProviderRegistryHTTP(t *testing.T) {
	client := newProviderClient(t)
	response, body := client.do(t, http.MethodPost, "/v1/providers", map[string]any{
		"id": "api", "name": "API", "driver": "openai", "config": map[string]any{"base_url": "https://api.example.com"},
		"profiles":        []map[string]any{{"id": "default", "name": "Default", "config": map[string]any{"model": "gpt"}}},
		"idempotency_key": "create-api",
	}, nil)
	if response.StatusCode != http.StatusCreated || !bytes.Contains(body, []byte(`"id":"api"`)) {
		t.Fatalf("create = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/providers", map[string]any{
		"id": "api", "name": "API", "driver": "openai", "config": map[string]any{"base_url": "https://api.example.com"},
		"profiles":        []map[string]any{{"id": "default", "name": "Default", "config": map[string]any{"model": "gpt"}}},
		"idempotency_key": "create-api",
	}, nil)
	if response.StatusCode != http.StatusCreated || !bytes.Contains(body, []byte(`"replayed":true`)) {
		t.Fatalf("replay = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/providers", nil, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"providers":[`)) {
		t.Fatalf("list = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/providers/api/profiles", nil, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"id":"default"`)) {
		t.Fatalf("profiles = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/providers/api/profiles/lint", map[string]any{
		"profiles": []map[string]any{{"id": "", "name": ""}},
	}, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"issues":[`)) {
		t.Fatalf("lint = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/providers/api/profiles", map[string]any{
		"profiles": []map[string]any{{"id": "fast", "name": "Fast"}}, "idempotency_key": "import-fast",
	}, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"id":"fast"`)) {
		t.Fatalf("import = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, "/v1/providers/api/profiles/fast", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("get profile = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/providers/api/profiles/fast", nil, map[string]string{"Idempotency-Key": "delete-fast"})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete profile = %d", response.StatusCode)
	}
	response, body = client.do(t, http.MethodPut, "/v1/providers/api", map[string]any{
		"name": "API v2", "driver": "openai", "config": map[string]any{}, "expected_revision": 1,
	}, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"revision":2`)) {
		t.Fatalf("update = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/providers/api", nil, map[string]string{"Idempotency-Key": "delete-api"})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", response.StatusCode)
	}
}
