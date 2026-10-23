package applicationhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/quota"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/settings"
	"github.com/KLORQ/quarshell-gateway/internal/application/template"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func newConfigClient(t *testing.T) *client {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	settingsService, _ := settings.NewService(store)
	templateService, _ := template.NewService(store)
	quotaService, _ := quota.NewService(store)
	server, err := New(workspaces, sandboxes, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.Settings = settingsService
	server.Templates = templateService
	server.Quotas = quotaService
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &client{base: httpServer.URL, token: "secret"}
}

func TestSettingsHTTP(t *testing.T) {
	client := newConfigClient(t)
	response, body := client.do(t, http.MethodPut, "/v1/workspaces/ws/settings/log_level", map[string]any{"value": "info"}, map[string]string{"Idempotency-Key": "set"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("set = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/settings/log_level", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"value":"info"`) {
		t.Fatalf("get = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPut, "/v1/workspaces/ws/settings/log_level", map[string]any{"value": "debug", "expected_version": 1}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("update = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, "/v1/workspaces/ws/settings", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/workspaces/ws/settings/log_level", nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", response.StatusCode)
	}
}

func TestTemplatesHTTP(t *testing.T) {
	client := newConfigClient(t)
	response, body := client.do(t, http.MethodPost, "/v1/workspaces/ws/templates", map[string]any{
		"id": "basic", "name": "Basic", "spec": map[string]any{"image": "ubuntu"},
	}, map[string]string{"Idempotency-Key": "create"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", response.StatusCode, body)
	}
	var created template.Template
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	response, body = client.do(t, http.MethodPut, "/v1/workspaces/ws/templates/basic", map[string]any{
		"name": "Basic", "spec": map[string]any{"image": "alpine"}, "revision": created.Revision,
	}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("update = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/templates", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"templates":[`) {
		t.Fatalf("list = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/workspaces/ws/templates/basic", nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", response.StatusCode)
	}
}

func TestQuotaHTTP(t *testing.T) {
	client := newConfigClient(t)
	response, body := client.do(t, http.MethodPut, "/v1/workspaces/ws/quota", map[string]any{
		"limits": map[string]any{"cpu": 4, "sandboxes": 2},
	}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("set = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/quota", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"found":true`) {
		t.Fatalf("get = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/quota/check", map[string]any{
		"usage": map[string]any{"cpu": 2, "sandboxes": 1},
	}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("check allowed = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/workspaces/ws/quota/check", map[string]any{
		"usage": map[string]any{"cpu": 10},
	}, nil)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("check exceeded = %d", response.StatusCode)
	}
}
