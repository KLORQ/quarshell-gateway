package applicationhttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

type client struct {
	base  string
	token string
}

func newClient(t *testing.T) *client {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	workspaces, err := workspace.NewService(store)
	if err != nil {
		t.Fatalf("workspace.NewService: %v", err)
	}
	sandboxes, err := sandbox.NewService(store)
	if err != nil {
		t.Fatalf("sandbox.NewService: %v", err)
	}
	server, err := New(workspaces, sandboxes, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &client{base: httpServer.URL, token: "secret"}
}

func (c *client) do(t *testing.T, method, path string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	payload, _ := io.ReadAll(response.Body)
	response.Body.Close()
	return response, payload
}

func TestWorkspaceAndSandboxHTTP(t *testing.T) {
	client := newClient(t)
	response, body := client.do(t, http.MethodPost, "/v1/workspaces", map[string]any{
		"id": "ws", "name": "Workspace", "owner": "alice",
	}, map[string]string{"Idempotency-Key": "create-ws"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create workspace = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/workspaces", map[string]any{
		"id": "ws", "name": "Workspace", "owner": "alice",
	}, map[string]string{"Idempotency-Key": "create-ws"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("replay workspace = %d", response.StatusCode)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/sandboxes", map[string]any{
		"id": "sb", "generation": 1, "image": "ubuntu:24.04", "command": []string{"/bin/true"},
	}, map[string]string{"Idempotency-Key": "create-sb"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create sandbox = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/sandboxes/sb", nil, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"sandbox":"sb"`)) {
		t.Fatalf("get sandbox = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/sandboxes/sb/start", map[string]any{
		"generation": 1, "idempotency_key": "start-sb",
	}, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"state":"running"`)) {
		t.Fatalf("start sandbox = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/sandboxes/sb/stop", map[string]any{
		"generation": 1, "idempotency_key": "stop-sb",
	}, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"state":"stopped"`)) {
		t.Fatalf("stop sandbox = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/sandboxes", nil, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"sandboxes":[`)) {
		t.Fatalf("list sandboxes = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, "/v1/workspaces", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list workspaces = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/workspaces/ws/sandboxes/sb", nil, map[string]string{"Idempotency-Key": "delete-sb"})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete sandbox = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodGet, "/v1/workspaces/ws/sandboxes/sb", nil, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted sandbox = %d", response.StatusCode)
	}
}

func TestHTTPAuthAndErrors(t *testing.T) {
	client := newClient(t)
	request, _ := http.NewRequest(http.MethodGet, client.base+"/v1/workspaces", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/workspaces", map[string]any{"id": "ws"}, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid body = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/workspaces", map[string]any{"id": "ws", "name": "W", "owner": "a"}, nil)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/workspaces", map[string]any{"id": "ws", "name": "Other", "owner": "a"}, nil)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate = %d", response.StatusCode)
	}
}

func TestPolicyEventStream(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	policyService, _ := policyapp.NewService(store)
	policyService.Events = eventlog.NewMemoryLog(100)
	draft, _, err := policyService.CreateDraft(context.Background(), policyapp.DraftRequest{
		Scope: policyapp.Scope{Workspace: "ws"}, Source: []byte("version: 1\n"), Author: "alice", IdempotencyKey: "draft",
	})
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := policyService.Approve(context.Background(), policyapp.Scope{Workspace: "ws"}, draft.ID, "bob", "approve"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	server, _ := New(workspaces, sandboxes, "secret")
	server.Events = policyService.Events
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/v1/workspaces/ws/policies/events", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("SSE request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("SSE status = %d", response.StatusCode)
	}
	scanner := bufio.NewScanner(response.Body)
	sawActivated := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "policy.activated") {
			sawActivated = true
			break
		}
	}
	if !sawActivated {
		t.Fatalf("policy.activated event not streamed")
	}
}
