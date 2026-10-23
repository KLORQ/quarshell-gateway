package applicationhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func newPolicyClient(t *testing.T) (*client, *policyapp.Service) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	policies, _ := policyapp.NewService(store)
	server, err := New(workspaces, sandboxes, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.Policies = policies
	chunks, _ := policyapp.NewChunkService(store, policies)
	server.PolicyChunks = chunks
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &client{base: httpServer.URL, token: "secret"}, policies
}

func TestPolicyHTTPLifecycle(t *testing.T) {
	client, _ := newPolicyClient(t)
	response, body := client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/drafts", map[string]any{
		"source": "version: 1\n", "author": "alice",
	}, map[string]string{"Idempotency-Key": "draft"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("draft = %d %s", response.StatusCode, body)
	}
	var revision policyapp.Revision
	if err := json.Unmarshal(body, &revision); err != nil {
		t.Fatalf("decode revision: %v", err)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/"+revision.ID+"/approve", map[string]any{"approver": "bob"}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/policies/active", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"found":true`) {
		t.Fatalf("active = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/policies/history", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"revisions":[`) {
		t.Fatalf("history = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/"+revision.ID+"/observe", map[string]any{"generation": 3}, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"observed_generation":3`) {
		t.Fatalf("observe = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/policies/"+revision.ID+"/analysis", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"Containment"`) {
		t.Fatalf("analysis = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/drafts", map[string]any{
		"source": "unknown: true\n", "author": "alice",
	}, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid source = %d", response.StatusCode)
	}
}

func TestPolicyChunksHTTP(t *testing.T) {
	client, _ := newPolicyClient(t)
	response, body := client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/draft/chunks", map[string]any{
		"sandbox": "sb", "id": "a", "index": 1, "source": "allow /a", "author": "alice", "idempotency_key": "edit-a",
	}, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":"a"`) {
		t.Fatalf("edit = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/policies/draft?sandbox=sb", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"chunks":[`) {
		t.Fatalf("draft = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/draft/approve-all", map[string]any{
		"sandbox": "sb", "approver": "bob",
	}, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"source":"allow /a"`) {
		t.Fatalf("approve all = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/workspaces/ws/policies/draft/history?sandbox=sb", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"chunks":[`) {
		t.Fatalf("history = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/workspaces/ws/policies/draft/chunks/a/undo", map[string]any{
		"sandbox": "sb",
	}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("undo = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/workspaces/ws/policies/draft/chunks?sandbox=sb", nil, map[string]string{"Idempotency-Key": "clear"})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("clear = %d", response.StatusCode)
	}
}
