package applicationhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/token"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func TestSandboxTokensHTTP(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	if _, _, err := sandboxes.Create(t.Context(), sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"}); err != nil {
		t.Fatalf("create sandbox for token test: %v", err)
	}
	tokens, _ := token.NewService([]byte("0123456789abcdef"), time.Hour)
	server, _ := New(workspaces, sandboxes, "secret")
	server.Tokens = tokens
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	client := &client{base: httpServer.URL, token: "secret"}

	response, body := client.do(t, http.MethodPost, "/v1/workspaces/ws/sandboxes/sb/tokens", map[string]any{
		"subject": "alice", "ttl_seconds": 60,
	}, nil)
	if response.StatusCode != http.StatusCreated || !strings.Contains(string(body), `"token":"`) {
		t.Fatalf("issue = %d %s", response.StatusCode, body)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := jsonUnmarshal(body, &issued); err != nil || issued.Token == "" {
		t.Fatalf("decode token = %v", err)
	}
	response, body = client.do(t, http.MethodPost, "/v1/tokens/refresh", map[string]any{"token": issued.Token, "ttl_seconds": 60}, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"sub":"spiffe://openshell/sandbox/sb"`) {
		t.Fatalf("refresh = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodPost, "/v1/tokens/refresh", map[string]any{"token": issued.Token + "x"}, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered refresh = %d", response.StatusCode)
	}
}

func jsonUnmarshal(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
