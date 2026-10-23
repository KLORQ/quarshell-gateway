package applicationhttp

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	credentials "github.com/KLORQ/quarshell-gateway/credentialstore"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/secrets"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func newSecretsClient(t *testing.T) (*client, *eventlog.MemoryLog) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	credentialStore, err := credentials.NewMemoryStore([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	broker, _ := credentials.NewBroker(credentialStore, nil)
	secretsService, _ := secrets.NewService(credentialStore, broker)
	events := eventlog.NewMemoryLog(100)
	server, err := New(workspaces, sandboxes, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.Secrets = secretsService
	server.Events = events
	server.GatewayName = "test"
	server.Capabilities = []string{"sandbox", "policy"}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &client{base: httpServer.URL, token: "secret"}, events
}

func TestSecretsHTTP(t *testing.T) {
	client, _ := newSecretsClient(t)
	response, body := client.do(t, http.MethodPost, "/v1/credentials", map[string]any{
		"id": "cred", "provider": "api", "material": "token",
		"endpoint":   map[string]any{"scheme": "https", "host": "api.example.com", "port": 443},
		"expires_at": time.Now().Add(time.Hour).UTC(),
	}, nil)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", response.StatusCode, body)
	}
	if strings.Contains(string(body), "token") {
		t.Fatalf("material leaked: %s", body)
	}
	response, body = client.do(t, http.MethodGet, "/v1/credentials/cred", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"provider":"api"`) || strings.Contains(string(body), `"material"`) {
		t.Fatalf("get = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/credentials/cred/rotate", map[string]any{
		"material": "new-token", "expires_at": time.Now().Add(time.Hour).UTC(),
	}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d %s", response.StatusCode, body)
	}
	response, body = client.do(t, http.MethodPost, "/v1/credentials/cred/handles", map[string]any{
		"workspace": "ws", "sandbox": "sb",
		"endpoint":   map[string]any{"scheme": "https", "host": "api.example.com", "port": 443},
		"stable_key": "stable", "ttl_seconds": 60,
	}, nil)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("handle = %d %s", response.StatusCode, body)
	}
	var issued struct {
		Handle string `json:"handle"`
	}
	json.Unmarshal(body, &issued)
	response, _ = client.do(t, http.MethodDelete, "/v1/handles/"+issued.Handle, nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d", response.StatusCode)
	}
	response, _ = client.do(t, http.MethodDelete, "/v1/credentials/cred", nil, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", response.StatusCode)
	}
}

func TestGatewayInfoAndEventsHTTP(t *testing.T) {
	client, events := newSecretsClient(t)
	response, body := client.do(t, http.MethodGet, "/v1/gateway/info", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"name":"test"`) {
		t.Fatalf("info = %d %s", response.StatusCode, body)
	}
	response, _ = client.do(t, http.MethodGet, "/v1/healthz", nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", response.StatusCode)
	}
	if _, err := events.Append(t.Context(), "relay", "relay.connected", []byte("payload")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	request, _ := http.NewRequest(http.MethodGet, client.base+"/v1/events?stream=relay", nil)
	request.Header.Set("Authorization", "Bearer "+client.token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	saw := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "relay.connected") {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("event not streamed")
	}
}

func TestHealthIsAvailableWithoutAuthentication(t *testing.T) {
	client, _ := newSecretsClient(t)
	request, err := http.NewRequest(http.MethodGet, client.base+"/v1/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Del("Authorization")
	request.Header.Del("X-Quarshell-Token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	request, err = http.NewRequest(http.MethodGet, client.base+"/v1/gateway/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("gateway info request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated gateway info status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

func TestWhoamiHTTP(t *testing.T) {
	client, _ := newSecretsClient(t)
	response, body := client.do(t, http.MethodGet, "/v1/whoami", nil, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":"gateway-client"`) {
		t.Fatalf("whoami = %d %s", response.StatusCode, body)
	}
}
