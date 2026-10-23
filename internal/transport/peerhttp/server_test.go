package peerhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-gateway/internal/application/peer"
)

func TestPeerOwnershipHTTP(t *testing.T) {
	registry := peer.NewRegistry(nil)
	ctx := context.Background()
	if _, err := registry.Join(ctx, "a", "https://a"); err != nil {
		t.Fatalf("Join: %v", err)
	}
	leader, err := registry.Claim(ctx, "a", time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	server, err := New(registry, "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/v1/peer/owner")
	if err != nil {
		t.Fatalf("unauthenticated: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/peer/owner", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	var owner peer.Peer
	if err := json.NewDecoder(response.Body).Decode(&owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}
	response.Body.Close()
	if owner.ID != "a" || !owner.Leader {
		t.Fatalf("owner = %+v", owner)
	}

	request, _ = http.NewRequest(http.MethodGet, httpServer.URL+"/v1/peer/peers", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, _ = http.DefaultClient.Do(request)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("peers = %d", response.StatusCode)
	}

	body, _ := json.Marshal(map[string]any{"id": "a", "token": leader.FencingToken})
	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/peer/validate", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	response, _ = http.DefaultClient.Do(request)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("validate valid = %d", response.StatusCode)
	}

	body, _ = json.Marshal(map[string]any{"id": "b", "token": leader.FencingToken})
	request, _ = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/peer/validate", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	response, _ = http.DefaultClient.Do(request)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("validate stale = %d", response.StatusCode)
	}
}

func TestPeerTransportValidation(t *testing.T) {
	if _, err := New(nil, "secret"); err == nil {
		t.Fatalf("nil registry accepted")
	}
	if _, err := New(peer.NewRegistry(nil), ""); err == nil {
		t.Fatalf("empty token accepted")
	}
}

func TestPeerOwnershipRPC(t *testing.T) {
	registry := peer.NewRegistry(nil)
	server, _ := New(registry, "secret")
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	do := func(path string, body any) (*http.Response, map[string]any) {
		encoded, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, httpServer.URL+path, bytes.NewReader(encoded))
		request.Header.Set("Authorization", "Bearer secret")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var payload map[string]any
		_ = json.NewDecoder(response.Body).Decode(&payload)
		response.Body.Close()
		return response, payload
	}
	response, _ := do("/v1/peer/join", map[string]any{"id": "a", "endpoint": "https://a"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("join = %d", response.StatusCode)
	}
	response, payload := do("/v1/peer/claim", map[string]any{"id": "a", "ttl_seconds": 60})
	if response.StatusCode != http.StatusOK || payload["leader"] != true {
		t.Fatalf("claim = %d %+v", response.StatusCode, payload)
	}
	token := uint64(payload["fencing_token"].(float64))
	response, _ = do("/v1/peer/heartbeat", map[string]any{"id": "a", "token": token, "ttl_seconds": 60})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat = %d", response.StatusCode)
	}
	response, _ = do("/v1/peer/release", map[string]any{"id": "a", "token": token})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("release = %d", response.StatusCode)
	}
}
