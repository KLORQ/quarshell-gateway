package credentialstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

type fakeVaultRecord struct {
	record  string
	version uint64
}

type fakeVault struct {
	mu        sync.Mutex
	token     string
	namespace string
	mount     string
	records   map[string]fakeVaultRecord
}

func newFakeVault(token, namespace, mount string) *fakeVault {
	return &fakeVault{token: token, namespace: namespace, mount: mount, records: map[string]fakeVaultRecord{}}
}

func (v *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != v.token {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if v.namespace != "" && r.Header.Get("X-Vault-Namespace") != v.namespace {
		http.Error(w, "namespace", http.StatusForbidden)
		return
	}
	prefix := "/v1/" + v.mount + "/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case strings.HasPrefix(path, "data/"):
		id := strings.TrimPrefix(path, "data/")
		if r.Method == http.MethodGet {
			record, exists := v.records[id]
			if !exists {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     map[string]any{"record": record.record},
					"metadata": map[string]any{"version": record.version},
				},
			})
			return
		}
		var body struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS uint64 `json:"cas"`
			} `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		current, exists := v.records[id]
		if body.Options.CAS == 0 && exists {
			http.Error(w, "exists", http.StatusPreconditionFailed)
			return
		}
		if body.Options.CAS > 0 && (!exists || current.version != body.Options.CAS) {
			http.Error(w, "cas", http.StatusPreconditionFailed)
			return
		}
		version := current.version + 1
		v.records[id] = fakeVaultRecord{record: body.Data["record"].(string), version: version}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"metadata": map[string]any{"version": version}}})
	case strings.HasPrefix(path, "metadata/"):
		id := strings.TrimPrefix(path, "metadata/")
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if _, exists := v.records[id]; !exists {
			http.NotFound(w, r)
			return
		}
		delete(v.records, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func newVaultStore(t *testing.T, server *httptest.Server, token string) *VaultStore {
	t.Helper()
	return newVaultStoreWithNamespace(t, server, token, "")
}

func newVaultStoreWithNamespace(t *testing.T, server *httptest.Server, token, namespace string) *VaultStore {
	t.Helper()
	store, err := NewVaultStore(VaultConfig{
		Address: server.URL, Token: token, Namespace: namespace, Mount: "secret", PathPrefix: "quarshell",
		Key: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}
	return store
}

func TestVaultStoreLifecycle(t *testing.T) {
	vault := newFakeVault("token", "", "secret")
	server := httptest.NewServer(vault)
	defer server.Close()
	store := newVaultStore(t, server, "token")
	secret := testSecret()
	secret.Endpoint = EndpointBinding{Scheme: "https", Host: "api.github.com", Port: 443}
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.Contains(vault.records["quarshell/cred-1"].record, "nonce") || strings.Contains(vault.records["quarshell/cred-1"].record, "super-secret-token") {
		t.Fatalf("record at rest = %q", vault.records["quarshell/cred-1"].record)
	}
	loaded, err := store.Get(context.Background(), "cred-1")
	if err != nil || string(loaded.Material) != "super-secret-token" || loaded.Revision != 1 {
		t.Fatalf("Get = %+v %v", loaded, err)
	}
	rotated, err := store.Rotate(context.Background(), "cred-1", []byte("rotated"), time.Now().Add(time.Hour))
	if err != nil || rotated.Revision != 2 || string(rotated.Material) != "rotated" {
		t.Fatalf("Rotate = %+v %v", rotated, err)
	}
	if err := store.Delete(context.Background(), "cred-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(context.Background(), "cred-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestVaultStoreErrors(t *testing.T) {
	vault := newFakeVault("token", "team", "secret")
	server := httptest.NewServer(vault)
	defer server.Close()
	good := newVaultStoreWithNamespace(t, server, "token", "team")
	if _, err := good.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	wrong := newVaultStoreWithNamespace(t, server, "wrong", "team")
	if _, err := wrong.Get(context.Background(), "cred-1"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("wrong token = %v", err)
	}
	// Namespace mismatch is also a permission error.
	namespaceStore, err := NewVaultStore(VaultConfig{
		Address: server.URL, Token: "token", Namespace: "other", Mount: "secret", PathPrefix: "quarshell",
		Key: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}
	if _, err := namespaceStore.Get(context.Background(), "cred-1"); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("namespace mismatch = %v", err)
	}
	// CAS conflict: a write with a stale version is rejected.
	first := newVaultStoreWithNamespace(t, server, "token", "team")
	record, version, err := first.read(context.Background(), "cred-1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := first.write(context.Background(), "cred-1", record, version+100); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale CAS = %v", err)
	}
}

func TestVaultStoreConfigValidation(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for name, config := range map[string]VaultConfig{
		"address": {Address: "ftp://vault", Token: "t", Key: key},
		"token":   {Address: "http://vault", Token: " ", Key: key},
		"key":     {Address: "http://vault", Token: "t", Key: []byte("short")},
		"mount":   {Address: "http://vault", Token: "t", Mount: "a/../b", Key: key},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVaultStore(config); err == nil {
				t.Fatalf("invalid config accepted")
			}
		})
	}
}

func TestVaultStoreIntegrationLive(t *testing.T) {
	address := os.Getenv("QUARSHELL_VAULT_ADDR")
	token := os.Getenv("QUARSHELL_VAULT_TOKEN")
	if address == "" || token == "" {
		t.Skip("QUARSHELL_VAULT_ADDR/QUARSHELL_VAULT_TOKEN are not set")
	}
	store, err := NewVaultStore(VaultConfig{
		Address: address, Token: token, Mount: "secret", PathPrefix: "quarshell-it",
		Key: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewVaultStore: %v", err)
	}
	secret := testSecret()
	secret.ID = domain.CredentialID("it-" + time.Now().Format("150405.000000000"))
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), secret.ID) })
	loaded, err := store.Get(context.Background(), secret.ID)
	if err != nil || string(loaded.Material) != "super-secret-token" {
		t.Fatalf("Get = %+v %v", loaded, err)
	}
	rotated, err := store.Rotate(context.Background(), secret.ID, []byte("rotated"), time.Now().Add(time.Hour))
	if err != nil || rotated.Revision != 2 {
		t.Fatalf("Rotate = %+v %v", rotated, err)
	}
	if err := store.Delete(context.Background(), secret.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
