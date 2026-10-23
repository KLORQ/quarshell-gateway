package secrets

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-credentials"
)

func testSecrets(t *testing.T) (*Service, *credentials.MemoryStore) {
	t.Helper()
	store, err := credentials.NewMemoryStore([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	broker, err := credentials.NewBroker(store, nil)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	service, err := NewService(store, broker)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func TestSecretsLifecycle(t *testing.T) {
	service, _ := testSecrets(t)
	endpoint := credentials.EndpointBinding{Scheme: "https", Host: "api.example.com", Port: 443, Method: "GET"}
	metadata, err := service.Create(context.Background(), "cred", "api", []byte("token"), endpoint, time.Now().Add(time.Hour))
	if err != nil || metadata.Revision != 1 {
		t.Fatalf("Create = %+v %v", metadata, err)
	}
	loaded, err := service.Get(context.Background(), "cred")
	if err != nil || loaded.Provider != "api" {
		t.Fatalf("Get = %+v %v", loaded, err)
	}
	rotated, err := service.Rotate(context.Background(), "cred", []byte("new-token"), time.Now().Add(time.Hour))
	if err != nil || rotated.Revision != 2 {
		t.Fatalf("Rotate = %+v %v", rotated, err)
	}
	handle, info, err := service.Issue(context.Background(), credentials.IssueRequest{
		Credential: "cred", Sandbox: domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, Endpoint: endpoint,
	})
	if err != nil || info.Provider != "api" {
		t.Fatalf("Issue = %q %+v %v", handle, info, err)
	}
	if err := service.Revoke(context.Background(), handle); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := service.Delete(context.Background(), "cred"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := service.Get(context.Background(), "cred"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestSecretsValidation(t *testing.T) {
	service, _ := testSecrets(t)
	if _, err := service.Create(context.Background(), "cred", "api", nil, credentials.EndpointBinding{}, time.Now()); err == nil {
		t.Fatalf("empty material accepted")
	}
	if err := ValidateMaterialLen(nil, 10); err == nil {
		t.Fatalf("empty material guard accepted")
	}
	if err := ValidateMaterialLen([]byte("123456"), 3); err == nil {
		t.Fatalf("oversized material guard accepted")
	}
}
