package endpoint

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func sandbox() domain.SandboxRef {
	return domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
}

func TestServiceRegistryLifecycle(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	registry, err := NewServiceRegistry(store)
	if err != nil {
		t.Fatalf("NewServiceRegistry: %v", err)
	}
	service, replayed, err := registry.Expose(context.Background(), sandbox(), "web", "Web", "https://sandbox.example/", 8080, "http", "strip", "expose")
	if err != nil || replayed || service.Name != "Web" {
		t.Fatalf("Expose = %+v replayed=%v err=%v", service, replayed, err)
	}
	replay, replayed, err := registry.Expose(context.Background(), sandbox(), "web", "Web", "https://sandbox.example/", 8080, "http", "strip", "expose")
	if err != nil || !replayed {
		t.Fatalf("replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	list, err := registry.List(context.Background(), sandbox())
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v %v", list, err)
	}
	if err := registry.Delete(context.Background(), sandbox(), "web", "delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := registry.Get(context.Background(), sandbox(), "web"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 2 {
			t.Fatalf("outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestServiceRegistryValidation(t *testing.T) {
	registry, _ := NewServiceRegistry(lifecycle.NewMemoryStore())
	if _, _, err := registry.Expose(context.Background(), sandbox(), "", "name", "https://x", 80, "http", "", ""); err == nil {
		t.Fatalf("empty id accepted")
	}
	if _, _, err := registry.Expose(context.Background(), sandbox(), "id", "name", "ftp://x", 80, "http", "", ""); err == nil {
		t.Fatalf("invalid URL accepted")
	}
	if _, _, err := registry.Expose(context.Background(), sandbox(), "id", "name", "https://x", 80, "http", "bogus", ""); err == nil {
		t.Fatalf("invalid auth mode accepted")
	}
}

func TestForwardRegistryLifecycle(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	registry, err := NewForwardRegistry(store)
	if err != nil {
		t.Fatalf("NewForwardRegistry: %v", err)
	}
	forward, replayed, err := registry.Create(context.Background(), sandbox(), "db", 15432, "db.internal", 5432, "tcp", "create")
	if err != nil || replayed || forward.LocalPort != 15432 {
		t.Fatalf("Create = %+v replayed=%v err=%v", forward, replayed, err)
	}
	replay, replayed, err := registry.Create(context.Background(), sandbox(), "db", 15432, "db.internal", 5432, "tcp", "create")
	if err != nil || !replayed {
		t.Fatalf("replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	list, err := registry.List(context.Background(), sandbox())
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v %v", list, err)
	}
	if err := registry.Delete(context.Background(), sandbox(), "db", "delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := registry.Get(context.Background(), sandbox(), "db"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	if _, _, err := registry.Create(context.Background(), sandbox(), "bad", 0, "host", 1, "tcp", ""); err == nil {
		t.Fatalf("zero local port accepted")
	}
}
