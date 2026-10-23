package template

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func testTemplates(t *testing.T) (*Service, *lifecycle.MemoryStore) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func TestTemplateLifecycle(t *testing.T) {
	service, store := testTemplates(t)
	created, replayed, err := service.Create(context.Background(), "ws", "basic", "Basic", []byte(`{"image":"ubuntu"}`), "create")
	if err != nil || replayed || created.Revision != 1 {
		t.Fatalf("Create = %+v replayed=%v err=%v", created, replayed, err)
	}
	replay, replayed, err := service.Create(context.Background(), "ws", "basic", "Basic", []byte(`{"image":"ubuntu"}`), "create")
	if err != nil || !replayed || replay.Revision != 1 {
		t.Fatalf("replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	updated, err := service.Update(context.Background(), "ws", "basic", "Basic", []byte(`{"image":"alpine"}`), 1, "update")
	if err != nil || updated.Revision != 2 || string(updated.Spec) != `{"image":"alpine"}` {
		t.Fatalf("Update = %+v %v", updated, err)
	}
	if _, err := service.Update(context.Background(), "ws", "basic", "Basic", []byte(`{}`), 1, "stale"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale update = %v", err)
	}
	list, err := service.List(context.Background(), "ws")
	if err != nil || len(list) != 1 || list[0].Revision != 2 {
		t.Fatalf("List = %+v %v", list, err)
	}
	if err := deleteTemplate(service, "del-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := deleteTemplate(service, "del-1"); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
	if _, err := service.Get(context.Background(), "ws", "basic"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 3 {
			t.Fatalf("outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func deleteTemplate(service *Service, key domain.OperationID) error {
	return service.Delete(context.Background(), "ws", "basic", key)
}

func TestTemplateValidation(t *testing.T) {
	service, _ := testTemplates(t)
	if _, _, err := service.Create(context.Background(), "", "id", "name", nil, ""); err == nil {
		t.Fatalf("empty workspace accepted")
	}
	if _, _, err := service.Create(context.Background(), "ws", "id", "name", []byte("{"), ""); err == nil {
		t.Fatalf("invalid JSON accepted")
	}
}
