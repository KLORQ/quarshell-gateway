package settings

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func testSettings(t *testing.T) (*Service, *lifecycle.MemoryStore) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func TestSettingsLifecycle(t *testing.T) {
	service, store := testSettings(t)
	first, replayed, err := service.Set(context.Background(), "ws", "log_level", []byte("info"), 0, "set-1")
	if err != nil || replayed || first.Version != 1 {
		t.Fatalf("Set = %+v replayed=%v err=%v", first, replayed, err)
	}
	replay, replayed, err := service.Set(context.Background(), "ws", "log_level", []byte("info"), 0, "set-1")
	if err != nil || !replayed || replay.Version != 1 {
		t.Fatalf("replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	updated, _, err := service.Set(context.Background(), "ws", "log_level", []byte("debug"), 1, "set-2")
	if err != nil || updated.Version != 2 || string(updated.Value) != "debug" {
		t.Fatalf("update = %+v %v", updated, err)
	}
	if _, _, err := service.Set(context.Background(), "ws", "log_level", []byte("trace"), 1, "set-3"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale update = %v", err)
	}
	if _, err := service.Get(context.Background(), "ws", "log_level"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	list, err := service.List(context.Background(), "ws")
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v %v", list, err)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 2 {
			t.Fatalf("outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	if err := service.Delete(context.Background(), "ws", "log_level", "del-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := service.Delete(context.Background(), "ws", "log_level", "del-1"); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
	if _, err := service.Get(context.Background(), "ws", "log_level"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestSettingsValidation(t *testing.T) {
	service, _ := testSettings(t)
	if _, _, err := service.Set(context.Background(), "", "key", nil, 0, ""); err == nil {
		t.Fatalf("empty workspace accepted")
	}
	if _, _, err := service.Set(context.Background(), "ws", "a/b", nil, 0, ""); err == nil {
		t.Fatalf("slash key accepted")
	}
}
