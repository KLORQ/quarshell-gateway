package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func testQuota(t *testing.T) (*Service, *lifecycle.MemoryStore) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func TestQuotaSetCheckAndVersion(t *testing.T) {
	service, store := testQuota(t)
	if _, found, err := service.Get(context.Background(), "ws"); err != nil || found {
		t.Fatalf("empty quota = %v %v", found, err)
	}
	if err := service.Check(context.Background(), "ws", Limits{CPU: 1000}); err != nil {
		t.Fatalf("no quota should allow: %v", err)
	}
	created, err := service.Set(context.Background(), "ws", Limits{CPU: 4, MemoryBytes: 1024, Sandboxes: 2}, 0)
	if err != nil || created.Version != 1 {
		t.Fatalf("Set = %+v %v", created, err)
	}
	if _, err := service.Set(context.Background(), "ws", Limits{CPU: 8}, 0); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Set = %v", err)
	}
	if err := service.Check(context.Background(), "ws", Limits{CPU: 4, MemoryBytes: 1024, Sandboxes: 2}); err != nil {
		t.Fatalf("at limit = %v", err)
	}
	if err := service.Check(context.Background(), "ws", Limits{CPU: 5}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("exceeded = %v", err)
	}
	updated, err := service.Set(context.Background(), "ws", Limits{CPU: 8}, 1)
	if err != nil || updated.Version != 2 {
		t.Fatalf("update = %+v %v", updated, err)
	}
	if _, err := service.Set(context.Background(), "ws", Limits{CPU: 16}, 1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale update = %v", err)
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

func TestQuotaValidation(t *testing.T) {
	service, _ := testQuota(t)
	if _, err := service.Set(context.Background(), "", Limits{}, 0); err == nil {
		t.Fatalf("empty workspace accepted")
	}
	if _, err := service.Set(context.Background(), "ws", Limits{CPU: -1}, 0); err == nil {
		t.Fatalf("negative limit accepted")
	}
}
