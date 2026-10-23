package lifecycle

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestSQLiteStoreIntegration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.db")
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	coordinator := &Coordinator{Store: store}
	fn := func(tx WriteTx) ([]byte, error) {
		if _, err := tx.Put("sandbox", "s1", 0, []byte("v1")); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(OutboxMessage{ID: "m1", Topic: "created"}); err != nil {
			return nil, err
		}
		return []byte("result"), nil
	}
	first, replayed, err := coordinator.Execute(ctx, "op-1", "hash", fn)
	if err != nil || replayed || string(first) != "result" {
		t.Fatalf("Execute = %q replayed=%v err=%v", first, replayed, err)
	}
	second, replayed, err := coordinator.Execute(ctx, "op-1", "hash", fn)
	if err != nil || !replayed || string(second) != "result" {
		t.Fatalf("replay = %q replayed=%v err=%v", second, replayed, err)
	}
	if err := store.View(ctx, func(tx ReadTx) error {
		record, exists, err := tx.Get("sandbox", "s1")
		if err != nil || !exists || record.Version != 1 {
			t.Fatalf("record = %+v exists=%v err=%v", record, exists, err)
		}
		if tx.PendingOutbox() != 1 {
			t.Fatalf("pending = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	if err := store.Update(ctx, func(tx WriteTx) error {
		if _, err := tx.Put("sandbox", "s1", 1, []byte("v2")); err != nil {
			return err
		}
		if _, err := tx.Put("sandbox", "s1", 1, []byte("v3")); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale update = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	now := time.Now().Add(time.Second)
	claimed, err := store.ClaimOutbox(ctx, now, time.Minute, 10)
	if err != nil || len(claimed) != 1 || claimed[0].ID != "m1" {
		t.Fatalf("Claim = %+v %v", claimed, err)
	}
	if claimed, err := store.ClaimOutbox(ctx, now, time.Minute, 10); err != nil || len(claimed) != 0 {
		t.Fatalf("double claim = %+v %v", claimed, err)
	}
	if err := store.RetryOutbox(ctx, "m1", now.Add(-time.Second), "temporary", false); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	claimed, err = store.ClaimOutbox(ctx, now, time.Minute, 10)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("retry claim = %+v %v", claimed, err)
	}
	if err := store.RetryOutbox(ctx, "m1", now, "permanent", true); err != nil {
		t.Fatalf("dead letter: %v", err)
	}
	if claimed, err := store.ClaimOutbox(ctx, now.Add(time.Hour), time.Minute, 10); err != nil || len(claimed) != 0 {
		t.Fatalf("dead claimed = %+v %v", claimed, err)
	}
	if err := store.View(ctx, func(tx ReadTx) error {
		if tx.DeadOutbox() != 1 {
			t.Fatalf("dead = %d", tx.DeadOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if err := reopened.View(ctx, func(tx ReadTx) error {
		record, exists, err := tx.Get("sandbox", "s1")
		if err != nil || !exists || string(record.Payload) != "v2" {
			t.Fatalf("reopened = %+v exists=%v err=%v", record, exists, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("View reopened: %v", err)
	}
}

func TestSQLiteValidation(t *testing.T) {
	if _, err := NewSQLiteStore(context.Background(), ""); err == nil {
		t.Fatalf("empty path accepted")
	}
}
