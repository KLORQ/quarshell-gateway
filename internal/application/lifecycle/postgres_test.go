package lifecycle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func postgresTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	url := os.Getenv("QUARSHELL_POSTGRES_URL")
	if url == "" {
		t.Skip("QUARSHELL_POSTGRES_URL is not set")
	}
	store, err := NewPostgresStore(context.Background(), url)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	cleanup := func() {
		_, _ = store.db.ExecContext(context.Background(), "TRUNCATE lifecycle_records, lifecycle_operations, lifecycle_outbox")
	}
	cleanup()
	t.Cleanup(func() { cleanup(); _ = store.Close() })
	return store
}

func TestPostgresStoreIntegration(t *testing.T) {
	store := postgresTestStore(t)
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
		t.Fatalf("Execute = %q replayed=%v err=%v cause=%v", first, replayed, err, errors.Unwrap(err))
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
	reopened, err := NewPostgresStore(ctx, os.Getenv("QUARSHELL_POSTGRES_URL"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if record, exists, err := reopenedGet(ctx, reopened, "sandbox", "s1"); err != nil || !exists || string(record.Payload) != "v2" {
		t.Fatalf("reopened = %+v exists=%v err=%v", record, exists, err)
	}
	_ = store
}

func reopenedGet(ctx context.Context, store *PostgresStore, kind, id string) (Record, bool, error) {
	var record Record
	var exists bool
	err := store.View(ctx, func(tx ReadTx) error {
		loaded, ok, err := tx.Get(kind, id)
		record = loaded
		exists = ok
		return err
	})
	return record, exists, err
}

func TestPostgresStoreValidation(t *testing.T) {
	if _, err := NewPostgresStore(context.Background(), ""); err == nil {
		t.Fatalf("empty URL accepted")
	}
}
