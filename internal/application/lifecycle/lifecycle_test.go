package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestCoordinatorIsIdempotent(t *testing.T) {
	store := NewMemoryStore()
	coordinator := &Coordinator{Store: store}
	calls := 0
	fn := func(tx WriteTx) ([]byte, error) {
		calls++
		if _, err := tx.Put("sandbox", "s1", 0, []byte(`{"state":"requested"}`)); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(OutboxMessage{ID: "m1", Topic: "sandbox.created"}); err != nil {
			return nil, err
		}
		return []byte(`{"id":"s1"}`), nil
	}
	first, replayed, err := coordinator.Execute(context.Background(), "op-1", "hash-1", fn)
	if err != nil || replayed || string(first) != `{"id":"s1"}` {
		t.Fatalf("first = %q replayed=%v err=%v", first, replayed, err)
	}
	second, replayed, err := coordinator.Execute(context.Background(), "op-1", "hash-1", fn)
	if err != nil || !replayed || string(second) != string(first) {
		t.Fatalf("second = %q replayed=%v err=%v", second, replayed, err)
	}
	if calls != 1 {
		t.Fatalf("callback calls = %d", calls)
	}
	if err := store.View(context.Background(), func(tx ReadTx) error {
		record, exists, err := tx.Get("sandbox", "s1")
		if err != nil || !exists || record.Version != 1 {
			t.Fatalf("record = %+v exists=%v err=%v", record, exists, err)
		}
		if tx.PendingOutbox() != 1 {
			t.Fatalf("pending outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestCoordinatorRejectsDifferentHash(t *testing.T) {
	store := NewMemoryStore()
	coordinator := &Coordinator{Store: store}
	fn := func(tx WriteTx) ([]byte, error) { return []byte("ok"), nil }
	if _, _, err := coordinator.Execute(context.Background(), "op-1", "hash-1", fn); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, _, err := coordinator.Execute(context.Background(), "op-1", "hash-2", fn); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("conflict = %v", err)
	}
}

func TestCoordinatorRollsBackOnError(t *testing.T) {
	store := NewMemoryStore()
	coordinator := &Coordinator{Store: store}
	_, _, err := coordinator.Execute(context.Background(), "op-1", "hash", func(tx WriteTx) ([]byte, error) {
		if _, err := tx.Put("sandbox", "s1", 0, []byte("v1")); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(OutboxMessage{ID: "m1", Topic: "t"}); err != nil {
			return nil, err
		}
		return nil, errors.New("boom")
	})
	if err == nil {
		t.Fatalf("operation succeeded")
	}
	if err := store.View(context.Background(), func(tx ReadTx) error {
		if _, exists, _ := tx.Get("sandbox", "s1"); exists {
			t.Fatalf("entity committed after rollback")
		}
		if tx.PendingOutbox() != 0 {
			t.Fatalf("outbox committed after rollback")
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Update(context.Background(), func(tx WriteTx) error {
		if _, err := tx.Put("sandbox", "s1", 0, []byte("v1")); err != nil {
			return err
		}
		if _, err := tx.Put("sandbox", "s1", 0, []byte("v2")); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("create conflict = %v", err)
		}
		record, err := tx.Put("sandbox", "s1", 1, []byte("v2"))
		if err != nil || record.Version != 2 {
			t.Fatalf("update = %+v err=%v", record, err)
		}
		if _, err := tx.Put("sandbox", "s1", 1, []byte("v3")); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale update = %v", err)
		}
		if err := tx.Delete("sandbox", "s1", 1); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale delete = %v", err)
		}
		return tx.Delete("sandbox", "s1", 2)
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestOutboxLeasePreventsDoubleClaim(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	store := NewMemoryStoreWithClock(func() time.Time { return base })
	if err := store.Update(context.Background(), func(tx WriteTx) error {
		return tx.Enqueue(OutboxMessage{ID: "m1", Topic: "t"})
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	now := base
	first, err := store.ClaimOutbox(context.Background(), now, time.Minute, 10)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim = %v, %v", first, err)
	}
	second, err := store.ClaimOutbox(context.Background(), now.Add(30*time.Second), time.Minute, 10)
	if err != nil || len(second) != 0 {
		t.Fatalf("second claim = %v, %v", second, err)
	}
	third, err := store.ClaimOutbox(context.Background(), now.Add(2*time.Minute), time.Minute, 10)
	if err != nil || len(third) != 1 {
		t.Fatalf("expired lease claim = %v, %v", third, err)
	}
}

func TestReconcilerRetriesThenAcknowledges(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	store := NewMemoryStoreWithClock(func() time.Time { return base })
	if err := store.Update(context.Background(), func(tx WriteTx) error {
		if err := tx.Enqueue(OutboxMessage{ID: "m1", Topic: "t"}); err != nil {
			return err
		}
		return tx.Enqueue(OutboxMessage{ID: "m2", Topic: "t"})
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	attempts := 0
	reconciler := &Reconciler{
		Store: store,
		Handler: func(_ context.Context, message OutboxMessage) error {
			if message.ID == "m1" && attempts == 0 {
				attempts++
				return errors.New("temporary")
			}
			return nil
		},
		Backoff: func(int) time.Duration { return 0 },
		Now:     func() time.Time { return base },
	}
	result, err := reconciler.RunOnce(context.Background())
	if err != nil || result.Claimed != 2 || result.Acknowledged != 1 || result.Retried != 1 {
		t.Fatalf("first pass = %+v err=%v", result, err)
	}
	reconciler.Now = func() time.Time { return time.Unix(1_700_000_001, 0) }
	result, err = reconciler.RunOnce(context.Background())
	if err != nil || result.Acknowledged != 1 {
		t.Fatalf("second pass = %+v err=%v", result, err)
	}
	if err := store.View(context.Background(), func(tx ReadTx) error {
		if tx.PendingOutbox() != 0 {
			t.Fatalf("pending = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestReconcilerDeadLetters(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	store := NewMemoryStoreWithClock(func() time.Time { return base })
	if err := store.Update(context.Background(), func(tx WriteTx) error {
		return tx.Enqueue(OutboxMessage{ID: "m1", Topic: "t"})
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	reconciler := &Reconciler{
		Store:       store,
		MaxAttempts: 2,
		Backoff:     func(int) time.Duration { return 0 },
		Now:         func() time.Time { return base },
		Handler:     func(context.Context, OutboxMessage) error { return errors.New("permanent") },
	}
	if _, err := reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	reconciler.Now = func() time.Time { return time.Unix(1_700_000_001, 0) }
	result, err := reconciler.RunOnce(context.Background())
	if err != nil || result.Dead != 1 {
		t.Fatalf("second pass = %+v err=%v", result, err)
	}
	if err := store.View(context.Background(), func(tx ReadTx) error {
		if tx.PendingOutbox() != 0 || tx.DeadOutbox() != 1 {
			t.Fatalf("pending=%d dead=%d", tx.PendingOutbox(), tx.DeadOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), time.Unix(1_700_000_002, 0), time.Minute, 10)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("dead message claimed = %v, %v", claimed, err)
	}
}
