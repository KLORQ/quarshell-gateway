package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestLeaseFencingAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewLeaseRegistry(func() time.Time { return now })
	first, err := registry.Acquire(context.Background(), "gateway", "owner-a", time.Minute)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if first.Token == 0 {
		t.Fatalf("token = 0")
	}
	if _, err := registry.Acquire(context.Background(), "gateway", "owner-b", time.Minute); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second owner = %v", err)
	}
	renewed, err := registry.Renew(context.Background(), first, 2*time.Minute)
	if err != nil || !renewed.ExpiresAt.After(first.ExpiresAt) {
		t.Fatalf("Renew = %+v %v", renewed, err)
	}
	if err := registry.Validate(renewed); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	now = now.Add(3 * time.Minute)
	if err := registry.Validate(renewed); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expired lease = %v", err)
	}
	second, err := registry.Acquire(context.Background(), "gateway", "owner-b", time.Minute)
	if err != nil {
		t.Fatalf("reacquire: %v", err)
	}
	if second.Token <= first.Token {
		t.Fatalf("fencing token did not increase: %d <= %d", second.Token, first.Token)
	}
	if err := registry.Validate(first); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale owner = %v", err)
	}
	if err := registry.Release(context.Background(), first); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale release = %v", err)
	}
	if err := registry.Release(context.Background(), second); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := registry.Current("gateway"); ok {
		t.Fatalf("released lease still current")
	}
	if _, err := registry.Acquire(context.Background(), "gateway", "owner-c", time.Minute); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}

func TestLeaseValidationAndCancellation(t *testing.T) {
	registry := NewLeaseRegistry(nil)
	if _, err := registry.Acquire(context.Background(), "", "owner", time.Minute); err == nil {
		t.Fatalf("empty key accepted")
	}
	if _, err := registry.Acquire(context.Background(), "key", "owner", 0); err == nil {
		t.Fatalf("zero ttl accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Acquire(ctx, "key", "owner", time.Minute); !errors.Is(err, domain.ErrCanceled) {
		t.Fatalf("canceled acquire = %v", err)
	}
}

func TestStoreList(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Update(context.Background(), func(tx WriteTx) error {
		if _, err := tx.Put("widget", "b", 0, []byte("2")); err != nil {
			return err
		}
		if _, err := tx.Put("widget", "a", 0, []byte("1")); err != nil {
			return err
		}
		_, err := tx.Put("other", "c", 0, []byte("3"))
		return err
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := store.View(context.Background(), func(tx ReadTx) error {
		records, err := tx.List("widget")
		if err != nil || len(records) != 2 {
			t.Fatalf("List = %v %v", records, err)
		}
		if records[0].ID != "a" || records[1].ID != "b" {
			t.Fatalf("order = %v", records)
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}
