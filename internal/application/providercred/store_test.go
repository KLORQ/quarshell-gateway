package providercred

import (
	"bytes"
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func TestStoreEncryptsAndRoundTrips(t *testing.T) {
	backing := lifecycle.NewMemoryStore()
	store, err := NewStore(backing, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Put(ctx, Secret{Workspace: "ws", Provider: "p", Key: "token", Value: "super-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := backing.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(recordKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			if bytes.Contains(record.Payload, []byte("super-secret")) {
				t.Fatal("plaintext credential found at rest")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "ws", "p", "token")
	if err != nil || got.Value != "super-secret" {
		t.Fatalf("Get = %+v err=%v", got, err)
	}
	list, err := store.List(ctx, "ws", "p")
	if err != nil || len(list) != 1 || list[0].Key != "token" {
		t.Fatalf("List = %+v err=%v", list, err)
	}
	if err := store.Delete(ctx, "ws", "p", "token"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "ws", "p", "token"); err == nil {
		t.Fatal("deleted credential still readable")
	}
}
