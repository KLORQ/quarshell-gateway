package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func testProviderService(t *testing.T) (*Service, *lifecycle.MemoryStore) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func sandboxRef() domain.SandboxRef {
	return domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
}

func TestProviderBindAckAndRevision(t *testing.T) {
	service, store := testProviderService(t)
	first, replayed, err := service.Bind(context.Background(), BindRequest{
		Sandbox: sandboxRef(), Provider: "github", Revision: 1, Config: []byte(`{"token":"ref"}`), IdempotencyKey: "bind-1",
	})
	if err != nil || replayed || first.Readiness != ReadinessPending {
		t.Fatalf("Bind = %+v replayed=%v err=%v", first, replayed, err)
	}
	replay, replayed, err := service.Bind(context.Background(), BindRequest{
		Sandbox: sandboxRef(), Provider: "github", Revision: 1, Config: []byte(`{"token":"ref"}`), IdempotencyKey: "bind-1",
	})
	if err != nil || !replayed || replay.Revision != 1 {
		t.Fatalf("replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	ready, err := service.Ack(context.Background(), sandboxRef(), "github", 1)
	if err != nil || ready.Readiness != ReadinessReady || ready.AckedAt == nil {
		t.Fatalf("Ack = %+v %v", ready, err)
	}
	if _, err := service.Ack(context.Background(), sandboxRef(), "github", 2); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale Ack = %v", err)
	}
	updated, _, err := service.Bind(context.Background(), BindRequest{
		Sandbox: sandboxRef(), Provider: "github", Revision: 2, IdempotencyKey: "bind-2",
	})
	if err != nil || updated.Readiness != ReadinessPending || updated.AckedAt != nil {
		t.Fatalf("revision update = %+v %v", updated, err)
	}
	if _, _, err := service.Bind(context.Background(), BindRequest{
		Sandbox: sandboxRef(), Provider: "github", Revision: 1, IdempotencyKey: "bind-3",
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale Bind = %v", err)
	}
	list, err := service.List(context.Background(), sandboxRef())
	if err != nil || len(list) != 1 || list[0].Revision != 2 {
		t.Fatalf("List = %+v %v", list, err)
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

func TestProviderFailUnbindAndValidation(t *testing.T) {
	service, _ := testProviderService(t)
	if _, _, err := service.Bind(context.Background(), BindRequest{Sandbox: sandboxRef(), Provider: "p", Revision: 1}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	failed, err := service.Fail(context.Background(), sandboxRef(), "p", 1, "install failed")
	if err != nil || failed.Readiness != ReadinessFailed || failed.Error != "install failed" {
		t.Fatalf("Fail = %+v %v", failed, err)
	}
	if err := service.Unbind(context.Background(), sandboxRef(), "p", "unbind-1"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if _, err := service.Get(context.Background(), sandboxRef(), "p"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after unbind = %v", err)
	}
	if err := service.Unbind(context.Background(), sandboxRef(), "p", "unbind-1"); err != nil {
		t.Fatalf("idempotent Unbind: %v", err)
	}
	if _, _, err := service.Bind(context.Background(), BindRequest{Sandbox: sandboxRef(), Provider: "p", Revision: 1, Config: []byte("{")}); err == nil {
		t.Fatalf("invalid config accepted")
	}
}

func TestProviderReplayAfterRestart(t *testing.T) {
	service, store := testProviderService(t)
	if _, _, err := service.Bind(context.Background(), BindRequest{Sandbox: sandboxRef(), Provider: "p", Revision: 1, IdempotencyKey: "bind"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	restarted, _ := NewService(store)
	if _, replayed, err := restarted.Bind(context.Background(), BindRequest{Sandbox: sandboxRef(), Provider: "p", Revision: 1, IdempotencyKey: "bind"}); err != nil || !replayed {
		t.Fatalf("replay = %v %v", replayed, err)
	}
	binding, err := restarted.Get(context.Background(), sandboxRef(), "p")
	if err != nil || binding.Revision != 1 {
		t.Fatalf("Get = %+v %v", binding, err)
	}
}
