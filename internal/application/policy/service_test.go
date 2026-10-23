package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-prover"
)

var validPolicy = []byte("version: 1\n")

func testPolicyService(t *testing.T) (*Service, *lifecycle.MemoryStore) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func sandboxScope() Scope {
	return Scope{Workspace: "ws", Sandbox: "sb"}
}

func TestPolicyDraftApproveAndSupersede(t *testing.T) {
	service, store := testPolicyService(t)
	first, replayed, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: validPolicy, Author: "alice", IdempotencyKey: "draft-1",
	})
	if err != nil || replayed || first.Number != 1 || first.Status != StatusDraft {
		t.Fatalf("draft = %+v replayed=%v err=%v", first, replayed, err)
	}
	replay, replayed, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: validPolicy, Author: "alice", IdempotencyKey: "draft-1",
	})
	if err != nil || !replayed || replay.ID != first.ID {
		t.Fatalf("draft replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	active, err := service.Approve(context.Background(), sandboxScope(), first.ID, "bob", "approve-1")
	if err != nil || active.Status != StatusActive {
		t.Fatalf("approve = %+v err=%v", active, err)
	}
	current, ok, err := service.Active(context.Background(), sandboxScope())
	if err != nil || !ok || current.ID != first.ID {
		t.Fatalf("active = %+v ok=%v err=%v", current, ok, err)
	}
	second, _, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: validPolicy, Author: "alice", IdempotencyKey: "draft-2",
	})
	if err != nil || second.Number != 2 {
		t.Fatalf("second draft = %+v err=%v", second, err)
	}
	if _, err := service.Approve(context.Background(), sandboxScope(), second.ID, "bob", "approve-2"); err != nil {
		t.Fatalf("second approve: %v", err)
	}
	history, err := service.List(context.Background(), sandboxScope())
	if err != nil || len(history) != 2 {
		t.Fatalf("history = %+v err=%v", history, err)
	}
	if history[0].ID != second.ID || history[0].Status != StatusActive || history[1].Status != StatusSuperseded {
		t.Fatalf("history = %+v", history)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 4 {
			t.Fatalf("outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestPolicyRejectAndInvalidSource(t *testing.T) {
	service, _ := testPolicyService(t)
	draft, _, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: validPolicy, Author: "alice", IdempotencyKey: "draft",
	})
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	rejected, err := service.Reject(context.Background(), sandboxScope(), draft.ID, "bob", "unsafe")
	if err != nil || rejected.Status != StatusRejected {
		t.Fatalf("Reject = %+v %v", rejected, err)
	}
	if _, _, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: []byte("version: 1\nunknown: true\n"), Author: "alice",
	}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("invalid source = %v", err)
	}
}

func TestPolicyActiveScopeFallback(t *testing.T) {
	service, _ := testPolicyService(t)
	if _, ok, err := service.Active(context.Background(), sandboxScope()); err != nil || ok {
		t.Fatalf("empty active = %v %v", ok, err)
	}
	global := Scope{Workspace: "ws"}
	draft, _, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: global, Source: validPolicy, Author: "alice", IdempotencyKey: "global",
	})
	if err != nil {
		t.Fatalf("global draft: %v", err)
	}
	if _, err := service.Approve(context.Background(), global, draft.ID, "bob", "approve"); err != nil {
		t.Fatalf("global approve: %v", err)
	}
	active, ok, err := service.Active(context.Background(), global)
	if err != nil || !ok || active.ID != draft.ID {
		t.Fatalf("global active = %+v %v %v", active, ok, err)
	}
	if _, ok, err := service.Active(context.Background(), sandboxScope()); err != nil || ok {
		t.Fatalf("sandbox active after global = %v %v", ok, err)
	}
}

func TestPolicyAnalyzeAndObserve(t *testing.T) {
	service, _ := testPolicyService(t)
	activeSource := []byte(`version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-only
`)
	activeDraft, _, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: activeSource, Author: "alice", IdempotencyKey: "active",
	})
	if err != nil {
		t.Fatalf("active draft: %v", err)
	}
	if _, err := service.Approve(context.Background(), sandboxScope(), activeDraft.ID, "bob", "approve-active"); err != nil {
		t.Fatalf("approve active: %v", err)
	}
	broadSource := []byte(`version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: full
`)
	broadDraft, _, err := service.CreateDraft(context.Background(), DraftRequest{
		Scope: sandboxScope(), Source: broadSource, Author: "alice", IdempotencyKey: "broad",
	})
	if err != nil {
		t.Fatalf("broad draft: %v", err)
	}
	analysis, err := service.Analyze(context.Background(), sandboxScope(), broadDraft.ID)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if analysis.Containment.Relation != prover.Exceeds || analysis.Risk.Score == 0 {
		t.Fatalf("analysis = %+v", analysis)
	}
	observed, err := service.Observe(context.Background(), sandboxScope(), activeDraft.ID, 2)
	if err != nil || observed.ObservedGeneration != 2 || observed.ObservedAt == nil {
		t.Fatalf("Observe = %+v %v", observed, err)
	}
	if _, err := service.Observe(context.Background(), sandboxScope(), activeDraft.ID, 1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale observe = %v", err)
	}
	if _, err := service.Observe(context.Background(), sandboxScope(), broadDraft.ID, 3); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("draft observe = %v", err)
	}
}
