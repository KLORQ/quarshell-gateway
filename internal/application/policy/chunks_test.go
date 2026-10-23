package policy

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func TestPolicyChunksLifecycle(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, err := NewChunkService(store, nil)
	if err != nil {
		t.Fatalf("NewChunkService: %v", err)
	}
	ctx := context.Background()
	scope := Scope{Workspace: "ws", Sandbox: "sb"}
	empty, err := service.GetDraft(ctx, scope)
	if err != nil || len(empty.Chunks) != 0 {
		t.Fatalf("empty draft = %+v err=%v", empty, err)
	}
	if _, err := service.Edit(ctx, scope, "alpha", 1, []byte("allow /a"), "alice", "edit-a"); err != nil {
		t.Fatalf("Edit alpha: %v", err)
	}
	if _, err := service.Edit(ctx, scope, "beta", 2, []byte("allow /b"), "alice", "edit-b"); err != nil {
		t.Fatalf("Edit beta: %v", err)
	}
	if _, err := service.Edit(ctx, scope, "alpha", 0, []byte("allow /a2"), "alice", "edit-a2"); err != nil {
		t.Fatalf("Edit alpha again: %v", err)
	}
	draft, err := service.GetDraft(ctx, scope)
	if err != nil || len(draft.Chunks) != 2 || string(draft.Source()) != "allow /a2\nallow /b" {
		t.Fatalf("draft = %+v source=%q err=%v", draft, draft.Source(), err)
	}
	approved, err := service.ApproveAll(ctx, scope, "bob")
	if err != nil || len(approved.Chunks) != 2 {
		t.Fatalf("ApproveAll = %+v err=%v", approved, err)
	}
	for _, chunk := range approved.Chunks {
		if chunk.Status != ChunkStatusApproved {
			t.Fatalf("chunk %s status = %s", chunk.ID, chunk.Status)
		}
	}
	restored, err := service.Undo(ctx, scope, "alpha")
	if err != nil || string(restored.Source) != "allow /a2" || restored.Status != ChunkStatusDraft {
		t.Fatalf("Undo approval = %+v err=%v", restored, err)
	}
	restored, err = service.Undo(ctx, scope, "alpha")
	if err != nil || string(restored.Source) != "allow /a" || restored.Status != ChunkStatusDraft {
		t.Fatalf("Undo edit = %+v err=%v", restored, err)
	}
	if _, err := service.Reject(ctx, scope, "beta", "bob", "too broad"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if _, err := service.Reject(ctx, scope, "beta", "bob", ""); err == nil {
		t.Fatalf("empty rejection reason accepted")
	}
	revisions, history, err := service.History(ctx, scope)
	if err != nil || len(revisions) != 0 || len(history) == 0 {
		t.Fatalf("History = %d %d err=%v", len(revisions), len(history), err)
	}
	if err := service.Clear(ctx, scope, "clear-1"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	cleared, err := service.GetDraft(ctx, scope)
	if err != nil || len(cleared.Chunks) != 0 {
		t.Fatalf("cleared draft = %+v err=%v", cleared, err)
	}
	if _, err := service.GetDraft(ctx, Scope{Workspace: ""}); err == nil {
		t.Fatalf("invalid scope accepted")
	}
}
