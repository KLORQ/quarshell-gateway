package sandbox

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func TestExecAdmissionIsAtomicAndRetainedUntilCompletion(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	first, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	first.now = func() time.Time { return now }
	second.now = func() time.Time { return now }
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	const id, hash = "d9d0ab40-6110-4d53-9fa8-a2a13b52bc99", "request-digest"

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, service := range []*Service{first, second} {
		wg.Add(1)
		go func(service *Service) {
			defer wg.Done()
			results <- service.AdmitExecRequest(context.Background(), ref, id, hash)
		}(service)
	}
	wg.Wait()
	close(results)
	accepted, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case domain.CodeOf(err) == domain.CodeConflict:
			rejected++
		default:
			t.Fatalf("unexpected admission error: %v", err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent admissions accepted=%d rejected=%d, want one each", accepted, rejected)
	}

	// An unknown outcome stays fenced even beyond the terminal replay window.
	now = now.Add(48 * time.Hour)
	if err := first.AdmitExecRequest(context.Background(), ref, id, hash); domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("unfinished execution admission after 48h = %v, want conflict", err)
	}
	if err := first.CompleteExecRequest(context.Background(), ref, id); err != nil {
		t.Fatal(err)
	}
	if err := second.AdmitExecRequest(context.Background(), ref, id, hash); domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("completed execution admission before retention expiry = %v, want conflict", err)
	}
	now = now.Add(execAdmissionRetention)
	if err := second.AdmitExecRequest(context.Background(), ref, id, hash); err != nil {
		t.Fatalf("completed request ID was not released after 24h: %v", err)
	}
}

func TestExecAdmissionSurvivesSQLiteReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lifecycle.db")
	store, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	const id = "6b6f8519-f7d4-471e-925b-4ccf11d03c8b"
	if err := service.AdmitExecRequest(ctx, ref, id, "payload-hash"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetExecSessionID(ctx, ref, id, "payload-hash", "retained-terminal"); err != nil {
		t.Fatalf("persist retained terminal ID: %v", err)
	}
	if err := service.SetExecSessionCursor(ctx, ref, id, "payload-hash", 7); err != nil {
		t.Fatalf("persist retained output cursor: %v", err)
	}
	if err := service.SetExecSessionCursor(ctx, ref, id, "payload-hash", 4); err != nil {
		t.Fatalf("ignore stale output cursor: %v", err)
	}
	if _, found, err := service.ExecSessionID(ctx, ref, id, "different-payload"); domain.CodeOf(err) != domain.CodeConflict || found {
		t.Fatalf("mismatched payload lookup found=%v err=%v, want conflict", found, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	service, err = NewService(reopened)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AdmitExecRequest(ctx, ref, id, "payload-hash"); domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("duplicate after SQLite reopen = %v, want conflict", err)
	}
	sessionID, cursor, found, err := service.ExecSessionCheckpoint(ctx, ref, id, "payload-hash")
	if err != nil || !found || sessionID != "retained-terminal" || cursor != 7 {
		t.Fatalf("terminal session checkpoint after SQLite reopen = %q cursor=%d found=%v err=%v", sessionID, cursor, found, err)
	}
}

func TestCanonicalOutputReaderCursorSurvivesGatewayReopenAndCannotRegress(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reader.db")
	store, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "canonical"}
	cursor, err := service.PrepareOutputReader(ctx, ref, "reader-1", "canonical-hash")
	if err != nil || cursor != 0 {
		t.Fatalf("initial reader cursor=%d err=%v", cursor, err)
	}
	if err := service.SetOutputReaderCursor(ctx, ref, "reader-1", "canonical-hash", 12); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err = NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err = service.PrepareOutputReader(ctx, ref, "reader-1", "canonical-hash")
	if err != nil || cursor != 12 {
		t.Fatalf("reopened reader cursor=%d err=%v, want 12", cursor, err)
	}
	if err := service.SetOutputReaderCursor(ctx, ref, "reader-1", "canonical-hash", 6); err != nil {
		t.Fatal(err)
	}
	cursor, err = service.PrepareOutputReader(ctx, ref, "reader-1", "canonical-hash")
	if err != nil || cursor != 12 {
		t.Fatalf("reader cursor regressed to %d, err=%v", cursor, err)
	}
	if _, err := service.PrepareOutputReader(ctx, ref, "reader-1", "different-sandbox-hash"); domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("reader reuse with a different binding = %v, want conflict", err)
	}
}
