package sandboxlogs

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func TestLogWindowPersistsAcrossStoreRestartAndRetainsNewestLines(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gateway.db")
	store, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	batch := make([]Line, 2001)
	for i := range batch {
		batch[i] = Line{SandboxID: "sandbox-a", EventTime: time.Unix(int64(i+1), 0).UTC(), Level: "INFO", Source: "sandbox", Message: fmt.Sprintf("event-%04d", i)}
	}
	if _, err := service.Append(ctx, "sandbox-a", batch); err != nil {
		t.Fatal(err)
	}
	platformEvent, created, err := service.AppendPlatformEvent(ctx, PlatformEvent{
		SandboxID: "sandbox-a", EventTime: time.Unix(3000, 0), Source: "vm", Type: "sandbox_state",
		Reason: "running", DedupKey: "vm-state:running:3000",
	})
	if err != nil || !created || platformEvent.Sequence != 2002 {
		t.Fatalf("AppendPlatformEvent()=(%+v, %v, %v)", platformEvent, created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := New(reopened)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := restored.List(ctx, "sandbox-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != maxLines || lines[0].Message != "event-0001" || lines[0].Sequence != 2 || lines[len(lines)-1].Message != "event-2000" || lines[len(lines)-1].Sequence != 2001 {
		t.Fatalf("retained window count=%d first=%q last=%q", len(lines), lines[0].Message, lines[len(lines)-1].Message)
	}
	events, err := restored.ListPlatformEvents(ctx, "sandbox-a")
	if err != nil || len(events) != 1 || events[0].Sequence != 2002 || events[0].Reason != "running" {
		t.Fatalf("retained platform events=(%+v, %v)", events, err)
	}
	latest, logsTrimmed, eventsTrimmed, err := restored.CursorState(ctx, "sandbox-a")
	if err != nil || latest != 2002 || logsTrimmed != 1 || eventsTrimmed != 0 {
		t.Fatalf("cursor state=(%d, %d, %d, %v)", latest, logsTrimmed, eventsTrimmed, err)
	}
}

func TestCursorEpochPersistsAcrossStoreRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gateway.db")
	store, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CursorEpoch(ctx)
	if err != nil || len(first) != 32 {
		t.Fatalf("first CursorEpoch()=(%q, %v)", first, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := lifecycle.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := New(reopened)
	if err != nil {
		t.Fatal(err)
	}
	second, err := restored.CursorEpoch(ctx)
	if err != nil || second != first {
		t.Fatalf("reopened CursorEpoch()=(%q, %v), want %q", second, err, first)
	}
}

func TestConcurrentCursorEpochInitializationSharesOneEpoch(t *testing.T) {
	ctx := context.Background()
	store, err := lifecycle.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	start := make(chan struct{})
	epochs := make(chan string, callers)
	errs := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			epoch, err := service.CursorEpoch(ctx)
			if err != nil {
				errs <- err
				return
			}
			epochs <- epoch
		}()
	}
	close(start)
	group.Wait()
	close(epochs)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent CursorEpoch(): %v", err)
	}
	want := ""
	for epoch := range epochs {
		if want == "" {
			want = epoch
		}
		if epoch != want || len(epoch) != 32 {
			t.Errorf("concurrent cursor epoch=%q, want shared epoch %q", epoch, want)
		}
	}
}

func TestPlatformEventDeduplicationSharesPerSandboxCursor(t *testing.T) {
	service, err := New(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := service.Append(ctx, "sandbox-a", []Line{{SandboxID: "sandbox-a", Message: "line"}}); err != nil {
		t.Fatal(err)
	}
	event := PlatformEvent{SandboxID: "sandbox-a", EventTime: time.Unix(4000, 0), Source: "vm", Type: "sandbox_state", Reason: "running", DedupKey: "vm-state:running:4000"}
	first, created, err := service.AppendPlatformEvent(ctx, event)
	if err != nil || !created || first.Sequence != 2 {
		t.Fatalf("first append=(%+v, %v, %v)", first, created, err)
	}
	duplicate, created, err := service.AppendPlatformEvent(ctx, event)
	if err != nil || created || duplicate.Sequence != first.Sequence {
		t.Fatalf("duplicate append=(%+v, %v, %v), want existing seq %d", duplicate, created, err, first.Sequence)
	}
	latest, _, _, err := service.CursorState(ctx, "sandbox-a")
	if err != nil || latest != 2 {
		t.Fatalf("latest cursor sequence=(%d, %v), want 2", latest, err)
	}
}

func TestPlatformEventWindowTracksTrimmedCursorRange(t *testing.T) {
	service, err := New(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for index := range maxLines + 1 {
		_, created, err := service.AppendPlatformEvent(ctx, PlatformEvent{
			SandboxID: "sandbox-a", EventTime: time.Unix(int64(index+1), 0), Source: "vm",
			Type: "sandbox_state", Reason: fmt.Sprintf("state-%d", index), DedupKey: fmt.Sprintf("state-%d", index),
		})
		if err != nil || !created {
			t.Fatalf("append event %d=(created %v, err %v)", index, created, err)
		}
	}
	events, err := service.ListPlatformEvents(ctx, "sandbox-a")
	if err != nil || len(events) != maxLines || events[0].Sequence != 2 || events[len(events)-1].Sequence != maxLines+1 {
		t.Fatalf("retained platform event range=(len %d, err %v)", len(events), err)
	}
	latest, logsTrimmed, eventsTrimmed, err := service.CursorState(ctx, "sandbox-a")
	if err != nil || latest != maxLines+1 || logsTrimmed != 0 || eventsTrimmed != 1 {
		t.Fatalf("cursor state=(%d, %d, %d, %v)", latest, logsTrimmed, eventsTrimmed, err)
	}
}

func TestAppendRejectsMismatchedSandboxAndOversizedMessage(t *testing.T) {
	service, err := New(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), "sandbox-a", []Line{{SandboxID: "sandbox-b", Message: "event"}}); err == nil {
		t.Fatal("accepted a line bound to a different sandbox")
	}
	if _, err := service.Append(context.Background(), "sandbox-a", []Line{{SandboxID: "sandbox-a", Message: string(make([]byte, 64*1024+1))}}); err == nil {
		t.Fatal("accepted an oversized message")
	}
}
