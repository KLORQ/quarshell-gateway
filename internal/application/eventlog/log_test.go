package eventlog

import (
	"context"
	"errors"
	"path/filepath"
	"sync"

	"github.com/KLORQ/quarshell-core/domain"
	"testing"
)

func TestMemoryLogCursorAndRetention(t *testing.T) {
	log := NewMemoryLog(2)
	ctx := context.Background()
	for index := 0; index < 3; index++ {
		if _, err := log.Append(ctx, "stream", "event", []byte{byte(index)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	events, cursor, err := log.After(ctx, "", 10)
	if err != nil || len(events) != 2 || events[0].ID != 2 || cursor != "3" {
		t.Fatalf("After from start = %+v %q %v", events, cursor, err)
	}
	events, cursor, err = log.After(ctx, "2", 10)
	if err != nil || len(events) != 1 || events[0].ID != 3 || cursor != "3" {
		t.Fatalf("After cursor = %+v %q %v", events, cursor, err)
	}
	events, _, err = log.After(ctx, "1", 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("cursor before retained window = %+v %v", events, err)
	}
	if _, _, err := log.After(ctx, "0", 10); !errors.Is(err, ErrCursorLost) {
		t.Fatalf("lost cursor = %v", err)
	}
	latest, err := log.Latest(ctx)
	if err != nil || latest != "3" {
		t.Fatalf("Latest = %q %v", latest, err)
	}
}

func TestMemoryLogValidationAndCancellation(t *testing.T) {
	log := NewMemoryLog(10)
	if _, err := log.Append(context.Background(), "", "event", nil); err == nil {
		t.Fatalf("empty stream accepted")
	}
	if _, _, err := log.After(context.Background(), "bad", 10); err == nil {
		t.Fatalf("invalid cursor accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := log.Append(ctx, "stream", "event", nil); !errors.Is(err, domain.ErrCanceled) {
		t.Fatalf("canceled append = %v", err)
	}
}

func TestFileLogPersistsAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	log, err := NewFileLog(path)
	if err != nil {
		t.Fatalf("NewFileLog: %v", err)
	}
	ctx := context.Background()
	for index := 0; index < 3; index++ {
		if _, err := log.Append(ctx, "stream", "event", []byte{byte(index)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := NewFileLog(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	events, cursor, err := reopened.After(ctx, "1", 10)
	if err != nil || len(events) != 2 || events[0].ID != 2 || cursor != "3" {
		t.Fatalf("After reopen = %+v %q %v", events, cursor, err)
	}
	latest, err := reopened.Latest(ctx)
	if err != nil || latest != "3" {
		t.Fatalf("Latest = %q %v", latest, err)
	}
}

func TestLogConcurrentAppends(t *testing.T) {
	log := NewMemoryLog(1000)
	ctx := context.Background()
	var wait sync.WaitGroup
	for worker := 0; worker < 10; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < 100; index++ {
				_, _ = log.Append(ctx, "stream", "event", nil)
			}
		}()
	}
	wait.Wait()
	events, cursor, err := log.After(ctx, "", 1000)
	if err != nil || len(events) != 1000 || cursor != "1000" {
		t.Fatalf("events=%d cursor=%q err=%v", len(events), cursor, err)
	}
}
