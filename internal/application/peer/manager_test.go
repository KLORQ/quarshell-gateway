package peer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestManagerLeadership(t *testing.T) {
	ctx := context.Background()
	registry := NewRegistry(nil)
	first, _ := NewManager(registry, "a", "https://a", time.Minute)
	second, _ := NewManager(registry, "b", "https://b", time.Minute)
	if _, err := first.Acquire(ctx); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := first.RequireLeader(); err != nil {
		t.Fatalf("first require: %v", err)
	}
	if _, err := second.Acquire(ctx); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second acquire = %v", err)
	}
	if err := second.RequireLeader(); !errors.Is(err, domain.ErrUnavailable) && !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second require = %v", err)
	}
	registry.Leave(ctx, "a")
	if err := first.RequireLeader(); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale leader = %v", err)
	}
	if _, err := second.Acquire(ctx); err != nil {
		t.Fatalf("second re-acquire: %v", err)
	}
}

func TestManagerRunTakesOver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := NewRegistry(nil)
	first, _ := NewManager(registry, "a", "https://a", 150*time.Millisecond)
	second, _ := NewManager(registry, "b", "https://b", 150*time.Millisecond)
	go func() { _ = first.Run(ctx) }()
	go func() { _ = second.Run(ctx) }()
	waitLeader(t, first, second)
	registry.Leave(ctx, "a")
	waitUntil(t, func() bool { return second.IsLeader() })
	cancel()
}

func waitLeader(t *testing.T, managers ...*Manager) {
	t.Helper()
	waitUntil(t, func() bool {
		for _, manager := range managers {
			if manager.IsLeader() {
				return true
			}
		}
		return false
	})
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition was not met")
}
