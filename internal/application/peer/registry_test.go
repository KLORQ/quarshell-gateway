package peer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestPeerLeadershipAndFencing(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	registry := NewRegistry(func() time.Time { return now })
	if _, err := registry.Join(ctx, "a", "https://a"); err != nil {
		t.Fatalf("Join a: %v", err)
	}
	if _, err := registry.Join(ctx, "b", "https://b"); err != nil {
		t.Fatalf("Join b: %v", err)
	}
	leader, err := registry.Claim(ctx, "a", time.Minute)
	if err != nil || !leader.Leader || leader.FencingToken == 0 {
		t.Fatalf("Claim a = %+v %v", leader, err)
	}
	if _, err := registry.Claim(ctx, "b", time.Minute); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second claim = %v", err)
	}
	if err := registry.Validate("a", leader.FencingToken); err != nil {
		t.Fatalf("Validate a: %v", err)
	}
	if err := registry.Validate("b", leader.FencingToken); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("Validate b = %v", err)
	}
	if _, err := registry.Heartbeat(ctx, "a", leader.FencingToken, time.Minute); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if owner, ok := registry.Owner(); !ok || owner.ID != "a" {
		t.Fatalf("Owner = %+v %v", owner, ok)
	}
	if err := registry.Release(ctx, "a", leader.FencingToken); err != nil {
		t.Fatalf("Release: %v", err)
	}
	second, err := registry.Claim(ctx, "b", time.Minute)
	if err != nil || second.FencingToken <= leader.FencingToken {
		t.Fatalf("second leader = %+v %v", second, err)
	}
	if err := registry.Validate("a", leader.FencingToken); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale a = %v", err)
	}
	registry.Leave(ctx, "b")
	if _, ok := registry.Owner(); ok {
		t.Fatalf("owner survived Leave")
	}
}

func TestPeerLeaseExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	registry := NewRegistry(func() time.Time { return now })
	_, _ = registry.Join(ctx, "a", "https://a")
	_, _ = registry.Join(ctx, "b", "https://b")
	first, err := registry.Claim(ctx, "a", time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	now = now.Add(2 * time.Minute)
	second, err := registry.Claim(ctx, "b", time.Minute)
	if err != nil || second.FencingToken <= first.FencingToken {
		t.Fatalf("expired claim = %+v %v", second, err)
	}
	list := registry.List()
	if len(list) != 2 {
		t.Fatalf("List = %+v", list)
	}
}
