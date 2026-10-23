package relay

import (
	"context"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
)

func sandbox() domain.SandboxRef {
	return domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
}

func TestRelayAttachHeartbeatDetach(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemoryLog(10)
	registry := NewRegistry(time.Minute, log)
	session := Session{Sandbox: sandbox(), ID: "agent", Revision: 1, Metadata: map[string]string{"host": "a"}}
	first, replayed, err := registry.Attach(ctx, session)
	if err != nil || replayed || first.ConnectedAt.IsZero() {
		t.Fatalf("Attach = %+v replayed=%v err=%v", first, replayed, err)
	}
	replay, replayed, err := registry.Attach(ctx, session)
	if err != nil || !replayed {
		t.Fatalf("replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	if err := registry.Heartbeat(ctx, sandbox(), "agent", 1); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if err := registry.Heartbeat(ctx, sandbox(), "agent", 2); err == nil {
		t.Fatalf("stale heartbeat accepted")
	}
	if list := registry.List(sandbox()); len(list) != 1 {
		t.Fatalf("List = %+v", list)
	}
	if err := registry.Detach(ctx, sandbox(), "agent", 1); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if _, exists := registry.Get(sandbox(), "agent"); exists {
		t.Fatalf("session survived detach")
	}
	events, _, err := log.After(ctx, "", 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events = %+v %v", events, err)
	}
}

func TestRelayRevisionReplacesAndExpires(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	registry := NewRegistry(30*time.Second, nil)
	registry.now = func() time.Time { return now }
	if _, _, err := registry.Attach(ctx, Session{Sandbox: sandbox(), ID: "agent", Revision: 1}); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	replaced, replayed, err := registry.Attach(ctx, Session{Sandbox: sandbox(), ID: "agent", Revision: 2})
	if err != nil || replayed || replaced.Revision != 2 {
		t.Fatalf("revision replace = %+v replayed=%v err=%v", replaced, replayed, err)
	}
	now = now.Add(time.Minute)
	if expired := registry.Expire(ctx); expired != 1 {
		t.Fatalf("Expire = %d", expired)
	}
	if _, exists := registry.Get(sandbox(), "agent"); exists {
		t.Fatalf("expired session still present")
	}
}

func TestRelayValidation(t *testing.T) {
	registry := NewRegistry(0, nil)
	if _, _, err := registry.Attach(context.Background(), Session{}); err == nil {
		t.Fatalf("empty session accepted")
	}
}
