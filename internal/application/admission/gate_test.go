package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestGateGenerationFence(t *testing.T) {
	gate := Gate{}
	if err := gate.Admit(2, 1); err != nil {
		t.Fatalf("newer generation: %v", err)
	}
	if err := gate.Admit(1, 1); err != nil {
		t.Fatalf("same generation: %v", err)
	}
	if err := gate.Admit(1, 2); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale generation = %v", err)
	}
	if err := gate.Admit(0, 1); err == nil {
		t.Fatalf("zero generation accepted")
	}
}

func TestGateDeadline(t *testing.T) {
	gate := Gate{Deadline: 10 * time.Millisecond}
	if err := gate.Run(context.Background(), func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}); !errors.Is(err, domain.ErrDeadlineExceeded) {
		t.Fatalf("deadline = %v", err)
	}
	if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("fast work: %v", err)
	}
}
