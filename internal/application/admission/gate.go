// Package admission implements gateway configuration admission deadlines and
// generation fencing.
package admission

import (
	"context"
	"errors"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Gate bounds admission work and rejects stale generations.
type Gate struct {
	Deadline time.Duration
}

// Admit rejects zero or stale generations.
func (g Gate) Admit(requested, current domain.Generation) error {
	if requested == 0 {
		return domain.Invalidf("admission.gate", "generation is required")
	}
	if current > 0 && requested < current {
		return domain.New(domain.CodeConflict, "admission.gate", "stale generation")
	}
	return nil
}

// Run executes work under the admission deadline.
func (g Gate) Run(ctx context.Context, fn func(context.Context) error) error {
	if fn == nil {
		return domain.Invalidf("admission.gate", "work is required")
	}
	if g.Deadline <= 0 {
		return fn(ctx)
	}
	admissionCtx, cancel := context.WithTimeout(ctx, g.Deadline)
	defer cancel()
	err := fn(admissionCtx)
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(admissionCtx.Err(), context.DeadlineExceeded) {
		return domain.Wrap(domain.ErrDeadlineExceeded, "admission.gate", "admission deadline exceeded")
	}
	if errors.Is(err, context.Canceled) {
		return domain.Wrap(domain.ErrCanceled, "admission.gate", "admission canceled")
	}
	return err
}
