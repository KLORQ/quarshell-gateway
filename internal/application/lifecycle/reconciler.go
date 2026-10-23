package lifecycle

import (
	"context"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Handler delivers one outbox side effect.
type Handler func(context.Context, OutboxMessage) error

// ReconcileResult reports one reconciler pass.
type ReconcileResult struct {
	Claimed      int
	Acknowledged int
	Retried      int
	Dead         int
}

// Reconciler claims outbox messages with leases, invokes the handler, and
// retries with bounded exponential backoff. Leases expire so a crashed worker
// cannot block delivery forever.
type Reconciler struct {
	Store       Store
	Handler     Handler
	Lease       time.Duration
	MaxAttempts int
	Batch       int
	Backoff     func(attempts int) time.Duration
	Now         func() time.Time
}

// RunOnce processes at most Batch messages.
func (r *Reconciler) RunOnce(ctx context.Context) (ReconcileResult, error) {
	var result ReconcileResult
	if r.Store == nil || r.Handler == nil {
		return result, domain.Invalidf("lifecycle.reconcile", "store and handler are required")
	}
	lease := r.Lease
	if lease <= 0 {
		lease = 30 * time.Second
	}
	batch := r.Batch
	if batch <= 0 {
		batch = 100
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	messages, err := r.Store.ClaimOutbox(ctx, now, lease, batch)
	if err != nil {
		return result, err
	}
	result.Claimed = len(messages)
	for _, message := range messages {
		if err := ctx.Err(); err != nil {
			return result, domain.Wrap(err, "lifecycle.reconcile", "reconcile canceled")
		}
		if err := r.Handler(ctx, message); err == nil {
			if err := r.Store.AckOutbox(ctx, message.ID); err != nil {
				return result, err
			}
			result.Acknowledged++
			continue
		}
		attempts := message.Attempts + 1
		maxAttempts := r.MaxAttempts
		if maxAttempts <= 0 {
			maxAttempts = 5
		}
		dead := attempts >= maxAttempts
		backoff := r.backoff(attempts)
		if err := r.Store.RetryOutbox(ctx, message.ID, now.Add(backoff), "delivery failed", dead); err != nil {
			return result, err
		}
		if dead {
			result.Dead++
		} else {
			result.Retried++
		}
	}
	return result, nil
}

func (r *Reconciler) backoff(attempts int) time.Duration {
	if r.Backoff != nil {
		return r.Backoff(attempts)
	}
	duration := time.Second
	for index := 1; index < attempts && duration < time.Hour; index++ {
		duration *= 2
	}
	if duration > time.Hour {
		duration = time.Hour
	}
	return duration
}
