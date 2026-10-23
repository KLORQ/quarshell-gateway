package lifecycle

import (
	"context"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Lease is an ownership grant with a monotonically increasing fencing token.
type Lease struct {
	Key       string
	Owner     string
	Token     uint64
	ExpiresAt time.Time
}

// LeaseRegistry grants one owner at a time per key. A stale owner that still
// believes it holds the lease is rejected by Validate after a newer token exists.
type LeaseRegistry struct {
	mu     sync.Mutex
	leases map[string]Lease
	now    func() time.Time
	next   uint64
}

// NewLeaseRegistry returns an empty registry.
func NewLeaseRegistry(now func() time.Time) *LeaseRegistry {
	if now == nil {
		now = time.Now
	}
	return &LeaseRegistry{leases: map[string]Lease{}, now: now}
}

// Acquire takes the lease for key or returns a conflict.
func (r *LeaseRegistry) Acquire(ctx context.Context, key, owner string, ttl time.Duration) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, domain.Wrap(domain.ErrCanceled, "lifecycle.lease", "acquire canceled")
	}
	if key == "" || owner == "" || ttl <= 0 {
		return Lease{}, domain.Invalidf("lifecycle.lease", "key, owner, and positive ttl are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if existing, ok := r.leases[key]; ok && existing.ExpiresAt.After(now) {
		return Lease{}, domain.New(domain.CodeConflict, "lifecycle.lease", "lease is held by another owner")
	}
	r.next++
	lease := Lease{Key: key, Owner: owner, Token: r.next, ExpiresAt: now.Add(ttl)}
	r.leases[key] = lease
	return lease, nil
}

// Renew extends a current lease.
func (r *LeaseRegistry) Renew(ctx context.Context, lease Lease, ttl time.Duration) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, domain.Wrap(domain.ErrCanceled, "lifecycle.lease", "renew canceled")
	}
	if ttl <= 0 {
		return Lease{}, domain.Invalidf("lifecycle.lease", "positive ttl is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.leases[lease.Key]
	if !ok || current.Token != lease.Token || current.Owner != lease.Owner || !current.ExpiresAt.After(r.now()) {
		return Lease{}, domain.New(domain.CodeConflict, "lifecycle.lease", "lease is no longer held")
	}
	current.ExpiresAt = r.now().Add(ttl)
	r.leases[lease.Key] = current
	return current, nil
}

// Release drops a current lease. A stale token is ignored as a conflict.
func (r *LeaseRegistry) Release(ctx context.Context, lease Lease) error {
	if err := ctx.Err(); err != nil {
		return domain.Wrap(domain.ErrCanceled, "lifecycle.lease", "release canceled")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.leases[lease.Key]
	if !ok {
		return nil
	}
	if current.Token != lease.Token || current.Owner != lease.Owner {
		return domain.New(domain.CodeConflict, "lifecycle.lease", "lease token is stale")
	}
	delete(r.leases, lease.Key)
	return nil
}

// Validate rejects an expired lease or a stale fencing token.
func (r *LeaseRegistry) Validate(lease Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.leases[lease.Key]
	if !ok || current.Token != lease.Token || current.Owner != lease.Owner {
		return domain.New(domain.CodeConflict, "lifecycle.lease", "lease token is stale")
	}
	if !current.ExpiresAt.After(r.now()) {
		return domain.New(domain.CodeConflict, "lifecycle.lease", "lease expired")
	}
	return nil
}

// Current returns the live lease for key.
func (r *LeaseRegistry) Current(key string) (Lease, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lease, ok := r.leases[key]
	if !ok || !lease.ExpiresAt.After(r.now()) {
		return Lease{}, false
	}
	return lease, true
}
