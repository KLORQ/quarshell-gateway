package credentialstore

import (
	"context"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Refresher obtains new material for an existing credential.
type Refresher interface {
	Refresh(ctx context.Context, secret Secret) (material []byte, expiresAt time.Time, err error)
}

// RefreshService rotates credentials with a hard deadline and bounded output.
// A canceled or timed-out refresh never updates the store.
type RefreshService struct {
	Store            Store
	Broker           *Broker
	Refresher        Refresher
	Timeout          time.Duration
	MaxMaterialBytes int
}

// Refresh replaces material and invalidates old handles.
func (s *RefreshService) Refresh(ctx context.Context, id domain.CredentialID) (uint64, error) {
	if s.Store == nil || s.Broker == nil || s.Refresher == nil {
		return 0, domain.Invalidf("credentials.refresh", "store, broker and refresher are required")
	}
	current, err := s.Store.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxBytes := s.MaxMaterialBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	refreshCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		material  []byte
		expiresAt time.Time
		err       error
	}
	done := make(chan result, 1)
	go func() {
		material, expiresAt, err := s.Refresher.Refresh(refreshCtx, current)
		done <- result{material: material, expiresAt: expiresAt, err: err}
	}()
	select {
	case <-refreshCtx.Done():
		return 0, domain.Wrap(classifyContextError(refreshCtx.Err()), "credentials.refresh", "credential refresh canceled or timed out")
	case result := <-done:
		if result.err != nil {
			return 0, domain.Wrap(result.err, "credentials.refresh", "credential refresh failed")
		}
		if refreshCtx.Err() != nil {
			return 0, domain.Wrap(classifyContextError(refreshCtx.Err()), "credentials.refresh", "credential refresh canceled or timed out")
		}
		if len(result.material) == 0 {
			return 0, domain.Invalidf("credentials.refresh", "refresher returned empty material")
		}
		if len(result.material) > maxBytes {
			return 0, domain.Invalidf("credentials.refresh", "refreshed material exceeds %d bytes", maxBytes)
		}
		return s.Broker.Rotate(ctx, id, result.material, result.expiresAt)
	}
}
