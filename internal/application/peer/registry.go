// Package peer tracks gateway peers and ownership leases with fencing.
package peer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

// Peer is one registered gateway instance.
type Peer struct {
	ID           string    `json:"id"`
	Endpoint     string    `json:"endpoint"`
	Leader       bool      `json:"leader"`
	FencingToken uint64    `json:"fencing_token,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
}

// Registry tracks peers and the gateway ownership lease.
type Registry struct {
	mu     sync.Mutex
	peers  map[string]Peer
	leases *lifecycle.LeaseRegistry
	now    func() time.Time
}

// NewRegistry returns a peer registry.
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{peers: map[string]Peer{}, leases: lifecycle.NewLeaseRegistry(now), now: now}
}

// Join registers or refreshes a peer.
func (r *Registry) Join(ctx context.Context, id, endpoint string) (Peer, error) {
	if id == "" || endpoint == "" {
		return Peer{}, domain.Invalidf("peer.join", "id and endpoint are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	peer := r.peers[id]
	peer.ID = id
	peer.Endpoint = endpoint
	peer.LastSeen = r.now().UTC()
	if current, ok := r.leases.Current("gateway"); ok {
		peer.Leader = current.Owner == id
		peer.FencingToken = current.Token
	}
	r.peers[id] = peer
	return peer, nil
}

// Claim attempts to become the gateway owner.
func (r *Registry) Claim(ctx context.Context, id string, ttl time.Duration) (Peer, error) {
	r.mu.Lock()
	peer, exists := r.peers[id]
	r.mu.Unlock()
	if !exists {
		return Peer{}, domain.Wrap(domain.ErrNotFound, "peer.claim", "peer is not registered")
	}
	lease, err := r.leases.Acquire(ctx, "gateway", id, ttl)
	if err != nil {
		return Peer{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	peer = r.peers[id]
	peer.Leader = true
	peer.FencingToken = lease.Token
	peer.LastSeen = r.now().UTC()
	r.peers[id] = peer
	for otherID, other := range r.peers {
		if otherID != id {
			other.Leader = false
			other.FencingToken = lease.Token
			r.peers[otherID] = other
		}
	}
	return peer, nil
}

// Heartbeat renews leadership for the current owner.
func (r *Registry) Heartbeat(ctx context.Context, id string, token uint64, ttl time.Duration) (Peer, error) {
	lease, err := r.leases.Renew(ctx, lifecycle.Lease{Key: "gateway", Owner: id, Token: token}, ttl)
	if err != nil {
		return Peer{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	peer, exists := r.peers[id]
	if !exists {
		return Peer{}, domain.Wrap(domain.ErrNotFound, "peer.heartbeat", "peer is not registered")
	}
	peer.Leader = true
	peer.FencingToken = lease.Token
	peer.LastSeen = r.now().UTC()
	r.peers[id] = peer
	return peer, nil
}

// Release drops leadership without unregistering the peer.
func (r *Registry) Release(ctx context.Context, id string, token uint64) error {
	if err := r.leases.Release(ctx, lifecycle.Lease{Key: "gateway", Owner: id, Token: token}); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	peer, exists := r.peers[id]
	if exists {
		peer.Leader = false
		r.peers[id] = peer
	}
	return nil
}

// Validate reports whether id still owns the current fence.
func (r *Registry) Validate(id string, token uint64) error {
	return r.leases.Validate(lifecycle.Lease{Key: "gateway", Owner: id, Token: token})
}

// Owner returns the current owner.
func (r *Registry) Owner() (Peer, bool) {
	lease, ok := r.leases.Current("gateway")
	if !ok {
		return Peer{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	peer, exists := r.peers[lease.Owner]
	return peer, exists
}

// List returns peers sorted by ID.
func (r *Registry) List() []Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Peer, 0, len(r.peers))
	for _, peer := range r.peers {
		result = append(result, peer)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

// Leave unregisters a peer and releases its lease if it owns it.
func (r *Registry) Leave(ctx context.Context, id string) {
	if lease, ok := r.leases.Current("gateway"); ok && lease.Owner == id {
		_ = r.leases.Release(ctx, lease)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, id)
}
