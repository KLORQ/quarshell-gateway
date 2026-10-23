package peer

import (
	"context"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Manager maintains this gateway's leadership lease.
type Manager struct {
	Registry *Registry
	ID       string
	Endpoint string
	TTL      time.Duration

	mu     sync.Mutex
	token  uint64
	leader bool
}

// NewManager returns a leadership manager.
func NewManager(registry *Registry, id, endpoint string, ttl time.Duration) (*Manager, error) {
	if registry == nil || id == "" || endpoint == "" {
		return nil, domain.Invalidf("peer.manager", "registry, id and endpoint are required")
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &Manager{Registry: registry, ID: id, Endpoint: endpoint, TTL: ttl}, nil
}

// Acquire joins and tries to claim leadership.
func (m *Manager) Acquire(ctx context.Context) (Peer, error) {
	if _, err := m.Registry.Join(ctx, m.ID, m.Endpoint); err != nil {
		return Peer{}, err
	}
	peer, err := m.Registry.Claim(ctx, m.ID, m.TTL)
	if err != nil {
		m.mu.Lock()
		m.leader = false
		m.mu.Unlock()
		return Peer{}, err
	}
	m.mu.Lock()
	m.token = peer.FencingToken
	m.leader = true
	m.mu.Unlock()
	return peer, nil
}

// Heartbeat renews leadership. A lost lease clears the leader flag.
func (m *Manager) Heartbeat(ctx context.Context) error {
	m.mu.Lock()
	token := m.token
	m.mu.Unlock()
	peer, err := m.Registry.Heartbeat(ctx, m.ID, token, m.TTL)
	if err != nil {
		m.mu.Lock()
		m.leader = false
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.token = peer.FencingToken
	m.leader = true
	m.mu.Unlock()
	return nil
}

// RequireLeader fails closed unless this manager still owns the fence.
func (m *Manager) RequireLeader() error {
	m.mu.Lock()
	token := m.token
	leader := m.leader
	m.mu.Unlock()
	if !leader {
		return domain.New(domain.CodeUnavailable, "peer.manager", "gateway is not the owner")
	}
	return m.Registry.Validate(m.ID, token)
}

// Run maintains leadership until the context is canceled.
func (m *Manager) Run(ctx context.Context) error {
	interval := m.TTL / 3
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		leader := m.leader
		m.mu.Unlock()
		if leader {
			_ = m.Heartbeat(ctx)
		} else {
			_, _ = m.Acquire(ctx)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// IsLeader reports the local flag.
func (m *Manager) IsLeader() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leader
}
