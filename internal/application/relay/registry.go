// Package relay tracks authenticated supervisor relay sessions.
package relay

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
)

// Session is one connected supervisor relay.
type Session struct {
	Sandbox     domain.SandboxRef `json:"sandbox"`
	ID          string            `json:"id"`
	Revision    uint64            `json:"revision"`
	ConnectedAt time.Time         `json:"connected_at"`
	LastSeen    time.Time         `json:"last_seen"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Registry tracks sessions in one gateway process.
type Registry struct {
	mu       sync.Mutex
	sessions map[string]Session
	now      func() time.Time
	ttl      time.Duration
	log      eventlog.Log
}

// NewRegistry returns a relay registry. Zero ttl disables expiry.
func NewRegistry(ttl time.Duration, log eventlog.Log) *Registry {
	return &Registry{sessions: map[string]Session{}, now: time.Now, ttl: ttl, log: log}
}

// Attach registers or refreshes a relay session. A revision change replaces the
// previous session.
func (r *Registry) Attach(ctx context.Context, session Session) (Session, bool, error) {
	if !session.Sandbox.Valid() || strings.TrimSpace(session.ID) == "" || session.Revision == 0 {
		return Session{}, false, domain.Invalidf("relay.attach", "sandbox, id and revision are required")
	}
	r.mu.Lock()
	now := r.now().UTC()
	key := relayKey(session.Sandbox, session.ID)
	current, exists := r.sessions[key]
	replayed := exists && current.Revision == session.Revision
	if replayed {
		current.LastSeen = now
		r.sessions[key] = current
		r.mu.Unlock()
		return cloneSession(current), true, nil
	}
	session.ConnectedAt = now
	session.LastSeen = now
	r.sessions[key] = session
	r.mu.Unlock()
	r.emit(ctx, "relay.attached", session)
	return cloneSession(session), false, nil
}

// Heartbeat refreshes a session for the current revision.
func (r *Registry) Heartbeat(ctx context.Context, sandbox domain.SandboxRef, id string, revision uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := relayKey(sandbox, id)
	session, exists := r.sessions[key]
	if !exists || session.Revision != revision {
		return domain.Wrap(domain.ErrNotFound, "relay.heartbeat", "relay session not found")
	}
	session.LastSeen = r.now().UTC()
	r.sessions[key] = session
	return nil
}

// Detach removes a session for the current revision.
func (r *Registry) Detach(ctx context.Context, sandbox domain.SandboxRef, id string, revision uint64) error {
	r.mu.Lock()
	key := relayKey(sandbox, id)
	session, exists := r.sessions[key]
	if !exists || session.Revision != revision {
		r.mu.Unlock()
		return nil
	}
	delete(r.sessions, key)
	r.mu.Unlock()
	r.emit(ctx, "relay.detached", session)
	return nil
}

// Get returns one session.
func (r *Registry) Get(sandbox domain.SandboxRef, id string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, exists := r.sessions[relayKey(sandbox, id)]
	return cloneSession(session), exists
}

// List returns sessions for one sandbox sorted by ID.
func (r *Registry) List(sandbox domain.SandboxRef) []Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []Session
	for _, session := range r.sessions {
		if session.Sandbox == sandbox {
			result = append(result, cloneSession(session))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

// Expire removes stale sessions and returns the count.
func (r *Registry) Expire(ctx context.Context) int {
	if r.ttl <= 0 {
		return 0
	}
	r.mu.Lock()
	now := r.now()
	var expired []Session
	for key, session := range r.sessions {
		if now.Sub(session.LastSeen) > r.ttl {
			expired = append(expired, session)
			delete(r.sessions, key)
		}
	}
	r.mu.Unlock()
	for _, session := range expired {
		r.emit(ctx, "relay.expired", session)
	}
	return len(expired)
}

func (r *Registry) emit(ctx context.Context, kind string, session Session) {
	if r.log == nil {
		return
	}
	_, _ = r.log.Append(ctx, "relay", kind, []byte(relayKey(session.Sandbox, session.ID)))
}

func relayKey(sandbox domain.SandboxRef, id string) string {
	return string(sandbox.Workspace) + "/" + string(sandbox.Sandbox) + "/" + id
}

func cloneSession(session Session) Session {
	if len(session.Metadata) > 0 {
		metadata := make(map[string]string, len(session.Metadata))
		for key, value := range session.Metadata {
			metadata[key] = value
		}
		session.Metadata = metadata
	}
	return session
}
