// Package sshrelay tracks live supervisor sessions and opens per-request byte
// relays into sandboxes (OpenShell supervisor relay). The gateway never dials a
// sandbox: supervisors connect out, and each channel is a fresh outbound data
// stream paired with a waiting client.
package sshrelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/relayproto"
)

// ErrNotConnected means the sandbox supervisor has no live control stream.
var ErrNotConnected = errors.New("sandbox is not ready: supervisor relay not connected")

// ErrSupervisorSessionOwned means a new hello cannot replace the active
// supervisor instance or replay an already accepted connection epoch.
var ErrSupervisorSessionOwned = errors.New("sandbox supervisor session is already owned")

// ErrOpenTimeout means the supervisor did not dial back the data stream in time.
var ErrOpenTimeout = errors.New("supervisor relay did not open the channel in time")

// ErrReplicaCapacity and ErrSandboxCapacity match the upstream RESOURCE_EXHAUSTED cases.
var ErrReplicaCapacity = errors.New("gateway relay capacity reached")
var ErrSandboxCapacity = errors.New("sandbox relay capacity reached")

const defaultOpenTimeout = 10 * time.Second
const maxPendingRelays = 256
const maxPendingRelaysPerSandbox = 32

// supervisorOwnerTTL mirrors OpenShell's owner lease. A disconnected
// supervisor keeps ownership briefly so another process cannot claim the
// sandbox during a transient control-stream failure.
const supervisorOwnerTTL = 45 * time.Second

// relayClaimDurationBuckets mirrors the pinned OpenShell histogram boundaries.
var relayClaimDurationBuckets = [...]float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15}

// RelayClaimHistogramBuckets returns a copy of the OpenShell histogram boundaries.
func RelayClaimHistogramBuckets() []float64 {
	return append([]float64(nil), relayClaimDurationBuckets[:]...)
}

// Hub is safe for concurrent use.
type Hub struct {
	OpenTimeout time.Duration
	Log         *slog.Logger

	mu                   sync.Mutex
	sessions             map[string]*session
	owners               map[string]supervisorOwner
	pending              map[string]*pending
	active               map[string]*activeRelay
	relayRejectedReplica uint64
	relayRejectedSandbox uint64
	relayExpired         uint64
	relayClaimCount      uint64
	relayClaimSumSeconds float64
	relayClaimBuckets    [len(relayClaimDurationBuckets)]uint64
}

type supervisorOwner struct {
	instanceID string
	epoch      uint64
	expiresAt  time.Time
}

// MetricsSnapshot returns aggregate relay state without exposing sandbox IDs.
// Values are captured under the same lock used for session and channel maps.
type MetricsSnapshot struct {
	SupervisorSessions   int
	RelayPending         int
	RelayPendingCapacity int
	RelayRejectedReplica uint64
	RelayRejectedSandbox uint64
	RelayExpired         uint64
	RelayClaimCount      uint64
	RelayClaimSumSeconds float64
	RelayClaimBuckets    [len(relayClaimDurationBuckets)]uint64
}

func (h *Hub) MetricsSnapshot() MetricsSnapshot {
	if h == nil {
		return MetricsSnapshot{RelayPendingCapacity: maxPendingRelays}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return MetricsSnapshot{
		SupervisorSessions: len(h.sessions), RelayPending: len(h.pending), RelayPendingCapacity: maxPendingRelays,
		RelayRejectedReplica: h.relayRejectedReplica, RelayRejectedSandbox: h.relayRejectedSandbox, RelayExpired: h.relayExpired,
		RelayClaimCount: h.relayClaimCount, RelayClaimSumSeconds: h.relayClaimSumSeconds, RelayClaimBuckets: h.relayClaimBuckets,
	}
}

type session struct {
	sandbox         string
	instanceID      string
	connectionEpoch uint64
	open            func(channel, target string) error
	closeFn         func()
	done            chan struct{}
	once            sync.Once
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		if s.closeFn != nil {
			s.closeFn()
		}
	})
}

// RegisterSupervisor registers a control stream backed by OpenShell
// ConnectSupervisor. The callback must enqueue a RelayOpen on that stream.
// A fresh owner lease may only be replaced by a higher connection epoch from
// the same instance. Another instance can claim ownership after the lease
// expires. The lease is process-local; shared persistence is required for HA.
// The returned function unregisters this exact session (safe after replacement).
func (h *Hub) RegisterSupervisor(sandbox, instanceID string, connectionEpoch uint64, open func(channel, target string) error, done <-chan struct{}, closeFn func()) (func(), error) {
	if sandbox == "" || instanceID == "" || connectionEpoch == 0 || open == nil || done == nil {
		return nil, errors.New("sandbox, supervisor instance, positive connection epoch, callback, and done channel are required")
	}
	s := &session{sandbox: sandbox, instanceID: instanceID, connectionEpoch: connectionEpoch, open: open, closeFn: closeFn, done: make(chan struct{})}
	h.mu.Lock()
	prev := h.sessions[sandbox]
	if h.owners == nil {
		h.owners = make(map[string]supervisorOwner)
	}
	owner := h.owners[sandbox]
	ownerFresh := time.Now().Before(owner.expiresAt)
	if ownerFresh && (owner.instanceID != instanceID || connectionEpoch <= owner.epoch) {
		h.mu.Unlock()
		return nil, ErrSupervisorSessionOwned
	}
	if prev != nil && (prev.instanceID != instanceID || connectionEpoch <= prev.connectionEpoch) {
		h.mu.Unlock()
		return nil, ErrSupervisorSessionOwned
	}
	h.owners[sandbox] = supervisorOwner{instanceID: instanceID, epoch: connectionEpoch, expiresAt: time.Now().Add(supervisorOwnerTTL)}
	var closing []*activeRelay
	if prev != nil {
		closing = h.takeActiveRelaysLocked(sandbox)
	}
	h.sessions[sandbox] = s
	h.mu.Unlock()
	if prev != nil {
		prev.close()
		closeActiveRelays(closing)
	}
	go func() {
		select {
		case <-done:
			s.close()
		case <-s.done:
		}
	}()
	return func() {
		h.mu.Lock()
		removed := false
		var closing []*activeRelay
		if h.sessions[sandbox] == s {
			delete(h.sessions, sandbox)
			closing = h.takeActiveRelaysLocked(sandbox)
			removed = true
		}
		h.mu.Unlock()
		s.close()
		if removed {
			closeActiveRelays(closing)
		}
	}, nil
}

// RenewSupervisorOwner extends the ownership lease on a valid supervisor
// heartbeat. Leases are process-local; deployments requiring upstream HA
// semantics must persist them in shared storage.
func (h *Hub) RenewSupervisorOwner(sandbox, instanceID string, connectionEpoch uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	owner, ok := h.owners[sandbox]
	if !ok || owner.instanceID != instanceID || owner.epoch != connectionEpoch {
		return false
	}
	owner.expiresAt = time.Now().Add(supervisorOwnerTTL)
	h.owners[sandbox] = owner
	return true
}

// ReleaseSupervisor removes an owner lease after an explicit sandbox stop.
// Unexpected stream loss keeps its lease so transient reconnects remain safe.
func (h *Hub) ReleaseSupervisor(sandbox string) {
	if h == nil || sandbox == "" {
		return
	}
	h.mu.Lock()
	s := h.sessions[sandbox]
	delete(h.owners, sandbox)
	delete(h.sessions, sandbox)
	closing := h.takeActiveRelaysLocked(sandbox)
	h.mu.Unlock()
	if s != nil {
		s.close()
	}
	closeActiveRelays(closing)
}

// ReleaseSupervisorClaim removes a claim rejected by a durable owner index.
// It acts only on the exact local session so a stale rejection cannot evict a
// newer reconnect that has already replaced it.
func (h *Hub) ReleaseSupervisorClaim(sandbox, instanceID string, connectionEpoch uint64) bool {
	if h == nil || sandbox == "" || instanceID == "" || connectionEpoch == 0 {
		return false
	}
	h.mu.Lock()
	s := h.sessions[sandbox]
	if s == nil || s.instanceID != instanceID || s.connectionEpoch != connectionEpoch {
		h.mu.Unlock()
		return false
	}
	delete(h.sessions, sandbox)
	if owner := h.owners[sandbox]; owner.instanceID == instanceID && owner.epoch == connectionEpoch {
		delete(h.owners, sandbox)
	}
	closing := h.takeActiveRelaysLocked(sandbox)
	h.mu.Unlock()
	s.close()
	closeActiveRelays(closing)
	return true
}

// SupervisorInstance returns the instance ID for the currently
// connected pinned OpenShell control stream.
func (h *Hub) SupervisorInstance(sandbox string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[sandbox]
	if !ok || s.instanceID == "" {
		return "", false
	}
	return s.instanceID, true
}

// AcceptRelay claims a pending channel and returns the stream side of
// a byte pipe. OpenChannel receives the other side after the claim succeeds.
func (h *Hub) AcceptRelay(sandbox, channel string) (net.Conn, error) {
	h.mu.Lock()
	p := h.pending[channel]
	if p == nil || p.sandbox != sandbox {
		h.mu.Unlock()
		return nil, ErrOpenTimeout
	}
	delete(h.pending, channel)
	client, stream := newHalfPipePair()
	if h.active == nil {
		h.active = map[string]*activeRelay{}
	}
	h.active[channel] = &activeRelay{sandbox: sandbox, client: client, stream: stream}
	h.mu.Unlock()
	select {
	case p.ready <- client:
		return stream, nil
	default:
		h.removeActiveRelay(channel, stream)
		_ = client.Close()
		_ = stream.Close()
		return nil, ErrOpenTimeout
	}
}

type activeRelay struct {
	sandbox string
	client  net.Conn
	stream  net.Conn
}

// CloseRelay aborts an active channel, or rejects a not-yet-opened
// channel. RelayClose is abortive: unlike CloseWrite it does not promise drain.
func (h *Hub) CloseRelay(sandbox, channel string, cause error) bool {
	if channel == "" {
		return false
	}
	if cause == nil {
		cause = ErrNotConnected
	}
	h.mu.Lock()
	active := h.active[channel]
	if active != nil && active.sandbox == sandbox {
		delete(h.active, channel)
	} else {
		active = nil
	}
	p := h.pending[channel]
	if p != nil && p.sandbox == sandbox {
		delete(h.pending, channel)
	} else {
		p = nil
	}
	h.mu.Unlock()
	if active != nil {
		_ = active.client.Close()
		_ = active.stream.Close()
	}
	if p != nil {
		select {
		case p.failed <- cause:
		default:
		}
	}
	return active != nil || p != nil
}

func (h *Hub) removeActiveRelay(channel string, stream net.Conn) {
	h.mu.Lock()
	if active := h.active[channel]; active != nil && active.stream == stream {
		delete(h.active, channel)
	}
	h.mu.Unlock()
}

func (h *Hub) takeActiveRelaysLocked(sandbox string) []*activeRelay {
	var closing []*activeRelay
	for channel, active := range h.active {
		if active.sandbox == sandbox {
			closing = append(closing, active)
			delete(h.active, channel)
		}
	}
	return closing
}

func closeActiveRelays(closing []*activeRelay) {
	for _, active := range closing {
		_ = active.client.Close()
		_ = active.stream.Close()
	}
}

type pending struct {
	sandbox         string
	instanceID      string
	connectionEpoch uint64
	ready           chan net.Conn
	failed          chan error
	openedAt        time.Time
}

// RejectRelay completes a pending OpenChannel request when the
// supervisor rejects the requested target.
func (h *Hub) RejectRelay(sandbox, channel string, cause error) {
	h.mu.Lock()
	p := h.pending[channel]
	if p != nil && p.sandbox == sandbox {
		delete(h.pending, channel)
	} else {
		p = nil
	}
	h.mu.Unlock()
	if p != nil {
		if cause == nil {
			cause = ErrNotConnected
		}
		select {
		case p.failed <- cause:
		default:
		}
	}
}

// NewHub returns a hub with OpenShell-aligned keepalive defaults.
func NewHub() *Hub {
	return &Hub{
		OpenTimeout: defaultOpenTimeout,
		sessions:    map[string]*session{},
		pending:     map[string]*pending{},
		active:      map[string]*activeRelay{},
	}
}

func (h *Hub) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Connected reports whether sandbox has a live supervisor control stream.
func (h *Hub) Connected(sandbox string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.sessions[sandbox]
	return ok
}

// SupervisorSession returns the currently connected local owner identity.
func (h *Hub) SupervisorSession(sandbox string) (string, uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[sandbox]
	if s == nil {
		return "", 0, false
	}
	return s.instanceID, s.connectionEpoch, true
}

// PendingSupervisorSession returns the owner that opened a pending relay.
func (h *Hub) PendingSupervisorSession(sandbox, channel string) (string, uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pending[channel]
	if p == nil || p.sandbox != sandbox {
		return "", 0, false
	}
	return p.instanceID, p.connectionEpoch, true
}

// WaitConnected blocks until the sandbox supervisor has registered its control
// stream. A running container alone is not sufficient readiness for relay RPCs.
func (h *Hub) WaitConnected(ctx context.Context, sandbox string, timeout time.Duration) error {
	if h == nil {
		return ErrNotConnected
	}
	if timeout <= 0 {
		timeout = defaultOpenTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if h.Connected(sandbox) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrNotConnected
		case <-ticker.C:
		}
	}
}

// Disconnect drops the supervisor session for sandbox (e.g. on delete).
func (h *Hub) Disconnect(sandbox string) {
	h.mu.Lock()
	s := h.sessions[sandbox]
	delete(h.sessions, sandbox)
	closing := h.takeActiveRelaysLocked(sandbox)
	h.mu.Unlock()
	if s != nil {
		s.close()
	}
	closeActiveRelays(closing)
}

// OpenChannel asks the sandbox supervisor for a new data stream to target and
// returns it once the supervisor dials back.
func (h *Hub) OpenChannel(ctx context.Context, sandbox, target string) (net.Conn, error) {
	id, err := newChannelID()
	if err != nil {
		return nil, err
	}
	p := &pending{sandbox: sandbox, ready: make(chan net.Conn, 1), failed: make(chan error, 1), openedAt: time.Now()}
	h.mu.Lock()
	s := h.sessions[sandbox]
	if s == nil {
		h.mu.Unlock()
		return nil, ErrNotConnected
	}
	p.instanceID = s.instanceID
	p.connectionEpoch = s.connectionEpoch
	if len(h.pending) >= maxPendingRelays {
		h.relayRejectedReplica++
		h.mu.Unlock()
		return nil, ErrReplicaCapacity
	}
	pendingForSandbox := 0
	for _, item := range h.pending {
		if item.sandbox == sandbox {
			pendingForSandbox++
		}
	}
	if pendingForSandbox >= maxPendingRelaysPerSandbox {
		h.relayRejectedSandbox++
		h.mu.Unlock()
		return nil, ErrSandboxCapacity
	}
	h.pending[id] = p
	h.mu.Unlock()
	delivered := false
	defer func() {
		h.mu.Lock()
		delete(h.pending, id)
		h.mu.Unlock()
		if !delivered {
			select {
			case c := <-p.ready:
				_ = c.Close()
			default:
			}
		}
	}()
	var openErr error
	if s.open == nil {
		openErr = ErrNotConnected
	} else {
		openErr = s.open(id, target)
	}
	if openErr != nil {
		s.close()
		return nil, fmt.Errorf("%w: %w", ErrNotConnected, openErr)
	}
	timeout := h.OpenTimeout
	if timeout <= 0 {
		timeout = defaultOpenTimeout
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case c := <-p.ready:
		h.recordRelayClaim(time.Since(p.openedAt))
		delivered = true
		return c, nil
	case err := <-p.failed:
		return nil, err
	case <-s.done:
		return nil, ErrNotConnected
	case <-t.C:
		h.mu.Lock()
		h.relayExpired++
		h.mu.Unlock()
		return nil, ErrOpenTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Hub) recordRelayClaim(waited time.Duration) {
	seconds := waited.Seconds()
	h.mu.Lock()
	h.relayClaimCount++
	h.relayClaimSumSeconds += seconds
	for i, bound := range relayClaimDurationBuckets {
		if seconds <= bound {
			h.relayClaimBuckets[i]++
		}
	}
	h.mu.Unlock()
}

func newChannelID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Bridge copies bytes bidirectionally until either side closes.
func Bridge(client, supervisor io.ReadWriteCloser) error {
	return relayproto.Pipe(client, supervisor)
}
