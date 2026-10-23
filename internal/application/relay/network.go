package relay

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
)

// Dialer opens one supervisor relay connection.
type Dialer interface {
	Dial(context.Context) (net.Conn, error)
}

// Status is a point-in-time relay state.
type Status struct {
	Connected   bool      `json:"connected"`
	Attempts    int       `json:"attempts"`
	LastError   string    `json:"last_error,omitempty"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
}

// Relay maintains one connection with bounded exponential reconnect.
type Relay struct {
	Dialer  Dialer
	Backoff func(attempt int) time.Duration
	Log     eventlog.Log

	mu     sync.Mutex
	status Status
	now    func() time.Time
}

// NewRelay returns a relay.
func NewRelay(dialer Dialer, log eventlog.Log) (*Relay, error) {
	if dialer == nil {
		return nil, domain.Invalidf("relay.network", "dialer is required")
	}
	return &Relay{Dialer: dialer, Log: log, now: time.Now}, nil
}

// Status returns the current state.
func (r *Relay) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// Run connects and reconnects until the context is canceled.
func (r *Relay) Run(ctx context.Context) error {
	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		connection, err := r.Dialer.Dial(ctx)
		if err != nil {
			attempt++
			r.setDisconnected(attempt, "dial failed")
			r.emit(ctx, "relay.dial_failed")
			if err := sleep(ctx, r.backoff(attempt)); err != nil {
				return err
			}
			continue
		}
		attempt = 0
		r.setConnected()
		r.emit(ctx, "relay.connected")
		closed := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, connection)
			close(closed)
		}()
		select {
		case <-ctx.Done():
			_ = connection.Close()
			return ctx.Err()
		case <-closed:
			_ = connection.Close()
			r.setDisconnected(0, "connection closed")
			r.emit(ctx, "relay.disconnected")
		}
		if err := sleep(ctx, r.backoff(1)); err != nil {
			return err
		}
	}
}

func (r *Relay) setConnected() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = Status{Connected: true, ConnectedAt: r.now().UTC()}
}

func (r *Relay) setDisconnected(attempts int, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.Connected = false
	r.status.Attempts = attempts
	r.status.LastError = reason
}

func (r *Relay) backoff(attempt int) time.Duration {
	if r.Backoff != nil {
		return r.Backoff(attempt)
	}
	duration := time.Second
	for index := 1; index < attempt && duration < 30*time.Second; index++ {
		duration *= 2
	}
	if duration > 30*time.Second {
		duration = 30 * time.Second
	}
	return duration
}

func (r *Relay) emit(ctx context.Context, kind string) {
	if r.Log == nil {
		return
	}
	_, _ = r.Log.Append(ctx, "relay", kind, nil)
}

func sleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
