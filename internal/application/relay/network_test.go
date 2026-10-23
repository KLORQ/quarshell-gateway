package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
)

type fakeDialer struct {
	mu      sync.Mutex
	calls   int
	fail    bool
	servers []net.Conn
}

func (d *fakeDialer) Dial(context.Context) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.fail {
		return nil, errors.New("dial failed")
	}
	client, server := net.Pipe()
	d.servers = append(d.servers, server)
	return client, nil
}

func (d *fakeDialer) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *fakeDialer) CloseLatest() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.servers) > 0 {
		_ = d.servers[len(d.servers)-1].Close()
	}
}

func TestRelayReconnects(t *testing.T) {
	dialer := &fakeDialer{}
	log := eventlog.NewMemoryLog(100)
	relay, err := NewRelay(dialer, log)
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	relay.Backoff = func(int) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relay.Run(ctx) }()
	waitFor(t, func() bool { return relay.Status().Connected })
	dialer.CloseLatest()
	waitFor(t, func() bool { return dialer.Calls() >= 2 && relay.Status().Connected })
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("relay did not stop")
	}
	events, _, err := log.After(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("events = %d", len(events))
	}
}

func TestRelayRetriesDialErrors(t *testing.T) {
	dialer := &fakeDialer{fail: true}
	relay, _ := NewRelay(dialer, nil)
	relay.Backoff = func(int) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay.Run(ctx) }()
	waitFor(t, func() bool { return relay.Status().Attempts >= 2 })
	cancel()
	<-done
}

func TestNetworkRelayValidation(t *testing.T) {
	if _, err := NewRelay(nil, nil); err == nil {
		t.Fatalf("nil dialer accepted")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition was not met")
}
