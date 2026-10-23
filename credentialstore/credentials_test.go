package credentialstore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func newTestBroker(t *testing.T, now func() time.Time) (*MemoryStore, *Broker) {
	t.Helper()
	store, err := NewMemoryStore([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	broker, err := NewBroker(store, now)
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return store, broker
}

func testSecret() Secret {
	return Secret{
		ID:        "cred-1",
		Provider:  "github",
		Material:  []byte("super-secret-token"),
		ExpiresAt: time.Now().Add(time.Hour),
		Endpoint:  EndpointBinding{Scheme: "https", Host: "api.github.com", Port: 443, Method: "GET", PathPrefix: "/repos"},
	}
}

func TestBrokerIssueResolveStable(t *testing.T) {
	store, broker := newTestBroker(t, nil)
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	sandbox := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	request := IssueRequest{
		Credential: "cred-1", Sandbox: sandbox, StableKey: "stable",
		Endpoint: EndpointBinding{Scheme: "https", Host: "api.github.com", Port: 443, Method: "GET", PathPrefix: "/repos"},
	}
	first, info, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	second, _, err := broker.Issue(context.Background(), request)
	if err != nil || second != first {
		t.Fatalf("stable handle = %q/%q err=%v", first, second, err)
	}
	material, resolved, err := broker.Resolve(context.Background(), first, request.Endpoint)
	if err != nil || !bytes.Equal(material, []byte("super-secret-token")) {
		t.Fatalf("Resolve = %q %+v %v", material, resolved, err)
	}
	if info.Provider != "github" {
		t.Fatalf("info = %+v", info)
	}
}

func TestBrokerRejectsWrongEndpointAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store, broker := newTestBroker(t, func() time.Time { return now })
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	request := IssueRequest{
		Credential: "cred-1",
		Sandbox:    domain.SandboxRef{Workspace: "ws", Sandbox: "sb"},
		Endpoint:   EndpointBinding{Scheme: "https", Host: "api.github.com", Port: 443, Method: "GET"},
		TTL:        time.Minute,
	}
	handle, _, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	wrong := request.Endpoint
	wrong.Host = "evil.example.com"
	if _, _, err := broker.Resolve(context.Background(), handle, wrong); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("wrong endpoint = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, _, err := broker.Resolve(context.Background(), handle, request.Endpoint); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expired = %v", err)
	}
}

func TestBrokerRotateInvalidatesHandles(t *testing.T) {
	store, broker := newTestBroker(t, nil)
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	request := IssueRequest{Credential: "cred-1", Sandbox: domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, Endpoint: testSecret().Endpoint}
	handle, _, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	revision, err := broker.Rotate(context.Background(), "cred-1", []byte("new-token"), time.Now().Add(time.Hour))
	if err != nil || revision != 2 {
		t.Fatalf("Rotate = %d %v", revision, err)
	}
	if _, _, err := broker.Resolve(context.Background(), handle, request.Endpoint); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old handle = %v", err)
	}
	newHandle, _, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue new: %v", err)
	}
	material, _, err := broker.Resolve(context.Background(), newHandle, request.Endpoint)
	if err != nil || string(material) != "new-token" {
		t.Fatalf("new material = %q %v", material, err)
	}
}

type fakeRefresher struct {
	material []byte
	err      error
	block    bool
	started  chan struct{}
}

func (f *fakeRefresher) Refresh(ctx context.Context, _ Secret) ([]byte, time.Time, error) {
	if f.started != nil {
		close(f.started)
	}
	if f.block {
		<-ctx.Done()
		return nil, time.Time{}, ctx.Err()
	}
	return f.material, time.Now().Add(time.Hour), f.err
}

func TestRefreshRotatesAndInvalidates(t *testing.T) {
	store, broker := newTestBroker(t, nil)
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	request := IssueRequest{Credential: "cred-1", Sandbox: domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, Endpoint: testSecret().Endpoint}
	handle, _, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	service := &RefreshService{Store: store, Broker: broker, Refresher: &fakeRefresher{material: []byte("rotated")}, Timeout: time.Second}
	revision, err := service.Refresh(context.Background(), "cred-1")
	if err != nil || revision != 2 {
		t.Fatalf("Refresh = %d %v", revision, err)
	}
	if _, _, err := broker.Resolve(context.Background(), handle, request.Endpoint); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old handle = %v", err)
	}
	secret, _ := store.Get(context.Background(), "cred-1")
	if string(secret.Material) != "rotated" {
		t.Fatalf("material = %q", secret.Material)
	}
}

func TestRefreshCancellationKeepsOldMaterial(t *testing.T) {
	store, broker := newTestBroker(t, nil)
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	started := make(chan struct{})
	service := &RefreshService{
		Store: store, Broker: broker, Timeout: time.Second,
		Refresher: &fakeRefresher{block: true, started: started},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	if _, err := service.Refresh(ctx, "cred-1"); !errors.Is(err, domain.ErrCanceled) {
		t.Fatalf("canceled refresh = %v", err)
	}
	secret, _ := store.Get(context.Background(), "cred-1")
	if string(secret.Material) != "super-secret-token" {
		t.Fatalf("material changed on cancel: %q", secret.Material)
	}
}

func TestRefreshTimeoutAndBounds(t *testing.T) {
	store, broker := newTestBroker(t, nil)
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	service := &RefreshService{
		Store: store, Broker: broker, Timeout: 20 * time.Millisecond,
		Refresher: &fakeRefresher{material: []byte("late")},
	}
	service.Refresher = &fakeRefresher{material: nil, err: nil}
	// A refresher that ignores context still cannot hold the call past the deadline.
	service.Refresher = blockingRefresh{}
	if _, err := service.Refresh(context.Background(), "cred-1"); !errors.Is(err, domain.ErrDeadlineExceeded) {
		t.Fatalf("timeout = %v", err)
	}
	service.Refresher = &fakeRefresher{material: []byte(strings.Repeat("x", 64))}
	service.MaxMaterialBytes = 8
	if _, err := service.Refresh(context.Background(), "cred-1"); err == nil {
		t.Fatalf("oversized material accepted")
	}
}

type blockingRefresh struct{}

func (blockingRefresh) Refresh(context.Context, Secret) ([]byte, time.Time, error) {
	time.Sleep(200 * time.Millisecond)
	return []byte("late"), time.Now(), nil
}
