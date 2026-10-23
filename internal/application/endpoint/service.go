// Package endpoint implements sandbox service exposure and port forwards.
package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const (
	serviceKind = "endpoint_service"
	forwardKind = "endpoint_forward"
)

// Service is one exposed sandbox service.
type Service struct {
	Sandbox   domain.SandboxRef `json:"sandbox"`
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	URL       string            `json:"url"`
	Port      uint16            `json:"port"`
	Protocol  string            `json:"protocol"`
	AuthMode  string            `json:"auth_mode,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Forward is one sandbox port forward.
type Forward struct {
	Sandbox    domain.SandboxRef `json:"sandbox"`
	ID         string            `json:"id"`
	LocalPort  uint16            `json:"local_port"`
	RemoteHost string            `json:"remote_host"`
	RemotePort uint16            `json:"remote_port"`
	Protocol   string            `json:"protocol"`
	CreatedAt  time.Time         `json:"created_at"`
}

type entryStore struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	kind        string
	now         func() time.Time
}

func newEntryStore(store lifecycle.Store, kind string) *entryStore {
	return &entryStore{store: store, coordinator: &lifecycle.Coordinator{Store: store}, kind: kind, now: time.Now}
}

func (e *entryStore) create(ctx context.Context, id string, payload []byte, key domain.OperationID) ([]byte, bool, error) {
	operationKey := strings.TrimSpace(string(key))
	if operationKey == "" {
		operationKey = e.kind + ".create:" + id
	} else {
		operationKey = e.kind + ".create:" + operationKey
	}
	return e.coordinator.Execute(ctx, operationKey, digest(id), func(tx lifecycle.WriteTx) ([]byte, error) {
		if _, exists, err := tx.Get(e.kind, id); err != nil {
			return nil, err
		} else if exists {
			return nil, domain.New(domain.CodeConflict, e.kind+".create", "entry already exists")
		}
		if _, err := tx.Put(e.kind, id, 0, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: id + ":created", Topic: e.kind + ".created", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
}

func (e *entryStore) get(ctx context.Context, id string) ([]byte, error) {
	var payload []byte
	err := e.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(e.kind, id)
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, e.kind+".get", "entry not found")
		}
		payload = record.Payload
		return nil
	})
	return payload, err
}

func (e *entryStore) list(ctx context.Context, prefix string) ([][]byte, error) {
	var result [][]byte
	err := e.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(e.kind)
		if err != nil {
			return err
		}
		for _, record := range records {
			if strings.HasPrefix(record.ID, prefix) {
				result = append(result, record.Payload)
			}
		}
		return nil
	})
	return result, err
}

func (e *entryStore) delete(ctx context.Context, id string, key domain.OperationID) error {
	operationKey := e.kind + ".delete:" + strings.TrimSpace(string(key))
	if strings.TrimSpace(string(key)) == "" {
		operationKey = e.kind + ".delete:" + id
	}
	_, _, err := e.coordinator.Execute(ctx, operationKey, digest(id), func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(e.kind, id)
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(e.kind, id, record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: operationKey + ":removed", Topic: e.kind + ".deleted", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

// ServiceRegistry exposes sandbox services.
type ServiceRegistry struct{ entries *entryStore }

// NewServiceRegistry returns a service registry.
func NewServiceRegistry(store lifecycle.Store) (*ServiceRegistry, error) {
	if store == nil {
		return nil, domain.Invalidf("endpoint.service", "store is required")
	}
	return &ServiceRegistry{entries: newEntryStore(store, serviceKind)}, nil
}

// Expose registers a sandbox service.
func (r *ServiceRegistry) Expose(ctx context.Context, sandbox domain.SandboxRef, id, name, rawURL string, port uint16, protocol, authMode string, key domain.OperationID) (Service, bool, error) {
	if !sandbox.Valid() || strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" || port == 0 {
		return Service{}, false, domain.Invalidf("endpoint.service", "sandbox, id, name and port are required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return Service{}, false, domain.Invalidf("endpoint.service", "url must be http(s)")
	}
	if authMode != "" && authMode != "strip" && authMode != "bearer" {
		return Service{}, false, domain.Invalidf("endpoint.service", "unknown auth mode")
	}
	service := Service{Sandbox: sandbox, ID: id, Name: name, URL: parsed.String(), Port: port, Protocol: protocol, AuthMode: authMode, CreatedAt: r.entries.now().UTC()}
	payload, err := json.Marshal(service)
	if err != nil {
		return Service{}, false, err
	}
	result, replayed, err := r.entries.create(ctx, entryID(sandbox, id), payload, key)
	if err != nil {
		return Service{}, false, err
	}
	if err := json.Unmarshal(result, &service); err != nil {
		return Service{}, false, err
	}
	return service, replayed, nil
}

// Get returns one service.
func (r *ServiceRegistry) Get(ctx context.Context, sandbox domain.SandboxRef, id string) (Service, error) {
	payload, err := r.entries.get(ctx, entryID(sandbox, id))
	if err != nil {
		return Service{}, err
	}
	var service Service
	if err := json.Unmarshal(payload, &service); err != nil {
		return Service{}, err
	}
	return service, nil
}

// List returns services for one sandbox.
func (r *ServiceRegistry) List(ctx context.Context, sandbox domain.SandboxRef) ([]Service, error) {
	payloads, err := r.entries.list(ctx, sandboxKey(sandbox)+"/")
	if err != nil {
		return nil, err
	}
	result := make([]Service, 0, len(payloads))
	for _, payload := range payloads {
		var service Service
		if err := json.Unmarshal(payload, &service); err != nil {
			return nil, err
		}
		result = append(result, service)
	}
	return result, nil
}

// Delete removes a service idempotently.
func (r *ServiceRegistry) Delete(ctx context.Context, sandbox domain.SandboxRef, id string, key domain.OperationID) error {
	return r.entries.delete(ctx, entryID(sandbox, id), key)
}

// ForwardRegistry manages sandbox port forwards.
type ForwardRegistry struct{ entries *entryStore }

// NewForwardRegistry returns a forward registry.
func NewForwardRegistry(store lifecycle.Store) (*ForwardRegistry, error) {
	if store == nil {
		return nil, domain.Invalidf("endpoint.forward", "store is required")
	}
	return &ForwardRegistry{entries: newEntryStore(store, forwardKind)}, nil
}

// Create registers a forward.
func (r *ForwardRegistry) Create(ctx context.Context, sandbox domain.SandboxRef, id string, localPort uint16, remoteHost string, remotePort uint16, protocol string, key domain.OperationID) (Forward, bool, error) {
	if !sandbox.Valid() || strings.TrimSpace(id) == "" || localPort == 0 || strings.TrimSpace(remoteHost) == "" || remotePort == 0 {
		return Forward{}, false, domain.Invalidf("endpoint.forward", "sandbox, id, ports and remote host are required")
	}
	forward := Forward{Sandbox: sandbox, ID: id, LocalPort: localPort, RemoteHost: remoteHost, RemotePort: remotePort, Protocol: protocol, CreatedAt: r.entries.now().UTC()}
	payload, err := json.Marshal(forward)
	if err != nil {
		return Forward{}, false, err
	}
	result, replayed, err := r.entries.create(ctx, entryID(sandbox, id), payload, key)
	if err != nil {
		return Forward{}, false, err
	}
	if err := json.Unmarshal(result, &forward); err != nil {
		return Forward{}, false, err
	}
	return forward, replayed, nil
}

// Get returns one forward.
func (r *ForwardRegistry) Get(ctx context.Context, sandbox domain.SandboxRef, id string) (Forward, error) {
	payload, err := r.entries.get(ctx, entryID(sandbox, id))
	if err != nil {
		return Forward{}, err
	}
	var forward Forward
	if err := json.Unmarshal(payload, &forward); err != nil {
		return Forward{}, err
	}
	return forward, nil
}

// List returns forwards for one sandbox.
func (r *ForwardRegistry) List(ctx context.Context, sandbox domain.SandboxRef) ([]Forward, error) {
	payloads, err := r.entries.list(ctx, sandboxKey(sandbox)+"/")
	if err != nil {
		return nil, err
	}
	result := make([]Forward, 0, len(payloads))
	for _, payload := range payloads {
		var forward Forward
		if err := json.Unmarshal(payload, &forward); err != nil {
			return nil, err
		}
		result = append(result, forward)
	}
	return result, nil
}

// Delete removes a forward idempotently.
func (r *ForwardRegistry) Delete(ctx context.Context, sandbox domain.SandboxRef, id string, key domain.OperationID) error {
	return r.entries.delete(ctx, entryID(sandbox, id), key)
}

func sandboxKey(sandbox domain.SandboxRef) string {
	return string(sandbox.Workspace) + "/" + string(sandbox.Sandbox)
}

func entryID(sandbox domain.SandboxRef, id string) string {
	return sandboxKey(sandbox) + "/" + id
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
