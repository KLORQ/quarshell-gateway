// Package provider implements durable sandbox provider bindings and readiness.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const bindingKind = "provider_binding"

// Readiness is the provider installation state for one binding revision.
type Readiness string

const (
	ReadinessPending Readiness = "pending"
	ReadinessReady   Readiness = "ready"
	ReadinessFailed  Readiness = "failed"
)

// Binding is one provider attached to a sandbox generation.
type Binding struct {
	Sandbox   domain.SandboxRef `json:"sandbox"`
	Provider  domain.ProviderID `json:"provider"`
	Revision  uint64            `json:"revision"`
	Config    []byte            `json:"config,omitempty"`
	Readiness Readiness         `json:"readiness"`
	Error     string            `json:"error,omitempty"`
	AckedAt   *time.Time        `json:"acked_at,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// BindRequest attaches or updates a provider revision.
type BindRequest struct {
	Sandbox        domain.SandboxRef
	Provider       domain.ProviderID
	Revision       uint64
	Config         []byte
	IdempotencyKey domain.OperationID
}

// Service owns provider bindings.
type Service struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
}

// NewService returns a provider binding service.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("provider.service", "store is required")
	}
	return &Service{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// Bind creates or updates a provider binding. A newer revision resets readiness.
func (s *Service) Bind(ctx context.Context, request BindRequest) (Binding, bool, error) {
	if !request.Sandbox.Valid() || request.Provider == "" || request.Revision == 0 {
		return Binding{}, false, domain.Invalidf("provider.bind", "sandbox, provider and revision are required")
	}
	if len(request.Config) > 0 && !json.Valid(request.Config) {
		return Binding{}, false, domain.Invalidf("provider.bind", "config must be valid JSON")
	}
	key := strings.TrimSpace(string(request.IdempotencyKey))
	if key == "" {
		key = "provider.bind:" + bindingID(request.Sandbox, request.Provider) + ":" + uintString(request.Revision)
	} else {
		key = "provider.bind:" + key
	}
	hash := digest(bindingID(request.Sandbox, request.Provider) + ":" + uintString(request.Revision))
	now := s.now().UTC()
	result, replayed, err := s.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		existing, exists, err := tx.Get(bindingKind, bindingID(request.Sandbox, request.Provider))
		if err != nil {
			return nil, err
		}
		if exists {
			var current Binding
			if err := json.Unmarshal(existing.Payload, &current); err != nil {
				return nil, err
			}
			if current.Revision > request.Revision {
				return nil, domain.New(domain.CodeConflict, "provider.bind", "stale provider revision")
			}
			if current.Revision == request.Revision {
				return existing.Payload, nil
			}
		}
		binding := Binding{
			Sandbox: request.Sandbox, Provider: request.Provider, Revision: request.Revision,
			Config: append([]byte(nil), request.Config...), Readiness: ReadinessPending,
			CreatedAt: now, UpdatedAt: now,
		}
		version := uint64(0)
		if exists {
			var current Binding
			_ = json.Unmarshal(existing.Payload, &current)
			binding.CreatedAt = current.CreatedAt
			version = existing.Version
		}
		payload, err := json.Marshal(binding)
		if err != nil {
			return nil, domain.Wrap(err, "provider.bind", "encode binding")
		}
		if _, err := tx.Put(bindingKind, bindingID(request.Sandbox, request.Provider), version, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: bindingID(request.Sandbox, request.Provider) + ":bind:" + uintString(request.Revision), Topic: "provider.binding.updated", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Binding{}, false, err
	}
	var binding Binding
	if err := json.Unmarshal(result, &binding); err != nil {
		return Binding{}, false, domain.Wrap(err, "provider.bind", "decode binding")
	}
	return binding, replayed, nil
}

// Ack marks the current revision ready.
func (s *Service) Ack(ctx context.Context, sandbox domain.SandboxRef, providerID domain.ProviderID, revision uint64) (Binding, error) {
	return s.transition(ctx, sandbox, providerID, revision, ReadinessReady, "")
}

// Fail marks the current revision failed.
func (s *Service) Fail(ctx context.Context, sandbox domain.SandboxRef, providerID domain.ProviderID, revision uint64, reason string) (Binding, error) {
	return s.transition(ctx, sandbox, providerID, revision, ReadinessFailed, reason)
}

func (s *Service) transition(ctx context.Context, sandbox domain.SandboxRef, providerID domain.ProviderID, revision uint64, readiness Readiness, reason string) (Binding, error) {
	var result Binding
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(bindingKind, bindingID(sandbox, providerID))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "provider.transition", "provider binding not found")
		}
		var binding Binding
		if err := json.Unmarshal(record.Payload, &binding); err != nil {
			return err
		}
		if binding.Revision != revision {
			return domain.New(domain.CodeConflict, "provider.transition", "provider revision is not current")
		}
		binding.Readiness = readiness
		binding.Error = redact(reason)
		binding.UpdatedAt = s.now().UTC()
		if readiness == ReadinessReady {
			acked := binding.UpdatedAt
			binding.AckedAt = &acked
		}
		payload, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		if _, err := tx.Put(bindingKind, bindingID(sandbox, providerID), record.Version, payload); err != nil {
			return err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: bindingID(sandbox, providerID) + ":ready:" + uintString(revision), Topic: "provider.readiness." + string(readiness), Payload: payload}); err != nil {
			return err
		}
		result = binding
		return nil
	})
	return result, err
}

// Get returns one binding.
func (s *Service) Get(ctx context.Context, sandbox domain.SandboxRef, providerID domain.ProviderID) (Binding, error) {
	var payload []byte
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(bindingKind, bindingID(sandbox, providerID))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "provider.get", "provider binding not found")
		}
		payload = record.Payload
		return nil
	})
	if err != nil {
		return Binding{}, err
	}
	var binding Binding
	if err := json.Unmarshal(payload, &binding); err != nil {
		return Binding{}, domain.Wrap(err, "provider.get", "decode binding")
	}
	return binding, nil
}

// List returns bindings for one sandbox sorted by provider ID.
func (s *Service) List(ctx context.Context, sandbox domain.SandboxRef) ([]Binding, error) {
	var result []Binding
	prefix := bindingID(sandbox, "")
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(bindingKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) || strings.TrimPrefix(record.ID, prefix) == "" {
				continue
			}
			var binding Binding
			if err := json.Unmarshal(record.Payload, &binding); err != nil {
				return err
			}
			result = append(result, binding)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Provider < result[right].Provider })
	return result, nil
}

// Unbind removes a binding idempotently.
func (s *Service) Unbind(ctx context.Context, sandbox domain.SandboxRef, providerID domain.ProviderID, key domain.OperationID) error {
	operationKey := "provider.unbind:" + bindingID(sandbox, providerID) + ":" + strings.TrimSpace(string(key))
	if strings.TrimSpace(string(key)) == "" {
		operationKey = "provider.unbind:" + bindingID(sandbox, providerID)
	}
	hash := digest(bindingID(sandbox, providerID))
	_, _, err := s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(bindingKind, bindingID(sandbox, providerID))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(bindingKind, bindingID(sandbox, providerID), record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: operationKey + ":removed", Topic: "provider.binding.removed", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

func bindingID(sandbox domain.SandboxRef, providerID domain.ProviderID) string {
	return string(sandbox.Workspace) + "/" + string(sandbox.Sandbox) + "/" + string(providerID)
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func uintString(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func redact(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 512 {
		reason = reason[:512]
	}
	return reason
}
