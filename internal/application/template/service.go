// Package template implements durable workspace workload templates.
package template

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const templateKind = "template"

// Template is one versioned workload template.
type Template struct {
	Workspace domain.WorkspaceID `json:"workspace"`
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Spec      []byte             `json:"spec,omitempty"`
	Revision  uint64             `json:"revision"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// Service owns templates.
type Service struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
}

// NewService returns a template service.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("template.service", "store is required")
	}
	return &Service{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// Create stores a new template.
func (s *Service) Create(ctx context.Context, workspace domain.WorkspaceID, id, name string, spec []byte, idempotencyKey domain.OperationID) (Template, bool, error) {
	if err := validate(workspace, id, name, spec); err != nil {
		return Template{}, false, err
	}
	key := strings.TrimSpace(string(idempotencyKey))
	if key == "" {
		key = "template.create:" + templateID(workspace, id) + ":" + digest(spec)[:16]
	} else {
		key = "template.create:" + key
	}
	now := s.now().UTC()
	result, replayed, err := s.coordinator.Execute(ctx, key, digest([]byte(templateID(workspace, id)+":"+name+":"+digest(spec))), func(tx lifecycle.WriteTx) ([]byte, error) {
		if _, exists, err := tx.Get(templateKind, templateID(workspace, id)); err != nil {
			return nil, err
		} else if exists {
			return nil, domain.New(domain.CodeConflict, "template.create", "template already exists")
		}
		template := Template{Workspace: workspace, ID: id, Name: name, Spec: append([]byte(nil), spec...), Revision: 1, CreatedAt: now, UpdatedAt: now}
		payload, err := json.Marshal(template)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(templateKind, templateID(workspace, id), 0, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: templateID(workspace, id) + ":created", Topic: "template.created", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Template{}, false, err
	}
	var template Template
	if err := json.Unmarshal(result, &template); err != nil {
		return Template{}, false, err
	}
	return template, replayed, nil
}

// Update replaces a template at the expected revision.
func (s *Service) Update(ctx context.Context, workspace domain.WorkspaceID, id, name string, spec []byte, expectedRevision uint64, idempotencyKey domain.OperationID) (Template, error) {
	if err := validate(workspace, id, name, spec); err != nil {
		return Template{}, err
	}
	if expectedRevision == 0 {
		return Template{}, domain.Invalidf("template.update", "expected revision is required")
	}
	key := strings.TrimSpace(string(idempotencyKey))
	if key == "" {
		key = "template.update:" + templateID(workspace, id) + ":" + digest(spec)[:16]
	} else {
		key = "template.update:" + key
	}
	now := s.now().UTC()
	result, _, err := s.coordinator.Execute(ctx, key, digest([]byte(templateID(workspace, id)+":"+name+":"+digest(spec))), func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(templateKind, templateID(workspace, id))
		if err != nil {
			return nil, err
		}
		if !exists || record.Version != expectedRevision {
			return nil, domain.New(domain.CodeConflict, "template.update", "template revision conflict")
		}
		var template Template
		if err := json.Unmarshal(record.Payload, &template); err != nil {
			return nil, err
		}
		template.Name = name
		template.Spec = append([]byte(nil), spec...)
		template.Revision = expectedRevision + 1
		template.UpdatedAt = now
		payload, err := json.Marshal(template)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(templateKind, templateID(workspace, id), expectedRevision, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: templateID(workspace, id) + ":updated:" + uintString(template.Revision), Topic: "template.updated", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Template{}, err
	}
	var template Template
	if err := json.Unmarshal(result, &template); err != nil {
		return Template{}, err
	}
	return template, nil
}

// Get returns one template.
func (s *Service) Get(ctx context.Context, workspace domain.WorkspaceID, id string) (Template, error) {
	var template Template
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(templateKind, templateID(workspace, id))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "template.get", "template not found")
		}
		return json.Unmarshal(record.Payload, &template)
	})
	return template, err
}

// List returns templates for one workspace sorted by ID.
func (s *Service) List(ctx context.Context, workspace domain.WorkspaceID) ([]Template, error) {
	var result []Template
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(templateKind)
		if err != nil {
			return err
		}
		prefix := string(workspace) + "/"
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			var template Template
			if err := json.Unmarshal(record.Payload, &template); err != nil {
				return err
			}
			result = append(result, template)
		}
		return nil
	})
	return result, err
}

// Delete removes a template idempotently.
func (s *Service) Delete(ctx context.Context, workspace domain.WorkspaceID, id string, idempotencyKey domain.OperationID) error {
	key := strings.TrimSpace(string(idempotencyKey))
	if key == "" {
		key = "template.delete:" + templateID(workspace, id)
	} else {
		key = "template.delete:" + key
	}
	_, _, err := s.coordinator.Execute(ctx, key, digest([]byte(templateID(workspace, id))), func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(templateKind, templateID(workspace, id))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(templateKind, templateID(workspace, id), record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":removed", Topic: "template.deleted", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

func validate(workspace domain.WorkspaceID, id, name string, spec []byte) error {
	if !workspace.Valid() || strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" || strings.Contains(id, "/") {
		return domain.Invalidf("template.validate", "workspace, id and name are required")
	}
	if len(spec) > 0 && !json.Valid(spec) {
		return domain.Invalidf("template.validate", "spec must be valid JSON")
	}
	return nil
}

func templateID(workspace domain.WorkspaceID, id string) string {
	return string(workspace) + "/" + id
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func uintString(value uint64) string {
	return strconv.FormatUint(value, 10)
}
