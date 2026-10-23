// Package workspace implements durable workspace and membership use cases on
// top of the lifecycle store.
package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const (
	workspaceKind = "workspace"
	memberKind    = "workspace_member"
)

// Role is a workspace membership role.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// Action is an authorization request.
type Action string

const (
	ActionRead   Action = "read"
	ActionWrite  Action = "write"
	ActionManage Action = "manage"
)

// Workspace is the durable workspace record.
type Workspace struct {
	ID        domain.WorkspaceID `json:"id"`
	Name      string             `json:"name"`
	Labels    map[string]string  `json:"labels,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// Member is one workspace membership.
type Member struct {
	Workspace domain.WorkspaceID `json:"workspace"`
	Subject   string             `json:"subject"`
	Role      Role               `json:"role"`
	AddedAt   time.Time          `json:"added_at"`
}

// CreateRequest creates a workspace and its owner membership.
type CreateRequest struct {
	ID             domain.WorkspaceID
	Name           string
	Labels         map[string]string
	Owner          string
	IdempotencyKey domain.OperationID
}

// Service owns workspace mutations and reads.
type Service struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
}

// NewService returns a workspace service.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("workspace.service", "store is required")
	}
	return &Service{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// Create is idempotent per key.
func (s *Service) Create(ctx context.Context, request CreateRequest) (Workspace, bool, error) {
	if !request.ID.Valid() || strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.Owner) == "" {
		return Workspace{}, false, domain.Invalidf("workspace.create", "id, name and owner are required")
	}
	key, hash, err := createIdentity(request)
	if err != nil {
		return Workspace{}, false, err
	}
	now := s.now().UTC()
	created := Workspace{ID: request.ID, Name: request.Name, Labels: cloneLabels(request.Labels), CreatedAt: now, UpdatedAt: now}
	payload, err := json.Marshal(created)
	if err != nil {
		return Workspace{}, false, domain.Wrap(err, "workspace.create", "encode workspace")
	}
	owner := Member{Workspace: request.ID, Subject: request.Owner, Role: RoleOwner, AddedAt: now}
	memberPayload, err := json.Marshal(owner)
	if err != nil {
		return Workspace{}, false, domain.Wrap(err, "workspace.create", "encode owner")
	}
	result, replayed, err := s.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		if _, exists, err := tx.Get(workspaceKind, string(request.ID)); err != nil {
			return nil, err
		} else if exists {
			return nil, domain.New(domain.CodeConflict, "workspace.create", "workspace already exists")
		}
		if _, err := tx.Put(workspaceKind, string(request.ID), 0, payload); err != nil {
			return nil, err
		}
		if _, err := tx.Put(memberKind, memberKey(request.ID, request.Owner), 0, memberPayload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":created", Topic: "workspace.created", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Workspace{}, false, err
	}
	var stored Workspace
	if err := json.Unmarshal(result, &stored); err != nil {
		return Workspace{}, false, domain.Wrap(err, "workspace.create", "decode workspace")
	}
	return stored, replayed, nil
}

// Get returns a workspace.
func (s *Service) Get(ctx context.Context, id domain.WorkspaceID) (Workspace, error) {
	if !id.Valid() {
		return Workspace{}, domain.Invalidf("workspace.get", "workspace id is invalid")
	}
	var payload []byte
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(workspaceKind, string(id))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "workspace.get", "workspace not found")
		}
		payload = record.Payload
		return nil
	})
	if err != nil {
		return Workspace{}, err
	}
	var stored Workspace
	if err := json.Unmarshal(payload, &stored); err != nil {
		return Workspace{}, domain.Wrap(err, "workspace.get", "decode workspace")
	}
	return stored, nil
}

// List returns workspaces sorted by ID.
func (s *Service) List(ctx context.Context) ([]Workspace, error) {
	var result []Workspace
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(workspaceKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			var workspace Workspace
			if err := json.Unmarshal(record.Payload, &workspace); err != nil {
				return domain.Wrap(err, "workspace.list", "decode workspace")
			}
			result = append(result, workspace)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result, nil
}

// Delete removes a workspace and its members.
func (s *Service) Delete(ctx context.Context, id domain.WorkspaceID, key domain.OperationID) error {
	if !id.Valid() {
		return domain.Invalidf("workspace.delete", "workspace id is invalid")
	}
	operationKey := "workspace.delete:" + strings.TrimSpace(string(key))
	if strings.TrimSpace(string(key)) == "" {
		operationKey = "workspace.delete:" + string(id)
	}
	hash := digest(string(id))
	_, _, err := s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(workspaceKind, string(id))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(workspaceKind, string(id), record.Version); err != nil {
			return nil, err
		}
		members, err := tx.List(memberKind)
		if err != nil {
			return nil, err
		}
		for _, member := range members {
			if strings.HasPrefix(member.ID, string(id)+"/") {
				_ = tx.Delete(memberKind, member.ID, member.Version)
			}
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: operationKey + ":deleted", Topic: "workspace.deleted", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

// AddMember adds or updates a membership.
func (s *Service) AddMember(ctx context.Context, workspaceID domain.WorkspaceID, subject string, role Role, key domain.OperationID) (Member, bool, error) {
	if !workspaceID.Valid() || strings.TrimSpace(subject) == "" || !validRole(role) {
		return Member{}, false, domain.Invalidf("workspace.member", "workspace, subject and role are required")
	}
	if _, err := s.Get(ctx, workspaceID); err != nil {
		return Member{}, false, err
	}
	operationKey := "workspace.member:" + strings.TrimSpace(string(key))
	if strings.TrimSpace(string(key)) == "" {
		operationKey = "workspace.member:" + string(workspaceID) + "/" + subject + "/" + string(role)
	}
	hash := digest(string(workspaceID) + "/" + subject + "/" + string(role))
	member := Member{Workspace: workspaceID, Subject: subject, Role: role, AddedAt: s.now().UTC()}
	payload, err := json.Marshal(member)
	if err != nil {
		return Member{}, false, domain.Wrap(err, "workspace.member", "encode member")
	}
	result, replayed, err := s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		existing, exists, err := tx.Get(memberKind, memberKey(workspaceID, subject))
		if err != nil {
			return nil, err
		}
		if exists {
			var current Member
			if err := json.Unmarshal(existing.Payload, &current); err != nil {
				return nil, err
			}
			if current.Role != role {
				return nil, domain.New(domain.CodeConflict, "workspace.member", "member already has a different role")
			}
			return existing.Payload, nil
		}
		if _, err := tx.Put(memberKind, memberKey(workspaceID, subject), 0, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: operationKey + ":added", Topic: "workspace.member.added", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Member{}, false, err
	}
	var stored Member
	if err := json.Unmarshal(result, &stored); err != nil {
		return Member{}, false, domain.Wrap(err, "workspace.member", "decode member")
	}
	return stored, replayed, nil
}

// RemoveMember removes a membership idempotently.
func (s *Service) RemoveMember(ctx context.Context, workspaceID domain.WorkspaceID, subject string, key domain.OperationID) error {
	operationKey := "workspace.member.remove:" + strings.TrimSpace(string(key))
	if strings.TrimSpace(string(key)) == "" {
		operationKey = "workspace.member.remove:" + string(workspaceID) + "/" + subject
	}
	hash := digest(string(workspaceID) + "/" + subject)
	_, _, err := s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(memberKind, memberKey(workspaceID, subject))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(memberKind, memberKey(workspaceID, subject), record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: operationKey + ":removed", Topic: "workspace.member.removed", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

// ListMembers returns members of one workspace sorted by subject.
func (s *Service) ListMembers(ctx context.Context, workspaceID domain.WorkspaceID) ([]Member, error) {
	var result []Member
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(memberKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			if !strings.HasPrefix(record.ID, string(workspaceID)+"/") {
				continue
			}
			var member Member
			if err := json.Unmarshal(record.Payload, &member); err != nil {
				return domain.Wrap(err, "workspace.members", "decode member")
			}
			result = append(result, member)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Subject < result[right].Subject })
	return result, nil
}

// Authorize checks a member role for an action.
func (s *Service) Authorize(ctx context.Context, workspaceID domain.WorkspaceID, subject string, action Action) error {
	var member Member
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(memberKind, memberKey(workspaceID, subject))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrPermissionDenied, "workspace.authorize", "subject is not a member")
		}
		return json.Unmarshal(record.Payload, &member)
	})
	if err != nil {
		return err
	}
	switch action {
	case ActionRead:
		if member.Role == RoleOwner || member.Role == RoleAdmin || member.Role == RoleMember || member.Role == RoleViewer {
			return nil
		}
	case ActionWrite:
		if member.Role == RoleOwner || member.Role == RoleAdmin || member.Role == RoleMember {
			return nil
		}
	case ActionManage:
		if member.Role == RoleOwner || member.Role == RoleAdmin {
			return nil
		}
	default:
		return domain.Invalidf("workspace.authorize", "unknown action")
	}
	return domain.Wrap(domain.ErrPermissionDenied, "workspace.authorize", "role does not allow this action")
}

func validRole(role Role) bool {
	return role == RoleOwner || role == RoleAdmin || role == RoleMember || role == RoleViewer
}

func memberKey(workspaceID domain.WorkspaceID, subject string) string {
	return string(workspaceID) + "/" + subject
}

func createIdentity(request CreateRequest) (string, string, error) {
	hashInput := struct {
		ID     domain.WorkspaceID `json:"id"`
		Name   string             `json:"name"`
		Labels map[string]string  `json:"labels"`
		Owner  string             `json:"owner"`
	}{request.ID, request.Name, request.Labels, request.Owner}
	hash, err := jsonHash(hashInput)
	if err != nil {
		return "", "", err
	}
	key := strings.TrimSpace(string(request.IdempotencyKey))
	if key == "" {
		key = "workspace.create:" + string(request.ID) + ":" + hash[:16]
	} else {
		key = "workspace.create:" + key
	}
	return key, hash, nil
}

func jsonHash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", domain.Wrap(err, "workspace.identity", "encode request")
	}
	return digest(string(encoded)), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
