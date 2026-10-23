// Package policy implements durable policy drafts and activation.
package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyengine "github.com/KLORQ/quarshell-policy"
	"github.com/KLORQ/quarshell-policy/prover"
)

const (
	revisionKind = "policy_revision"
	activeKind   = "policy_active"
)

// Status is a policy revision lifecycle state.
type Status string

const (
	StatusDraft      Status = "draft"
	StatusActive     Status = "active"
	StatusSuperseded Status = "superseded"
	StatusRejected   Status = "rejected"
)

// Scope selects a sandbox policy or the workspace-global policy when Sandbox is
// empty.
type Scope struct {
	Workspace domain.WorkspaceID
	Sandbox   domain.SandboxID
}

// Valid reports whether the scope is complete.
func (s Scope) Valid() bool {
	return s.Workspace.Valid() && (s.Sandbox == "" || s.Sandbox.Valid())
}

// Key is the durable scope key.
func (s Scope) Key() string {
	if s.Sandbox == "" {
		return string(s.Workspace)
	}
	return string(s.Workspace) + "/" + string(s.Sandbox)
}

// Revision is one immutable policy document revision.
type Revision struct {
	ID                 string             `json:"id"`
	Workspace          domain.WorkspaceID `json:"workspace"`
	Sandbox            domain.SandboxID   `json:"sandbox,omitempty"`
	Number             uint64             `json:"number"`
	Source             []byte             `json:"source"`
	Hash               string             `json:"hash"`
	Status             Status             `json:"status"`
	Author             string             `json:"author"`
	Approver           string             `json:"approver,omitempty"`
	ObservedGeneration domain.Generation  `json:"observed_generation,omitempty"`
	ObservedAt         *time.Time         `json:"observed_at,omitempty"`
	LoadError          string             `json:"load_error,omitempty"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

// DraftRequest creates one policy revision draft.
type DraftRequest struct {
	Scope          Scope
	Source         []byte
	Author         string
	IdempotencyKey domain.OperationID
}

// Service owns policy revisions.
type Service struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
	// Events optionally receives streaming revision events.
	Events eventlog.Log
}

// NewService returns a policy revision service.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("policy.service", "store is required")
	}
	return &Service{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// CreateDraft validates and stores a draft revision.
func (s *Service) CreateDraft(ctx context.Context, request DraftRequest) (Revision, bool, error) {
	if !request.Scope.Valid() || len(request.Source) == 0 || strings.TrimSpace(request.Author) == "" {
		return Revision{}, false, domain.Invalidf("policy.draft", "scope, source and author are required")
	}
	if err := validateSource(request.Source); err != nil {
		return Revision{}, false, err
	}
	hash := digest(request.Source)
	key := strings.TrimSpace(string(request.IdempotencyKey))
	if key == "" {
		key = "policy.draft:" + request.Scope.Key() + ":" + hash[:16]
	} else {
		key = "policy.draft:" + key
	}
	now := s.now().UTC()
	result, replayed, err := s.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		records, err := tx.List(revisionKind)
		if err != nil {
			return nil, err
		}
		prefix := request.Scope.Key() + "~"
		var number uint64
		for _, record := range records {
			if strings.HasPrefix(record.ID, prefix) {
				suffix := strings.TrimPrefix(record.ID, prefix)
				if parsed, err := strconv.ParseUint(suffix, 10, 64); err == nil && parsed > number {
					number = parsed
				}
			}
		}
		number++
		revision := Revision{
			ID: prefix + strconv.FormatUint(number, 10), Workspace: request.Scope.Workspace,
			Sandbox: request.Scope.Sandbox, Number: number, Source: append([]byte(nil), request.Source...),
			Hash: hash, Status: StatusDraft, Author: request.Author, CreatedAt: now, UpdatedAt: now,
		}
		payload, err := json.Marshal(revision)
		if err != nil {
			return nil, domain.Wrap(err, "policy.draft", "encode revision")
		}
		if _, err := tx.Put(revisionKind, revision.ID, 0, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: revision.ID + ":draft", Topic: "policy.draft.created", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Revision{}, false, err
	}
	var revision Revision
	if err := json.Unmarshal(result, &revision); err != nil {
		return Revision{}, false, domain.Wrap(err, "policy.draft", "decode revision")
	}
	if !replayed {
		s.emit(ctx, request.Scope, "policy.draft.created", revision)
	}
	return revision, replayed, nil
}

// Approve activates a draft and supersedes the previous active revision.
func (s *Service) Approve(ctx context.Context, scope Scope, revisionID, approver string, key domain.OperationID) (Revision, error) {
	if !scope.Valid() || revisionID == "" || strings.TrimSpace(approver) == "" {
		return Revision{}, domain.Invalidf("policy.approve", "scope, revision and approver are required")
	}
	operationKey := "policy.approve:" + revisionID + ":" + strings.TrimSpace(string(key))
	if strings.TrimSpace(string(key)) == "" {
		operationKey = "policy.approve:" + revisionID
	}
	hash := digest([]byte(revisionID + ":" + approver))
	result, replayed, err := s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		revision, revisionRecord, err := loadRevision(tx, revisionID)
		if err != nil {
			return nil, err
		}
		if !revisionMatchesScope(revision, scope) {
			return nil, domain.Invalidf("policy.approve", "revision does not belong to the scope")
		}
		if revision.Status != StatusDraft {
			return nil, domain.New(domain.CodeConflict, "policy.approve", "revision is not a draft")
		}
		activeVersion := uint64(0)
		if active, exists, err := tx.Get(activeKind, scope.Key()); err != nil {
			return nil, err
		} else if exists {
			activeVersion = active.Version
			var activeID string
			if err := json.Unmarshal(active.Payload, &activeID); err != nil {
				return nil, err
			}
			previous, previousRecord, err := loadRevision(tx, activeID)
			if err != nil {
				return nil, err
			}
			previous.Status = StatusSuperseded
			previous.UpdatedAt = s.now().UTC()
			payload, err := json.Marshal(previous)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Put(revisionKind, previous.ID, previousRecord.Version, payload); err != nil {
				return nil, err
			}
		}
		revision.Status = StatusActive
		revision.Approver = approver
		revision.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(revision)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(revisionKind, revision.ID, revisionRecord.Version, payload); err != nil {
			return nil, err
		}
		activePayload, _ := json.Marshal(revision.ID)
		if _, err := tx.Put(activeKind, scope.Key(), activeVersion, activePayload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: revision.ID + ":active", Topic: "policy.activated", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Revision{}, err
	}
	var revision Revision
	if err := json.Unmarshal(result, &revision); err != nil {
		return Revision{}, domain.Wrap(err, "policy.approve", "decode revision")
	}
	if !replayed {
		s.emit(ctx, scope, "policy.activated", revision)
	}
	return revision, nil
}

// Reject marks a draft rejected.
func (s *Service) Reject(ctx context.Context, scope Scope, revisionID, approver, reason string) (Revision, error) {
	if !scope.Valid() || revisionID == "" || strings.TrimSpace(approver) == "" {
		return Revision{}, domain.Invalidf("policy.reject", "scope, revision and approver are required")
	}
	var result Revision
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		revision, revisionRecord, err := loadRevision(tx, revisionID)
		if err != nil {
			return err
		}
		if !revisionMatchesScope(revision, scope) {
			return domain.Invalidf("policy.reject", "revision does not belong to the scope")
		}
		if revision.Status != StatusDraft {
			return domain.New(domain.CodeConflict, "policy.reject", "revision is not a draft")
		}
		revision.Status = StatusRejected
		revision.Approver = approver
		revision.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(revision)
		if err != nil {
			return err
		}
		if _, err := tx.Put(revisionKind, revision.ID, revisionRecord.Version, payload); err != nil {
			return err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: revision.ID + ":rejected", Topic: "policy.rejected", Payload: payload}); err != nil {
			return err
		}
		result = revision
		return nil
	})
	if err == nil {
		s.emit(ctx, scope, "policy.rejected", result)
	}
	return result, err
}

// Active returns the active revision for a scope.
func (s *Service) Active(ctx context.Context, scope Scope) (Revision, bool, error) {
	var activeID string
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(activeKind, scope.Key())
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		return json.Unmarshal(record.Payload, &activeID)
	})
	if err != nil {
		return Revision{}, false, err
	}
	if activeID == "" {
		return Revision{}, false, nil
	}
	var revision Revision
	err = s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(revisionKind, activeID)
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "policy.active", "active revision not found")
		}
		return json.Unmarshal(record.Payload, &revision)
	})
	return revision, err == nil, err
}

// List returns revisions for one scope, newest first.
func (s *Service) List(ctx context.Context, scope Scope) ([]Revision, error) {
	var result []Revision
	prefix := scope.Key() + "~"
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(revisionKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			var revision Revision
			if err := json.Unmarshal(record.Payload, &revision); err != nil {
				return err
			}
			result = append(result, revision)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Number > result[right].Number })
	return result, nil
}

func loadRevision(tx lifecycle.ReadTx, id string) (Revision, lifecycle.Record, error) {
	record, exists, err := tx.Get(revisionKind, id)
	if err != nil {
		return Revision{}, lifecycle.Record{}, err
	}
	if !exists {
		return Revision{}, lifecycle.Record{}, domain.Wrap(domain.ErrNotFound, "policy.revision", "revision not found")
	}
	var revision Revision
	if err := json.Unmarshal(record.Payload, &revision); err != nil {
		return Revision{}, lifecycle.Record{}, err
	}
	return revision, record, nil
}

func revisionMatchesScope(revision Revision, scope Scope) bool {
	return revision.Workspace == scope.Workspace && revision.Sandbox == scope.Sandbox
}

// Analysis is a policy risk and containment report.
type Analysis struct {
	RevisionID  string
	Risk        prover.RiskReport
	Containment prover.Report
}

// Analyze reports risk and containment against the active revision.
func (s *Service) Analyze(ctx context.Context, scope Scope, revisionID string) (Analysis, error) {
	revision, err := s.getRevision(ctx, revisionID)
	if err != nil {
		return Analysis{}, err
	}
	candidate, err := parsePolicy(revision.Source)
	if err != nil {
		return Analysis{}, err
	}
	analysis := Analysis{RevisionID: revisionID, Risk: prover.Analyze(candidate), Containment: prover.Report{Relation: prover.Within}}
	active, ok, err := s.Active(ctx, scope)
	if err != nil {
		return Analysis{}, err
	}
	if ok && active.ID != revisionID {
		activePolicy, err := parsePolicy(active.Source)
		if err != nil {
			return Analysis{}, err
		}
		analysis.Containment, _ = prover.Containment(prover.Query{Allowed: activePolicy, Requested: candidate})
	}
	return analysis, nil
}

// Observe records the runtime generation that activated a revision.
func (s *Service) Observe(ctx context.Context, scope Scope, revisionID string, generation domain.Generation) (Revision, error) {
	return s.ObserveStatus(ctx, scope, revisionID, generation, "")
}

// ObserveStatus records a runtime generation's policy load result.
func (s *Service) ObserveStatus(ctx context.Context, scope Scope, revisionID string, generation domain.Generation, loadError string) (Revision, error) {
	if !scope.Valid() || revisionID == "" || generation == 0 {
		return Revision{}, domain.Invalidf("policy.observe", "scope, revision and generation are required")
	}
	if len(loadError) > 4096 {
		return Revision{}, domain.Invalidf("policy.observe", "load error exceeds 4096 bytes")
	}
	var result Revision
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		revision, record, err := loadRevision(tx, revisionID)
		if err != nil {
			return err
		}
		if !revisionMatchesScope(revision, scope) {
			return domain.Invalidf("policy.observe", "revision does not belong to the scope")
		}
		if revision.Status != StatusActive {
			return domain.New(domain.CodeConflict, "policy.observe", "revision is not active")
		}
		if revision.ObservedGeneration > generation {
			return domain.New(domain.CodeConflict, "policy.observe", "stale generation")
		}
		revision.ObservedGeneration = generation
		now := s.now().UTC()
		revision.ObservedAt = &now
		revision.LoadError = strings.TrimSpace(loadError)
		revision.UpdatedAt = now
		payload, err := json.Marshal(revision)
		if err != nil {
			return err
		}
		if _, err := tx.Put(revisionKind, revision.ID, record.Version, payload); err != nil {
			return err
		}
		topic := "policy.observed"
		if revision.LoadError != "" {
			topic = "policy.load_failed"
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: revision.ID + ":observed:" + strconv.FormatUint(uint64(generation), 10), Topic: topic, Payload: payload}); err != nil {
			return err
		}
		result = revision
		return nil
	})
	if err == nil {
		topic := "policy.observed"
		if result.LoadError != "" {
			topic = "policy.load_failed"
		}
		s.emit(ctx, scope, topic, result)
	}
	return result, err
}

func (s *Service) getRevision(ctx context.Context, id string) (Revision, error) {
	var revision Revision
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		loaded, _, err := loadRevision(tx, id)
		revision = loaded
		return err
	})
	return revision, err
}

func parsePolicy(source []byte) (*policyengine.Policy, error) {
	document, err := policyengine.Parse(bytes.NewReader(source), policyengine.DefaultLimits())
	if err != nil {
		return nil, domain.Wrap(domain.ErrInvalid, "policy.parse", "parse policy")
	}
	typed, err := document.Typed()
	if err != nil {
		return nil, domain.Wrap(domain.ErrInvalid, "policy.parse", "decode policy")
	}
	return typed, nil
}

func (s *Service) emit(ctx context.Context, scope Scope, kind string, revision Revision) {
	if s.Events == nil {
		return
	}
	payload, err := json.Marshal(revision)
	if err != nil {
		return
	}
	_, _ = s.Events.Append(ctx, "policy/"+scope.Key(), kind, payload)
}

func validateSource(source []byte) error {
	document, err := policyengine.Parse(bytes.NewReader(source), policyengine.DefaultLimits())
	if err != nil {
		return domain.Wrap(domain.ErrInvalid, "policy.validate", "parse policy")
	}
	typed, err := document.Typed()
	if err != nil {
		return domain.Wrap(domain.ErrInvalid, "policy.validate", "decode policy")
	}
	if err := typed.Validate(); err != nil {
		return domain.Wrap(domain.ErrInvalid, "policy.validate", "validate policy")
	}
	return nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
