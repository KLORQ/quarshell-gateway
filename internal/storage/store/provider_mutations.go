package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// MaxProviderMutations bounds the durable receipt journal. Receipts are not
// secret material; the oldest entry is evicted when the journal is full.
const MaxProviderMutations = 4096

// ErrProviderMutationInvalid indicates a malformed receipt.
var ErrProviderMutationInvalid = errors.New("invalid provider mutation receipt")

// ProviderMutationKind names one sandbox provider mutation. Values mirror the
// pinned OpenShell enum names.
type ProviderMutationKind string

const (
	ProviderMutationAttach  ProviderMutationKind = "ATTACH"
	ProviderMutationDetach  ProviderMutationKind = "DETACH"
	ProviderMutationUpdate  ProviderMutationKind = "UPDATE"
	ProviderMutationObserve ProviderMutationKind = "OBSERVE"
)

// ProviderDesiredIdentityRecord is the secret-free authority frozen by one
// receipt. Revisions are equality tokens, not ordered counters.
type ProviderDesiredIdentityRecord struct {
	SandboxID               string `json:"sandbox_id,omitempty"`
	Sandbox                 string `json:"sandbox,omitempty"`
	AttachmentEpoch         string `json:"attachment_epoch,omitempty"`
	ProviderID              string `json:"provider_id,omitempty"`
	ProviderResourceVersion uint64 `json:"provider_resource_version,omitempty"`
	ProviderEnvRevision     uint64 `json:"provider_env_revision,omitempty"`
	ConfigRevision          uint64 `json:"config_revision,omitempty"`
	PolicyHash              string `json:"policy_hash,omitempty"`
}

// ProviderMutationRecord is an immutable receipt for one sandbox-scoped
// provider mutation. It never carries credentials or raw error text.
type ProviderMutationRecord struct {
	ReceiptID          string                        `json:"receipt_id"`
	MutationID         string                        `json:"mutation_id,omitempty"`
	Provider           string                        `json:"provider"`
	Workspace          string                        `json:"workspace"`
	Kind               ProviderMutationKind          `json:"kind"`
	Desired            ProviderDesiredIdentityRecord `json:"desired"`
	PersistedAt        time.Time                     `json:"persisted_at"`
	OperationState     string                        `json:"operation_state,omitempty"`
	OperationOutcome   string                        `json:"operation_outcome,omitempty"`
	OperationUpdatedAt time.Time                     `json:"operation_updated_at,omitempty"`
}

func validProviderMutationKind(kind ProviderMutationKind) bool {
	switch kind {
	case ProviderMutationAttach, ProviderMutationDetach, ProviderMutationUpdate, ProviderMutationObserve:
		return true
	default:
		return false
	}
}

// RecordProviderMutation persists one receipt. Recording the same receipt ID
// with identical content is idempotent; any other reuse is rejected.
func (s *Store) RecordProviderMutation(record ProviderMutationRecord) (ProviderMutationRecord, error) {
	if record.ReceiptID == "" || len(record.ReceiptID) > 64 || record.Provider == "" || len(record.Provider) > 253 || record.Workspace == "" || len(record.Workspace) > 128 || !validProviderMutationKind(record.Kind) {
		return ProviderMutationRecord{}, ErrProviderMutationInvalid
	}
	if record.PersistedAt.IsZero() {
		record.PersistedAt = time.Now().UTC()
	}
	if record.OperationState == "" {
		record.OperationState = "PENDING"
		record.OperationUpdatedAt = record.PersistedAt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.state.ProviderMutations[record.ReceiptID]; ok {
		if existing == record {
			return existing, nil
		}
		return ProviderMutationRecord{}, fmt.Errorf("%w: receipt ID reused with different content", ErrProviderMutationInvalid)
	}
	wasNil := s.state.ProviderMutations == nil
	previous := s.state.ProviderMutations
	next := make(map[string]ProviderMutationRecord, len(previous)+1)
	for id, existing := range previous {
		next[id] = existing
	}
	if len(next) >= MaxProviderMutations {
		oldestID := ""
		var oldest time.Time
		for id, existing := range next {
			if oldestID == "" || existing.PersistedAt.Before(oldest) {
				oldestID, oldest = id, existing.PersistedAt
			}
		}
		if oldestID != "" {
			delete(next, oldestID)
		}
	}
	next[record.ReceiptID] = record
	s.state.ProviderMutations = next
	if err := s.flushLocked(); err != nil {
		if wasNil {
			s.state.ProviderMutations = nil
		} else {
			s.state.ProviderMutations = previous
		}
		return ProviderMutationRecord{}, err
	}
	return record, nil
}

// SetProviderMutationOperation records the durable apply projection for one
// receipt. Identical updates are idempotent; a receipt that is already
// terminal cannot move back to a non-terminal state.
func (s *Store) SetProviderMutationOperation(receiptID, state, outcome string) (ProviderMutationRecord, error) {
	if receiptID == "" || state == "" || len(state) > 32 || len(outcome) > 64 {
		return ProviderMutationRecord{}, ErrProviderMutationInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.ProviderMutations[receiptID]
	if !ok {
		return ProviderMutationRecord{}, ErrProviderMutationInvalid
	}
	if record.OperationState == state && record.OperationOutcome == outcome {
		return record, nil
	}
	if providerOperationTerminal(record.OperationState) && !providerOperationTerminal(state) {
		return record, nil
	}
	previous := record
	record.OperationState = state
	record.OperationOutcome = outcome
	record.OperationUpdatedAt = time.Now().UTC()
	s.state.ProviderMutations[receiptID] = record
	if err := s.flushLocked(); err != nil {
		s.state.ProviderMutations[receiptID] = previous
		return ProviderMutationRecord{}, err
	}
	return record, nil
}

func providerOperationTerminal(state string) bool {
	switch state {
	case "APPLIED", "INACTIVE", "FAILED", "SUPERSEDED", "CANCELLED":
		return true
	default:
		return false
	}
}

// GetProviderMutation returns an immutable receipt by ID.
func (s *Store) GetProviderMutation(receiptID string) (ProviderMutationRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.ProviderMutations[receiptID]
	return record, ok
}

func newCanonicalUUID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return ""
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(id[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}
