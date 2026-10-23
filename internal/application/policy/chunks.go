package policy

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const (
	chunkKind        = "policy_chunk"
	chunkHistoryKind = "policy_chunk_history"
)

// ChunkStatus is the review state of one draft chunk.
type ChunkStatus string

const (
	ChunkStatusDraft    ChunkStatus = "draft"
	ChunkStatusApproved ChunkStatus = "approved"
	ChunkStatusRejected ChunkStatus = "rejected"
)

// Chunk is one editable policy section.
type Chunk struct {
	Scope     Scope       `json:"scope"`
	ID        string      `json:"id"`
	Index     int         `json:"index"`
	Source    []byte      `json:"source"`
	Status    ChunkStatus `json:"status"`
	Author    string      `json:"author"`
	Reason    string      `json:"reason,omitempty"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// ChunkDraft is the ordered set of chunks for one scope.
type ChunkDraft struct {
	Scope  Scope   `json:"scope"`
	Chunks []Chunk `json:"chunks"`
}

// Source composes approved chunks in order.
func (d ChunkDraft) Source() []byte {
	parts := make([][]byte, 0, len(d.Chunks))
	for _, chunk := range d.Chunks {
		parts = append(parts, chunk.Source)
	}
	return []byte(strings.Join(bytesToStrings(parts), "\n"))
}

func bytesToStrings(values [][]byte) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

// ChunkHistory is one previous chunk snapshot.
type ChunkHistory struct {
	Scope     Scope       `json:"scope"`
	Chunk     string      `json:"chunk"`
	Source    []byte      `json:"source"`
	Status    ChunkStatus `json:"status"`
	Author    string      `json:"author"`
	Reason    string      `json:"reason,omitempty"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// ChunkService owns policy draft chunks.
type ChunkService struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
	revisions   *Service
}

// NewChunkService returns a chunk service. revisions may be nil.
func NewChunkService(store lifecycle.Store, revisions *Service) (*ChunkService, error) {
	if store == nil {
		return nil, domain.Invalidf("policy.chunks", "store is required")
	}
	return &ChunkService{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now, revisions: revisions}, nil
}

// GetDraft returns chunks for a scope sorted by index and ID.
func (s *ChunkService) GetDraft(ctx context.Context, scope Scope) (ChunkDraft, error) {
	if !scope.Valid() {
		return ChunkDraft{}, domain.Invalidf("policy.chunks.get", "scope is required")
	}
	var chunks []Chunk
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(chunkKind)
		if err != nil {
			return err
		}
		prefix := scope.Key() + "#"
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			var chunk Chunk
			if err := json.Unmarshal(record.Payload, &chunk); err != nil {
				return err
			}
			chunks = append(chunks, chunk)
		}
		return nil
	})
	sortChunks(chunks)
	return ChunkDraft{Scope: scope, Chunks: chunks}, err
}

// Edit creates or updates one chunk and records its previous state.
func (s *ChunkService) Edit(ctx context.Context, scope Scope, chunkID string, index int, source []byte, author string, idempotencyKey domain.OperationID) (Chunk, error) {
	if !scope.Valid() || strings.TrimSpace(chunkID) == "" || strings.Contains(chunkID, "#") || strings.TrimSpace(author) == "" {
		return Chunk{}, domain.Invalidf("policy.chunks.edit", "scope, chunk and author are required")
	}
	if len(source) == 0 || len(source) > 4<<20 {
		return Chunk{}, domain.Invalidf("policy.chunks.edit", "chunk source is required and bounded")
	}
	key := chunkOperationKey("policy.chunk.edit", string(idempotencyKey), chunkKey(scope, chunkID))
	hash := digest([]byte(chunkKey(scope, chunkID) + ":" + strconv.Itoa(index) + ":" + string(source) + ":" + author))
	now := s.now().UTC()
	payload, _, err := s.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(chunkKind, chunkKey(scope, chunkID))
		if err != nil {
			return nil, err
		}
		chunk := Chunk{Scope: scope, ID: chunkID, Index: index, Source: append([]byte(nil), source...), Status: ChunkStatusDraft, Author: author, UpdatedAt: now}
		version := uint64(0)
		if exists {
			var previous Chunk
			if err := json.Unmarshal(record.Payload, &previous); err != nil {
				return nil, err
			}
			if err := putChunkHistory(tx, previous, now); err != nil {
				return nil, err
			}
			version = record.Version
			if index == 0 {
				chunk.Index = previous.Index
			}
		}
		if chunk.Index == 0 {
			chunk.Index = nextChunkIndex(tx, scope)
		}
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(chunkKind, chunkKey(scope, chunkID), version, encoded); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":edited", Topic: "policy.chunk.edited", Payload: encoded}); err != nil {
			return nil, err
		}
		return encoded, nil
	})
	if err != nil {
		return Chunk{}, err
	}
	var chunk Chunk
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return Chunk{}, err
	}
	return chunk, nil
}

// Approve marks one chunk approved.
func (s *ChunkService) Approve(ctx context.Context, scope Scope, chunkID, approver string) (Chunk, error) {
	return s.setStatus(ctx, scope, chunkID, ChunkStatusApproved, approver, "")
}

// Reject marks one chunk rejected with a reason.
func (s *ChunkService) Reject(ctx context.Context, scope Scope, chunkID, approver, reason string) (Chunk, error) {
	if strings.TrimSpace(reason) == "" {
		return Chunk{}, domain.Invalidf("policy.chunks.reject", "reason is required")
	}
	return s.setStatus(ctx, scope, chunkID, ChunkStatusRejected, approver, reason)
}

func (s *ChunkService) setStatus(ctx context.Context, scope Scope, chunkID string, status ChunkStatus, approver, reason string) (Chunk, error) {
	if !scope.Valid() || strings.TrimSpace(chunkID) == "" || strings.TrimSpace(approver) == "" {
		return Chunk{}, domain.Invalidf("policy.chunks.status", "scope, chunk and approver are required")
	}
	var result Chunk
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(chunkKind, chunkKey(scope, chunkID))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "policy.chunks.status", "chunk not found")
		}
		var chunk Chunk
		if err := json.Unmarshal(record.Payload, &chunk); err != nil {
			return err
		}
		if err := putChunkHistory(tx, chunk, s.now().UTC()); err != nil {
			return err
		}
		chunk.Status = status
		chunk.Author = approver
		chunk.Reason = reason
		chunk.UpdatedAt = s.now().UTC()
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		if _, err := tx.Put(chunkKind, chunkKey(scope, chunkID), record.Version, encoded); err != nil {
			return err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: chunkKey(scope, chunkID) + ":status:" + string(status), Topic: "policy.chunk.status", Payload: encoded}); err != nil {
			return err
		}
		result = chunk
		return nil
	})
	return result, err
}

// Undo restores the most recent previous snapshot of one chunk.
func (s *ChunkService) Undo(ctx context.Context, scope Scope, chunkID string) (Chunk, error) {
	var result Chunk
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(chunkKind, chunkKey(scope, chunkID))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "policy.chunks.undo", "chunk not found")
		}
		history, exists, err := latestChunkHistory(tx, scope, chunkID)
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "policy.chunks.undo", "chunk history not found")
		}
		if err := tx.Delete(chunkHistoryKind, history.ID, history.Version); err != nil {
			return err
		}
		var snapshot Chunk
		if err := json.Unmarshal(history.Payload, &snapshot); err != nil {
			return err
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		if _, err := tx.Put(chunkKind, chunkKey(scope, chunkID), record.Version, encoded); err != nil {
			return err
		}
		result = snapshot
		return nil
	})
	return result, err
}

// Clear removes all chunks and their history for a scope.
func (s *ChunkService) Clear(ctx context.Context, scope Scope, idempotencyKey domain.OperationID) error {
	if !scope.Valid() {
		return domain.Invalidf("policy.chunks.clear", "scope is required")
	}
	key := chunkOperationKey("policy.chunk.clear", string(idempotencyKey), scope.Key())
	_, _, err := s.coordinator.Execute(ctx, key, digest([]byte(scope.Key())), func(tx lifecycle.WriteTx) ([]byte, error) {
		for _, kind := range []string{chunkKind, chunkHistoryKind} {
			records, err := tx.List(kind)
			if err != nil {
				return nil, err
			}
			prefix := scope.Key() + "#"
			for _, record := range records {
				if strings.HasPrefix(record.ID, prefix) {
					if err := tx.Delete(kind, record.ID, record.Version); err != nil {
						return nil, err
					}
				}
			}
		}
		return []byte(`{}`), nil
	})
	return err
}

// ApproveAll approves every chunk and returns the composed draft.
func (s *ChunkService) ApproveAll(ctx context.Context, scope Scope, approver string) (ChunkDraft, error) {
	draft, err := s.GetDraft(ctx, scope)
	if err != nil {
		return ChunkDraft{}, err
	}
	if len(draft.Chunks) == 0 {
		return ChunkDraft{}, domain.Wrap(domain.ErrNotFound, "policy.chunks.approve_all", "no chunks")
	}
	for i := range draft.Chunks {
		approved, err := s.Approve(ctx, scope, draft.Chunks[i].ID, approver)
		if err != nil {
			return ChunkDraft{}, err
		}
		draft.Chunks[i] = approved
	}
	return draft, nil
}

// History returns policy revisions and chunk snapshots for a scope.
func (s *ChunkService) History(ctx context.Context, scope Scope) ([]Revision, []ChunkHistory, error) {
	var revisions []Revision
	if s.revisions != nil {
		var err error
		revisions, err = s.revisions.List(ctx, scope)
		if err != nil {
			return nil, nil, err
		}
	}
	var history []ChunkHistory
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(chunkHistoryKind)
		if err != nil {
			return err
		}
		prefix := scope.Key() + "#"
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			var entry ChunkHistory
			if err := json.Unmarshal(record.Payload, &entry); err != nil {
				return err
			}
			history = append(history, entry)
		}
		return nil
	})
	return revisions, history, err
}

func putChunkHistory(tx lifecycle.WriteTx, chunk Chunk, now time.Time) error {
	records, err := tx.List(chunkHistoryKind)
	if err != nil {
		return err
	}
	entry := ChunkHistory{Scope: chunk.Scope, Chunk: chunk.ID, Source: chunk.Source, Status: chunk.Status, Author: chunk.Author, Reason: chunk.Reason, UpdatedAt: now}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	sequence := strconv.Itoa(len(records))
	_, err = tx.Put(chunkHistoryKind, chunkKey(chunk.Scope, chunk.ID)+"~"+strconv.FormatInt(now.UnixNano(), 10)+"-"+sequence, 0, encoded)
	return err
}

func latestChunkHistory(tx lifecycle.ReadTx, scope Scope, chunkID string) (lifecycle.Record, bool, error) {
	records, err := tx.List(chunkHistoryKind)
	if err != nil {
		return lifecycle.Record{}, false, err
	}
	prefix := chunkKey(scope, chunkID) + "~"
	var latest lifecycle.Record
	for _, record := range records {
		if strings.HasPrefix(record.ID, prefix) && record.ID > latest.ID {
			latest = record
		}
	}
	return latest, latest.ID != "", nil
}

func nextChunkIndex(tx lifecycle.ReadTx, scope Scope) int {
	records, err := tx.List(chunkKind)
	if err != nil {
		return 1
	}
	prefix := scope.Key() + "#"
	max := 0
	for _, record := range records {
		if !strings.HasPrefix(record.ID, prefix) {
			continue
		}
		var chunk Chunk
		if json.Unmarshal(record.Payload, &chunk) == nil && chunk.Index > max {
			max = chunk.Index
		}
	}
	return max + 1
}

func sortChunks(chunks []Chunk) {
	sort.Slice(chunks, func(i, j int) bool {
		if chunks[i].Index == chunks[j].Index {
			return chunks[i].ID < chunks[j].ID
		}
		return chunks[i].Index < chunks[j].Index
	})
}

func chunkOperationKey(prefix, key, fallback string) string {
	if value := strings.TrimSpace(key); value != "" {
		return prefix + ":" + value
	}
	return prefix + ":" + fallback
}

func chunkKey(scope Scope, id string) string {
	return scope.Key() + "#" + id
}
