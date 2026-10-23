package lifecycle

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// MemoryStore is an in-memory Store for tests and single-process development.
// Transactions copy the storage maps and commit them only on success.
type MemoryStore struct {
	mu         sync.Mutex
	records    map[string]Record
	operations map[string]Operation
	outbox     map[string]OutboxMessage
	now        func() time.Time
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithClock(time.Now)
}

// NewMemoryStoreWithClock returns an empty store with an injectable clock.
func NewMemoryStoreWithClock(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		records:    map[string]Record{},
		operations: map[string]Operation{},
		outbox:     map[string]OutboxMessage{},
		now:        now,
	}
}

func recordKey(kind, id string) string { return kind + "\x00" + id }

func (s *MemoryStore) View(ctx context.Context, fn func(ReadTx) error) error {
	if err := ctx.Err(); err != nil {
		return domain.Wrap(err, "lifecycle.view", "view canceled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&memoryTx{records: s.records, operations: s.operations, outbox: s.outbox})
}

func (s *MemoryStore) Update(ctx context.Context, fn func(WriteTx) error) error {
	if err := ctx.Err(); err != nil {
		return domain.Wrap(err, "lifecycle.update", "update canceled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := cloneRecords(s.records)
	operations := cloneOperations(s.operations)
	outbox := cloneOutbox(s.outbox)
	tx := &memoryTx{records: records, operations: operations, outbox: outbox, now: s.now}
	if err := fn(tx); err != nil {
		return err
	}
	s.records = records
	s.operations = operations
	s.outbox = outbox
	return nil
}

func (s *MemoryStore) ClaimOutbox(_ context.Context, now time.Time, lease time.Duration, limit int) ([]OutboxMessage, error) {
	if lease <= 0 {
		return nil, domain.Invalidf("lifecycle.outbox", "lease must be positive")
	}
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.outbox))
	for id := range s.outbox {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]OutboxMessage, 0, limit)
	for _, id := range ids {
		message := s.outbox[id]
		if message.Dead || message.AvailableAt.After(now) {
			continue
		}
		if !message.LeaseUntil.IsZero() && message.LeaseUntil.After(now) {
			continue
		}
		message.LeaseUntil = now.Add(lease)
		s.outbox[id] = message
		result = append(result, cloneMessage(message))
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

func (s *MemoryStore) AckOutbox(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.outbox, id)
	return nil
}

func (s *MemoryStore) RetryOutbox(_ context.Context, id string, availableAt time.Time, reason string, dead bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	message, exists := s.outbox[id]
	if !exists {
		return domain.Wrap(domain.ErrNotFound, "lifecycle.outbox", "outbox message not found")
	}
	message.Attempts++
	message.AvailableAt = availableAt
	message.LeaseUntil = time.Time{}
	message.LastError = reason
	message.Dead = dead
	s.outbox[id] = message
	return nil
}

type memoryTx struct {
	records    map[string]Record
	operations map[string]Operation
	outbox     map[string]OutboxMessage
	now        func() time.Time
}

func (tx *memoryTx) Get(kind, id string) (Record, bool, error) {
	record, exists := tx.records[recordKey(kind, id)]
	if !exists || record.Deleted {
		return Record{}, false, nil
	}
	return cloneRecord(record), true, nil
}

func (tx *memoryTx) List(kind string) ([]Record, error) {
	result := make([]Record, 0)
	for _, record := range tx.records {
		if record.Kind == kind && !record.Deleted {
			result = append(result, cloneRecord(record))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result, nil
}

func (tx *memoryTx) GetOperation(key string) (Operation, bool, error) {
	operation, exists := tx.operations[key]
	if !exists {
		return Operation{}, false, nil
	}
	operation.Result = append([]byte(nil), operation.Result...)
	return operation, true, nil
}

func (tx *memoryTx) PendingOutbox() int {
	count := 0
	for _, message := range tx.outbox {
		if !message.Dead {
			count++
		}
	}
	return count
}

func (tx *memoryTx) DeadOutbox() int {
	count := 0
	for _, message := range tx.outbox {
		if message.Dead {
			count++
		}
	}
	return count
}

func (tx *memoryTx) Put(kind, id string, expectedVersion uint64, payload []byte) (Record, error) {
	if kind == "" || id == "" {
		return Record{}, domain.Invalidf("lifecycle.put", "kind and id are required")
	}
	key := recordKey(kind, id)
	current, exists := tx.records[key]
	if expectedVersion == 0 {
		if exists && !current.Deleted {
			return Record{}, domain.New(domain.CodeConflict, "lifecycle.put", "record already exists")
		}
	} else if !exists || current.Version != expectedVersion {
		return Record{}, domain.New(domain.CodeConflict, "lifecycle.put", "record version conflict")
	}
	version := expectedVersion + 1
	if version == 0 {
		version = 1
	}
	record := Record{Kind: kind, ID: id, Version: version, Payload: append([]byte(nil), payload...), UpdatedAt: tx.now()}
	tx.records[key] = record
	return cloneRecord(record), nil
}

func (tx *memoryTx) Delete(kind, id string, expectedVersion uint64) error {
	if expectedVersion == 0 {
		return domain.Invalidf("lifecycle.delete", "expected version is required")
	}
	key := recordKey(kind, id)
	current, exists := tx.records[key]
	if !exists || current.Deleted || current.Version != expectedVersion {
		return domain.New(domain.CodeConflict, "lifecycle.delete", "record version conflict")
	}
	delete(tx.records, key)
	return nil
}

func (tx *memoryTx) PutOperation(operation Operation) error {
	if operation.Key == "" {
		return domain.Invalidf("lifecycle.operation", "operation key is required")
	}
	if _, exists := tx.operations[operation.Key]; exists {
		return domain.New(domain.CodeConflict, "lifecycle.operation", "operation already exists")
	}
	operation.Result = append([]byte(nil), operation.Result...)
	if operation.CreatedAt.IsZero() {
		operation.CreatedAt = tx.now()
	}
	tx.operations[operation.Key] = operation
	return nil
}

func (tx *memoryTx) DeleteOperation(key string) error {
	if key == "" {
		return domain.Invalidf("lifecycle.operation", "operation key is required")
	}
	if _, exists := tx.operations[key]; !exists {
		return domain.New(domain.CodeConflict, "lifecycle.operation", "operation does not exist")
	}
	delete(tx.operations, key)
	return nil
}

func (tx *memoryTx) Enqueue(message OutboxMessage) error {
	if message.ID == "" || message.Topic == "" {
		return domain.Invalidf("lifecycle.outbox", "message id and topic are required")
	}
	if _, exists := tx.outbox[message.ID]; exists {
		return domain.New(domain.CodeConflict, "lifecycle.outbox", "outbox message already exists")
	}
	if message.AvailableAt.IsZero() {
		message.AvailableAt = tx.now()
	}
	message.Payload = append([]byte(nil), message.Payload...)
	tx.outbox[message.ID] = message
	return nil
}

func cloneRecords(source map[string]Record) map[string]Record {
	result := make(map[string]Record, len(source))
	for key, record := range source {
		result[key] = cloneRecord(record)
	}
	return result
}

func cloneRecord(record Record) Record {
	record.Payload = append([]byte(nil), record.Payload...)
	return record
}

func cloneOperations(source map[string]Operation) map[string]Operation {
	result := make(map[string]Operation, len(source))
	for key, operation := range source {
		operation.Result = append([]byte(nil), operation.Result...)
		result[key] = operation
	}
	return result
}

func cloneOutbox(source map[string]OutboxMessage) map[string]OutboxMessage {
	result := make(map[string]OutboxMessage, len(source))
	for key, message := range source {
		result[key] = cloneMessage(message)
	}
	return result
}

func cloneMessage(message OutboxMessage) OutboxMessage {
	message.Payload = append([]byte(nil), message.Payload...)
	return message
}
