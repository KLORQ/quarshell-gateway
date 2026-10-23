// Package lifecycle provides the durable application primitives used by the
// new gateway use cases: optimistic entity records, idempotent operations, an
// outbox, and a bounded reconciler. It intentionally has no transport, SQL, or
// protobuf dependency.
package lifecycle

import (
	"context"
	"time"
)

// Record is one durable entity version.
type Record struct {
	Kind      string
	ID        string
	Version   uint64
	Payload   []byte
	Deleted   bool
	UpdatedAt time.Time
}

// Operation is the replayable result of one idempotent operation.
type Operation struct {
	Key         string
	RequestHash string
	Result      []byte
	CreatedAt   time.Time
}

// OutboxMessage is one durable side effect awaiting delivery.
type OutboxMessage struct {
	ID          string
	Topic       string
	Payload     []byte
	Attempts    int
	AvailableAt time.Time
	LeaseUntil  time.Time
	LastError   string
	Dead        bool
}

// ReadTx is a read-only transaction view.
type ReadTx interface {
	Get(kind, id string) (Record, bool, error)
	List(kind string) ([]Record, error)
	GetOperation(key string) (Operation, bool, error)
	PendingOutbox() int
	DeadOutbox() int
}

// WriteTx is an atomic transaction view. It commits only when the callback
// returns nil.
type WriteTx interface {
	ReadTx
	Put(kind, id string, expectedVersion uint64, payload []byte) (Record, error)
	Delete(kind, id string, expectedVersion uint64) error
	PutOperation(operation Operation) error
	DeleteOperation(key string) error
	Enqueue(message OutboxMessage) error
}

// Store owns transactions, idempotency records, and the outbox.
type Store interface {
	View(ctx context.Context, fn func(ReadTx) error) error
	Update(ctx context.Context, fn func(WriteTx) error) error
	ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]OutboxMessage, error)
	AckOutbox(ctx context.Context, id string) error
	RetryOutbox(ctx context.Context, id string, availableAt time.Time, reason string, dead bool) error
}
