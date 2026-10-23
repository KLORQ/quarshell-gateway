package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	postgresRecordsTable    = "lifecycle_records"
	postgresOperationsTable = "lifecycle_operations"
	postgresOutboxTable     = "lifecycle_outbox"
)

// PostgresStore is a durable Store backed by PostgreSQL. One transaction
// contains entity writes, the idempotency record, and outbox rows.
type PostgresStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewPostgresStore opens a PostgreSQL store, pings it, and migrates the schema.
func NewPostgresStore(ctx context.Context, url string) (*PostgresStore, error) {
	if url == "" {
		return nil, domain.Invalidf("lifecycle.postgres", "url is required")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, domain.Wrap(err, "lifecycle.postgres", "open database")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "database unavailable")
	}
	store := &PostgresStore{db: db, now: time.Now}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the database.
func (s *PostgresStore) Close() error { return s.db.Close() }

// Migrate creates the lifecycle schema.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS ` + postgresRecordsTable + ` (
			kind TEXT NOT NULL,
			id TEXT NOT NULL,
			version BIGINT NOT NULL,
			payload BYTEA NOT NULL,
			deleted BOOLEAN NOT NULL DEFAULT FALSE,
			updated_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (kind, id)
		)`,
		`CREATE TABLE IF NOT EXISTS ` + postgresOperationsTable + ` (
			key TEXT PRIMARY KEY,
			request_hash TEXT NOT NULL,
			result BYTEA NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + postgresOutboxTable + ` (
			id TEXT PRIMARY KEY,
			topic TEXT NOT NULL,
			payload BYTEA NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			available_at TIMESTAMPTZ NOT NULL,
			lease_until TIMESTAMPTZ NULL,
			last_error TEXT NOT NULL DEFAULT '',
			dead BOOLEAN NOT NULL DEFAULT FALSE
		)`,
		`CREATE INDEX IF NOT EXISTS lifecycle_outbox_available ON ` + postgresOutboxTable + ` (available_at)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "migration failed")
		}
	}
	return nil
}

// View runs a read-only transaction.
func (s *PostgresStore) View(ctx context.Context, fn func(ReadTx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "begin read transaction")
	}
	defer tx.Rollback()
	if err := fn(&postgresTx{tx: tx, ctx: ctx, now: s.now}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "commit read transaction")
	}
	return nil
}

// Update runs a read-write transaction and commits only on nil.
func (s *PostgresStore) Update(ctx context.Context, fn func(WriteTx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "begin transaction")
	}
	defer tx.Rollback()
	if err := fn(&postgresTx{tx: tx, ctx: ctx, now: s.now}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "commit transaction")
	}
	return nil
}

// ClaimOutbox atomically leases pending messages with SKIP LOCKED.
func (s *PostgresStore) ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]OutboxMessage, error) {
	if lease <= 0 {
		return nil, domain.Invalidf("lifecycle.postgres", "lease must be positive")
	}
	if limit <= 0 {
		limit = 100
	}
	statement := `WITH claimed AS (
		SELECT id FROM ` + postgresOutboxTable + `
		WHERE dead = FALSE AND available_at <= $1 AND (lease_until IS NULL OR lease_until <= $1)
		ORDER BY available_at, id LIMIT $2 FOR UPDATE SKIP LOCKED
	)
	UPDATE ` + postgresOutboxTable + ` AS o SET lease_until = $3
	FROM claimed WHERE o.id = claimed.id
	RETURNING o.id, o.topic, o.payload, o.attempts, o.available_at, o.lease_until, o.last_error, o.dead`
	rows, err := s.db.QueryContext(ctx, statement, now, limit, now.Add(lease))
	if err != nil {
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "claim outbox")
	}
	defer rows.Close()
	var result []OutboxMessage
	for rows.Next() {
		var message OutboxMessage
		var leaseUntil sql.NullTime
		if err := rows.Scan(&message.ID, &message.Topic, &message.Payload, &message.Attempts, &message.AvailableAt, &leaseUntil, &message.LastError, &message.Dead); err != nil {
			return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "scan outbox")
		}
		if leaseUntil.Valid {
			message.LeaseUntil = leaseUntil.Time
		}
		result = append(result, message)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "read outbox")
	}
	return result, nil
}

// AckOutbox removes a delivered message.
func (s *PostgresStore) AckOutbox(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM `+postgresOutboxTable+` WHERE id = $1`, id); err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "ack outbox")
	}
	return nil
}

// RetryOutbox schedules a retry or dead-letters it.
func (s *PostgresStore) RetryOutbox(ctx context.Context, id string, availableAt time.Time, reason string, dead bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE `+postgresOutboxTable+`
		SET attempts = attempts + 1, available_at = $2, lease_until = NULL, last_error = $3, dead = $4
		WHERE id = $1`, id, availableAt, reason, dead)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "retry outbox")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.Wrap(domain.ErrNotFound, "lifecycle.postgres", "outbox message not found")
	}
	return nil
}

type postgresTx struct {
	tx  *sql.Tx
	ctx context.Context
	now func() time.Time
}

func (t *postgresTx) Get(kind, id string) (Record, bool, error) {
	row := t.tx.QueryRowContext(t.ctx, `SELECT version, payload, deleted, updated_at FROM `+postgresRecordsTable+` WHERE kind = $1 AND id = $2`, kind, id)
	var record Record
	var deleted bool
	if err := row.Scan(&record.Version, &record.Payload, &deleted, &record.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "read record")
	}
	if deleted {
		return Record{}, false, nil
	}
	record.Kind = kind
	record.ID = id
	return record, true, nil
}

func (t *postgresTx) List(kind string) ([]Record, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT id, version, payload, deleted, updated_at FROM `+postgresRecordsTable+` WHERE kind = $1 AND deleted = FALSE ORDER BY id`, kind)
	if err != nil {
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "list records")
	}
	defer rows.Close()
	var result []Record
	for rows.Next() {
		record := Record{Kind: kind}
		var deleted bool
		if err := rows.Scan(&record.ID, &record.Version, &record.Payload, &deleted, &record.UpdatedAt); err != nil {
			return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "scan record")
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "read records")
	}
	return result, nil
}

func (t *postgresTx) GetOperation(key string) (Operation, bool, error) {
	row := t.tx.QueryRowContext(t.ctx, `SELECT request_hash, result, created_at FROM `+postgresOperationsTable+` WHERE key = $1`, key)
	var operation Operation
	if err := row.Scan(&operation.RequestHash, &operation.Result, &operation.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, false, nil
		}
		return Operation{}, false, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "read operation")
	}
	operation.Key = key
	return operation, true, nil
}

func (t *postgresTx) PendingOutbox() int {
	var count int
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM `+postgresOutboxTable+` WHERE dead = FALSE`).Scan(&count); err != nil {
		return 0
	}
	return count
}

func (t *postgresTx) DeadOutbox() int {
	var count int
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM `+postgresOutboxTable+` WHERE dead = TRUE`).Scan(&count); err != nil {
		return 0
	}
	return count
}

func (t *postgresTx) Put(kind, id string, expectedVersion uint64, payload []byte) (Record, error) {
	if kind == "" || id == "" {
		return Record{}, domain.Invalidf("lifecycle.postgres", "kind and id are required")
	}
	if payload == nil {
		payload = []byte{}
	}
	now := t.now().UTC()
	if expectedVersion == 0 {
		record := Record{Kind: kind, ID: id, Version: 1, Payload: append([]byte(nil), payload...), UpdatedAt: now}
		result, err := t.tx.ExecContext(t.ctx, `INSERT INTO `+postgresRecordsTable+` (kind, id, version, payload, deleted, updated_at)
			VALUES ($1, $2, 1, $3, FALSE, $4) ON CONFLICT (kind, id) DO NOTHING`, kind, id, payload, now)
		if err != nil {
			return Record{}, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "insert record")
		}
		affected, err := result.RowsAffected()
		if err != nil || affected == 0 {
			return Record{}, domain.New(domain.CodeConflict, "lifecycle.postgres", "record already exists")
		}
		return record, nil
	}
	record := Record{Kind: kind, ID: id, Version: expectedVersion + 1, Payload: append([]byte(nil), payload...), UpdatedAt: now}
	result, err := t.tx.ExecContext(t.ctx, `UPDATE `+postgresRecordsTable+`
		SET version = $1, payload = $2, deleted = FALSE, updated_at = $3
		WHERE kind = $4 AND id = $5 AND version = $6`, record.Version, payload, now, kind, id, expectedVersion)
	if err != nil {
		return Record{}, domain.New(domain.CodeUnavailable, "lifecycle.postgres", "update record")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return Record{}, domain.New(domain.CodeConflict, "lifecycle.postgres", "record version conflict")
	}
	return record, nil
}

func (t *postgresTx) Delete(kind, id string, expectedVersion uint64) error {
	if expectedVersion == 0 {
		return domain.Invalidf("lifecycle.postgres", "expected version is required")
	}
	result, err := t.tx.ExecContext(t.ctx, `DELETE FROM `+postgresRecordsTable+` WHERE kind = $1 AND id = $2 AND version = $3`, kind, id, expectedVersion)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "delete record")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.postgres", "record version conflict")
	}
	return nil
}

func (t *postgresTx) PutOperation(operation Operation) error {
	if operation.Key == "" {
		return domain.Invalidf("lifecycle.postgres", "operation key is required")
	}
	createdAt := operation.CreatedAt
	if createdAt.IsZero() {
		createdAt = t.now().UTC()
	}
	resultBytes := operation.Result
	if resultBytes == nil {
		resultBytes = []byte{}
	}
	result, err := t.tx.ExecContext(t.ctx, `INSERT INTO `+postgresOperationsTable+` (key, request_hash, result, created_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (key) DO NOTHING`, operation.Key, operation.RequestHash, resultBytes, createdAt)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "insert operation")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.postgres", "operation already exists")
	}
	return nil
}

func (t *postgresTx) DeleteOperation(key string) error {
	if key == "" {
		return domain.Invalidf("lifecycle.postgres", "operation key is required")
	}
	result, err := t.tx.ExecContext(t.ctx, `DELETE FROM `+postgresOperationsTable+` WHERE key = $1`, key)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.postgres", "delete operation")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.postgres", "operation does not exist")
	}
	return nil
}

func (t *postgresTx) Enqueue(message OutboxMessage) error {
	if message.ID == "" || message.Topic == "" {
		return domain.Invalidf("lifecycle.postgres", "message id and topic are required")
	}
	availableAt := message.AvailableAt
	if availableAt.IsZero() {
		availableAt = t.now().UTC()
	}
	payload := message.Payload
	if payload == nil {
		payload = []byte{}
	}
	result, err := t.tx.ExecContext(t.ctx, `INSERT INTO `+postgresOutboxTable+` (id, topic, payload, attempts, available_at, lease_until, last_error, dead)
		VALUES ($1, $2, $3, $4, $5, NULL, $6, $7) ON CONFLICT (id) DO NOTHING`, message.ID, message.Topic, payload, message.Attempts, availableAt, message.LastError, message.Dead)
	if err != nil {
		return domain.Wrap(err, "lifecycle.postgres", "enqueue outbox")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.postgres", "outbox message already exists")
	}
	return nil
}
