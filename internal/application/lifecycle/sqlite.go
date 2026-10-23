package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	_ "modernc.org/sqlite"
)

const (
	sqliteRecordsTable    = "lifecycle_records"
	sqliteOperationsTable = "lifecycle_operations"
	sqliteOutboxTable     = "lifecycle_outbox"
)

// SQLiteStore is a durable single-node Store.
type SQLiteStore struct {
	mu      sync.Mutex
	claimMu sync.Mutex
	db      *sql.DB
	now     func() time.Time
}

// NewSQLiteStore opens a SQLite database, pings it, and migrates the schema.
func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, domain.Invalidf("lifecycle.sqlite", "path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, domain.Wrap(err, "lifecycle.sqlite", "open database")
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.sqlite", "database unavailable")
	}
	store := &SQLiteStore{db: db, now: time.Now}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// Migrate creates the lifecycle schema.
func (s *SQLiteStore) Migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS ` + sqliteRecordsTable + ` (
			kind TEXT NOT NULL,
			id TEXT NOT NULL,
			version INTEGER NOT NULL,
			payload BLOB NOT NULL,
			deleted INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (kind, id)
		)`,
		`CREATE TABLE IF NOT EXISTS ` + sqliteOperationsTable + ` (
			key TEXT PRIMARY KEY,
			request_hash TEXT NOT NULL,
			result BLOB NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + sqliteOutboxTable + ` (
			id TEXT PRIMARY KEY,
			topic TEXT NOT NULL,
			payload BLOB NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			available_at INTEGER NOT NULL,
			lease_until INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			dead INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS lifecycle_outbox_available ON ` + sqliteOutboxTable + ` (available_at)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return domain.Wrap(err, "lifecycle.sqlite", "migration failed")
		}
	}
	return nil
}

// View runs a transaction for reads.
func (s *SQLiteStore) View(ctx context.Context, fn func(ReadTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.sqlite", "begin transaction")
	}
	defer tx.Rollback()
	if err := fn(&sqliteTx{tx: tx, ctx: ctx, now: s.now}); err != nil {
		return err
	}
	return tx.Commit()
}

// Update runs a transaction and commits only on nil.
func (s *SQLiteStore) Update(ctx context.Context, fn func(WriteTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.sqlite", "begin transaction")
	}
	defer tx.Rollback()
	if err := fn(&sqliteTx{tx: tx, ctx: ctx, now: s.now}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return domain.New(domain.CodeUnavailable, "lifecycle.sqlite", "commit transaction")
	}
	return nil
}

// ClaimOutbox leases pending messages.
func (s *SQLiteStore) ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]OutboxMessage, error) {
	if lease <= 0 {
		return nil, domain.Invalidf("lifecycle.sqlite", "lease must be positive")
	}
	if limit <= 0 {
		limit = 100
	}
	s.claimMu.Lock()
	defer s.claimMu.Unlock()
	nowNano := now.UnixNano()
	leaseNano := now.Add(lease).UnixNano()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.sqlite", "begin claim")
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id, topic, payload, attempts, available_at, last_error, dead FROM `+sqliteOutboxTable+`
		WHERE dead = 0 AND available_at <= ? AND (lease_until = 0 OR lease_until <= ?)
		ORDER BY available_at, id LIMIT ?`, nowNano, nowNano, limit)
	if err != nil {
		return nil, domain.Wrap(err, "lifecycle.sqlite", "claim outbox")
	}
	var messages []OutboxMessage
	for rows.Next() {
		var message OutboxMessage
		var attempts int
		var availableAt int64
		var dead int
		if err := rows.Scan(&message.ID, &message.Topic, &message.Payload, &attempts, &availableAt, &message.LastError, &dead); err != nil {
			rows.Close()
			return nil, domain.Wrap(err, "lifecycle.sqlite", "scan outbox")
		}
		message.Attempts = attempts
		message.AvailableAt = time.Unix(0, availableAt)
		message.LeaseUntil = time.Unix(0, leaseNano)
		message.Dead = dead != 0
		messages = append(messages, message)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, domain.Wrap(err, "lifecycle.sqlite", "read outbox")
	}
	for _, message := range messages {
		if _, err := tx.ExecContext(ctx, `UPDATE `+sqliteOutboxTable+` SET lease_until = ? WHERE id = ?`, leaseNano, message.ID); err != nil {
			return nil, domain.Wrap(err, "lifecycle.sqlite", "lease outbox")
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, domain.New(domain.CodeUnavailable, "lifecycle.sqlite", "commit claim")
	}
	return messages, nil
}

// AckOutbox removes a delivered message.
func (s *SQLiteStore) AckOutbox(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM `+sqliteOutboxTable+` WHERE id = ?`, id); err != nil {
		return domain.Wrap(err, "lifecycle.sqlite", "ack outbox")
	}
	return nil
}

// RetryOutbox schedules a retry or dead-letters it.
func (s *SQLiteStore) RetryOutbox(ctx context.Context, id string, availableAt time.Time, reason string, dead bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE `+sqliteOutboxTable+`
		SET attempts = attempts + 1, available_at = ?, lease_until = 0, last_error = ?, dead = ?
		WHERE id = ?`, availableAt.UnixNano(), reason, boolInt(dead), id)
	if err != nil {
		return domain.Wrap(err, "lifecycle.sqlite", "retry outbox")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.Wrap(domain.ErrNotFound, "lifecycle.sqlite", "outbox message not found")
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

type sqliteTx struct {
	tx  *sql.Tx
	ctx context.Context
	now func() time.Time
}

func (t *sqliteTx) Get(kind, id string) (Record, bool, error) {
	row := t.tx.QueryRowContext(t.ctx, `SELECT version, payload, deleted, updated_at FROM `+sqliteRecordsTable+` WHERE kind = ? AND id = ?`, kind, id)
	var record Record
	var version int64
	var deleted int
	var updatedAt int64
	if err := row.Scan(&version, &record.Payload, &deleted, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, domain.Wrap(err, "lifecycle.sqlite", "read record")
	}
	if deleted != 0 {
		return Record{}, false, nil
	}
	record.Kind = kind
	record.ID = id
	record.Version = uint64(version)
	record.UpdatedAt = time.Unix(0, updatedAt)
	return record, true, nil
}

func (t *sqliteTx) List(kind string) ([]Record, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT id, version, payload, deleted, updated_at FROM `+sqliteRecordsTable+` WHERE kind = ? AND deleted = 0 ORDER BY id`, kind)
	if err != nil {
		return nil, domain.Wrap(err, "lifecycle.sqlite", "list records")
	}
	defer rows.Close()
	var result []Record
	for rows.Next() {
		record := Record{Kind: kind}
		var version int64
		var deleted int
		var updatedAt int64
		if err := rows.Scan(&record.ID, &version, &record.Payload, &deleted, &updatedAt); err != nil {
			return nil, domain.Wrap(err, "lifecycle.sqlite", "scan record")
		}
		record.Version = uint64(version)
		record.UpdatedAt = time.Unix(0, updatedAt)
		result = append(result, record)
	}
	return result, rows.Err()
}

func (t *sqliteTx) GetOperation(key string) (Operation, bool, error) {
	row := t.tx.QueryRowContext(t.ctx, `SELECT request_hash, result, created_at FROM `+sqliteOperationsTable+` WHERE key = ?`, key)
	var operation Operation
	var createdAt int64
	if err := row.Scan(&operation.RequestHash, &operation.Result, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, false, nil
		}
		return Operation{}, false, domain.Wrap(err, "lifecycle.sqlite", "read operation")
	}
	operation.Key = key
	operation.CreatedAt = time.Unix(0, createdAt)
	return operation, true, nil
}

func (t *sqliteTx) PendingOutbox() int {
	var count int
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM `+sqliteOutboxTable+` WHERE dead = 0`).Scan(&count); err != nil {
		return 0
	}
	return count
}

func (t *sqliteTx) DeadOutbox() int {
	var count int
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM `+sqliteOutboxTable+` WHERE dead = 1`).Scan(&count); err != nil {
		return 0
	}
	return count
}

func (t *sqliteTx) Put(kind, id string, expectedVersion uint64, payload []byte) (Record, error) {
	if kind == "" || id == "" {
		return Record{}, domain.Invalidf("lifecycle.sqlite", "kind and id are required")
	}
	if payload == nil {
		payload = []byte{}
	}
	now := t.now().UTC().UnixNano()
	if expectedVersion == 0 {
		result, err := t.tx.ExecContext(t.ctx, `INSERT INTO `+sqliteRecordsTable+` (kind, id, version, payload, deleted, updated_at)
			VALUES (?, ?, 1, ?, 0, ?)`, kind, id, payload, now)
		if err != nil {
			return Record{}, domain.Wrap(err, "lifecycle.sqlite", "insert record")
		}
		affected, err := result.RowsAffected()
		if err != nil || affected == 0 {
			return Record{}, domain.New(domain.CodeConflict, "lifecycle.sqlite", "record already exists")
		}
		return Record{Kind: kind, ID: id, Version: 1, Payload: append([]byte(nil), payload...), UpdatedAt: time.Unix(0, now)}, nil
	}
	result, err := t.tx.ExecContext(t.ctx, `UPDATE `+sqliteRecordsTable+` SET version = ?, payload = ?, deleted = 0, updated_at = ? WHERE kind = ? AND id = ? AND version = ?`,
		expectedVersion+1, payload, now, kind, id, expectedVersion)
	if err != nil {
		return Record{}, domain.Wrap(err, "lifecycle.sqlite", "update record")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return Record{}, domain.New(domain.CodeConflict, "lifecycle.sqlite", "record version conflict")
	}
	return Record{Kind: kind, ID: id, Version: expectedVersion + 1, Payload: append([]byte(nil), payload...), UpdatedAt: time.Unix(0, now)}, nil
}

func (t *sqliteTx) Delete(kind, id string, expectedVersion uint64) error {
	if expectedVersion == 0 {
		return domain.Invalidf("lifecycle.sqlite", "expected version is required")
	}
	result, err := t.tx.ExecContext(t.ctx, `DELETE FROM `+sqliteRecordsTable+` WHERE kind = ? AND id = ? AND version = ?`, kind, id, expectedVersion)
	if err != nil {
		return domain.Wrap(err, "lifecycle.sqlite", "delete record")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.sqlite", "record version conflict")
	}
	return nil
}

func (t *sqliteTx) PutOperation(operation Operation) error {
	if operation.Key == "" {
		return domain.Invalidf("lifecycle.sqlite", "operation key is required")
	}
	createdAt := operation.CreatedAt
	if createdAt.IsZero() {
		createdAt = t.now().UTC()
	}
	result := operation.Result
	if result == nil {
		result = []byte{}
	}
	execResult, err := t.tx.ExecContext(t.ctx, `INSERT INTO `+sqliteOperationsTable+` (key, request_hash, result, created_at) VALUES (?, ?, ?, ?)`,
		operation.Key, operation.RequestHash, result, createdAt.UnixNano())
	if err != nil {
		return domain.Wrap(err, "lifecycle.sqlite", "insert operation")
	}
	affected, err := execResult.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.sqlite", "operation already exists")
	}
	return nil
}

func (t *sqliteTx) DeleteOperation(key string) error {
	if key == "" {
		return domain.Invalidf("lifecycle.sqlite", "operation key is required")
	}
	result, err := t.tx.ExecContext(t.ctx, `DELETE FROM `+sqliteOperationsTable+` WHERE key = ?`, key)
	if err != nil {
		return domain.Wrap(err, "lifecycle.sqlite", "delete operation")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.sqlite", "operation does not exist")
	}
	return nil
}

func (t *sqliteTx) Enqueue(message OutboxMessage) error {
	if message.ID == "" || message.Topic == "" {
		return domain.Invalidf("lifecycle.sqlite", "message id and topic are required")
	}
	availableAt := message.AvailableAt
	if availableAt.IsZero() {
		availableAt = t.now().UTC()
	}
	payload := message.Payload
	if payload == nil {
		payload = []byte{}
	}
	result, err := t.tx.ExecContext(t.ctx, `INSERT INTO `+sqliteOutboxTable+` (id, topic, payload, attempts, available_at, lease_until, last_error, dead)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?)`, message.ID, message.Topic, payload, message.Attempts, availableAt.UnixNano(), message.LastError, boolInt(message.Dead))
	if err != nil {
		return domain.Wrap(err, "lifecycle.sqlite", "enqueue outbox")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.New(domain.CodeConflict, "lifecycle.sqlite", "outbox message already exists")
	}
	return nil
}

var _ Store = (*SQLiteStore)(nil)
