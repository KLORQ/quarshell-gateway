package credentialstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var postgresTablePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// PostgresConfig configures the PostgreSQL credential store.
type PostgresConfig struct {
	URL   string
	Key   []byte
	Table string
}

// PostgresStore stores encrypted credential records in PostgreSQL.
type PostgresStore struct {
	db    *sql.DB
	table string
	box   *cipherBox
}

// NewPostgresStore validates config, pings the database, and creates the table.
func NewPostgresStore(ctx context.Context, config PostgresConfig) (*PostgresStore, error) {
	if config.URL == "" {
		return nil, domain.Invalidf("credentials.postgres", "url is required")
	}
	table := config.Table
	if table == "" {
		table = "quarshell_credentials"
	}
	if !postgresTablePattern.MatchString(table) {
		return nil, domain.Invalidf("credentials.postgres", "invalid table name")
	}
	box, err := newCipherBox(config.Key)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", config.URL)
	if err != nil {
		return nil, domain.Wrap(err, "credentials.postgres", "open database")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, domain.New(domain.CodeUnavailable, "credentials.postgres", "database unavailable")
	}
	store := &PostgresStore{db: db, table: table, box: box}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the database.
func (s *PostgresStore) Close() error { return s.db.Close() }

func (s *PostgresStore) migrate(ctx context.Context) error {
	statement := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id TEXT PRIMARY KEY,
		provider TEXT NOT NULL,
		endpoint JSONB NOT NULL,
		expires_at TIMESTAMPTZ NULL,
		revision BIGINT NOT NULL,
		nonce BYTEA NOT NULL,
		ciphertext BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`, s.table)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return domain.New(domain.CodeUnavailable, "credentials.postgres", "migration failed")
	}
	return nil
}

func (s *PostgresStore) Put(ctx context.Context, secret Secret) (uint64, error) {
	if secret.ID == "" || secret.Provider == "" {
		return 0, domain.Invalidf("credentials.postgres", "credential id and provider are required")
	}
	endpoint, err := json.Marshal(secret.Endpoint)
	if err != nil {
		return 0, domain.Wrap(err, "credentials.postgres", "encode endpoint")
	}
	nonce, ciphertext, err := s.box.seal(secret.Material)
	if err != nil {
		return 0, err
	}
	statement := fmt.Sprintf(`INSERT INTO %s (id, provider, endpoint, expires_at, revision, nonce, ciphertext)
		VALUES ($1, $2, $3, $4, 1, $5, $6)`, s.table)
	var expires any
	if !secret.ExpiresAt.IsZero() {
		expires = secret.ExpiresAt
	}
	if _, err := s.db.ExecContext(ctx, statement, string(secret.ID), string(secret.Provider), string(endpoint), expires, nonce, ciphertext); err != nil {
		if isUniqueViolation(err) {
			return 0, domain.New(domain.CodeConflict, "credentials.postgres", "credential already exists")
		}
		return 0, domain.New(domain.CodeUnavailable, "credentials.postgres", "insert failed")
	}
	return 1, nil
}

func (s *PostgresStore) Get(ctx context.Context, id domain.CredentialID) (Secret, error) {
	statement := fmt.Sprintf(`SELECT provider, endpoint, expires_at, revision, nonce, ciphertext FROM %s WHERE id = $1`, s.table)
	var provider string
	var endpoint []byte
	var expires sql.NullTime
	var revision uint64
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, statement, string(id)).Scan(&provider, &endpoint, &expires, &revision, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, domain.Wrap(domain.ErrNotFound, "credentials.postgres", "credential not found")
	}
	if err != nil {
		return Secret{}, domain.New(domain.CodeUnavailable, "credentials.postgres", "read failed")
	}
	material, err := s.box.open(nonce, ciphertext)
	if err != nil {
		return Secret{}, err
	}
	var binding EndpointBinding
	if err := json.Unmarshal(endpoint, &binding); err != nil {
		return Secret{}, domain.Wrap(err, "credentials.postgres", "decode endpoint")
	}
	secret := Secret{ID: id, Provider: domain.ProviderID(provider), Material: material, Endpoint: binding, Revision: revision}
	if expires.Valid {
		secret.ExpiresAt = expires.Time
	}
	return secret, nil
}

func (s *PostgresStore) Rotate(ctx context.Context, id domain.CredentialID, material []byte, expiresAt time.Time) (Secret, error) {
	nonce, ciphertext, err := s.box.seal(material)
	if err != nil {
		return Secret{}, err
	}
	statement := fmt.Sprintf(`UPDATE %s SET nonce = $2, ciphertext = $3, expires_at = $4, revision = revision + 1, updated_at = now()
		WHERE id = $1 RETURNING revision`, s.table)
	var expires any
	if !expiresAt.IsZero() {
		expires = expiresAt
	}
	var revision uint64
	err = s.db.QueryRowContext(ctx, statement, string(id), nonce, ciphertext, expires).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, domain.Wrap(domain.ErrNotFound, "credentials.postgres", "credential not found")
	}
	if err != nil {
		return Secret{}, domain.New(domain.CodeUnavailable, "credentials.postgres", "rotate failed")
	}
	loaded, err := s.Get(ctx, id)
	if err != nil {
		return Secret{}, err
	}
	loaded.Material = append([]byte(nil), material...)
	loaded.Revision = revision
	return loaded, nil
}

func (s *PostgresStore) Delete(ctx context.Context, id domain.CredentialID) error {
	statement := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table)
	result, err := s.db.ExecContext(ctx, statement, string(id))
	if err != nil {
		return domain.New(domain.CodeUnavailable, "credentials.postgres", "delete failed")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return domain.Wrap(domain.ErrNotFound, "credentials.postgres", "credential not found")
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
