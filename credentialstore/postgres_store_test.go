package credentialstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestPostgresStoreIntegration(t *testing.T) {
	url := os.Getenv("QUARSHELL_POSTGRES_URL")
	if url == "" {
		t.Skip("QUARSHELL_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	store, err := NewPostgresStore(ctx, PostgresConfig{
		URL: url, Table: "quarshell_credentials_it", Key: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), "DROP TABLE IF EXISTS quarshell_credentials_it")
		_ = store.Close()
	})
	if _, err := store.db.ExecContext(ctx, "DROP TABLE IF EXISTS quarshell_credentials_it"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := store.migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	secret := testSecret()
	if _, err := store.Put(ctx, secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := store.Put(ctx, secret); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Put = %v", err)
	}
	loaded, err := store.Get(ctx, "cred-1")
	if err != nil || string(loaded.Material) != "super-secret-token" || loaded.Revision != 1 {
		t.Fatalf("Get = %+v %v", loaded, err)
	}
	rotated, err := store.Rotate(ctx, "cred-1", []byte("rotated"), time.Now().Add(time.Hour))
	if err != nil || rotated.Revision != 2 || string(rotated.Material) != "rotated" {
		t.Fatalf("Rotate = %+v %v", rotated, err)
	}
	// A different key cannot decrypt the same row.
	wrong, err := NewPostgresStore(ctx, PostgresConfig{
		URL: url, Table: "quarshell_credentials_it", Key: []byte("abcdef0123456789abcdef0123456789"),
	})
	if err != nil {
		t.Fatalf("wrong-key store: %v", err)
	}
	defer wrong.Close()
	if _, err := wrong.Get(ctx, "cred-1"); err == nil {
		t.Fatalf("wrong key decrypted material")
	}
	if err := store.Delete(ctx, "cred-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, "cred-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestPostgresConfigValidation(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if _, err := NewPostgresStore(context.Background(), PostgresConfig{Key: key}); err == nil {
		t.Fatalf("empty URL accepted")
	}
	if _, err := NewPostgresStore(context.Background(), PostgresConfig{URL: "postgres://x", Key: []byte("short")}); err == nil {
		t.Fatalf("short key accepted")
	}
}
