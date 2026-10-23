package credentialstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestFileStorePersistsEncryptedRotations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	secret := testSecret()
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte("super-secret-token")) {
		t.Fatalf("store file contains plaintext")
	}
	reopened, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	loaded, err := reopened.Get(context.Background(), "cred-1")
	if err != nil || string(loaded.Material) != "super-secret-token" {
		t.Fatalf("loaded = %q %v", loaded.Material, err)
	}
	if _, err := reopened.Rotate(context.Background(), "cred-1", []byte("rotated"), secret.ExpiresAt); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	again, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("reopen after rotate: %v", err)
	}
	rotated, err := again.Get(context.Background(), "cred-1")
	if err != nil || string(rotated.Material) != "rotated" || rotated.Revision != 2 {
		t.Fatalf("rotated = %+v %v", rotated, err)
	}
	if err := again.Delete(context.Background(), "cred-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	final, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("reopen after delete: %v", err)
	}
	if _, err := final.Get(context.Background(), "cred-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted credential = %v", err)
	}
}

func TestFileStoreWrongKeyAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := NewFileStore(path, key)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	wrong, err := NewFileStore(path, []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("wrong key open: %v", err)
	}
	if _, err := wrong.Get(context.Background(), "cred-1"); err == nil {
		t.Fatalf("wrong key decrypted material")
	}
	if _, err := NewFileStore("", key); err == nil {
		t.Fatalf("empty path accepted")
	}
	if _, err := NewFileStore(path, []byte("short")); err == nil {
		t.Fatalf("short key accepted")
	}
}
