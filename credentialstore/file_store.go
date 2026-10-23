package credentialstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

type fileEnvelope struct {
	Entries map[string]fileEntry `json:"entries"`
}

type fileEntry struct {
	Secret     fileSecret `json:"secret"`
	Nonce      string     `json:"nonce"`
	Ciphertext string     `json:"ciphertext"`
}

type fileSecret struct {
	ID        domain.CredentialID `json:"id"`
	Provider  domain.ProviderID   `json:"provider"`
	Endpoint  EndpointBinding     `json:"endpoint"`
	ExpiresAt time.Time           `json:"expires_at"`
	Revision  uint64              `json:"revision"`
}

// FileStore is an AES-GCM encrypted, atomically rewritten JSON store. It is a
// durable single-node backend; Kubernetes/Vault/database drivers are separate.
type FileStore struct {
	mu      sync.Mutex
	path    string
	box     *cipherBox
	entries map[domain.CredentialID]fileEntry
}

// NewFileStore opens or creates an encrypted store.
func NewFileStore(path string, key []byte) (*FileStore, error) {
	if path == "" {
		return nil, domain.Invalidf("credentials.store", "path is required")
	}
	box, err := newCipherBox(key)
	if err != nil {
		return nil, err
	}
	store := &FileStore{path: path, box: box, entries: map[domain.CredentialID]fileEntry{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, domain.Wrap(err, "credentials.store", "read store")
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, domain.Wrap(err, "credentials.store", "decode store")
	}
	for key, entry := range envelope.Entries {
		store.entries[domain.CredentialID(key)] = entry
	}
	return store, nil
}

func (s *FileStore) Put(ctx context.Context, secret Secret) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, domain.Wrap(classifyContextError(err), "credentials.store", "put canceled")
	}
	if secret.ID == "" || secret.Provider == "" {
		return 0, domain.Invalidf("credentials.store", "credential id and provider are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[secret.ID]; exists {
		return 0, domain.New(domain.CodeConflict, "credentials.store", "credential already exists")
	}
	nonce, ciphertext, err := s.box.seal(secret.Material)
	if err != nil {
		return 0, err
	}
	entry := fileEntry{
		Secret: fileSecret{ID: secret.ID, Provider: secret.Provider, Endpoint: secret.Endpoint, ExpiresAt: secret.ExpiresAt, Revision: 1},
		Nonce:  base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	s.entries[secret.ID] = entry
	if err := s.persist(); err != nil {
		delete(s.entries, secret.ID)
		return 0, err
	}
	return 1, nil
}

func (s *FileStore) Get(ctx context.Context, id domain.CredentialID) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, domain.Wrap(classifyContextError(err), "credentials.store", "get canceled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[id]
	if !exists {
		return Secret{}, domain.Wrap(domain.ErrNotFound, "credentials.store", "credential not found")
	}
	nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.store", "decode nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.store", "decode ciphertext")
	}
	material, err := s.box.open(nonce, ciphertext)
	if err != nil {
		return Secret{}, err
	}
	return Secret{
		ID: entry.Secret.ID, Provider: entry.Secret.Provider, Material: material,
		Endpoint: entry.Secret.Endpoint, ExpiresAt: entry.Secret.ExpiresAt, Revision: entry.Secret.Revision,
	}, nil
}

func (s *FileStore) Rotate(ctx context.Context, id domain.CredentialID, material []byte, expiresAt time.Time) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, domain.Wrap(classifyContextError(err), "credentials.store", "rotate canceled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[id]
	if !exists {
		return Secret{}, domain.Wrap(domain.ErrNotFound, "credentials.store", "credential not found")
	}
	nonce, ciphertext, err := s.box.seal(material)
	if err != nil {
		return Secret{}, err
	}
	previous := entry
	entry.Nonce = base64.StdEncoding.EncodeToString(nonce)
	entry.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	entry.Secret.Revision++
	entry.Secret.ExpiresAt = expiresAt
	s.entries[id] = entry
	if err := s.persist(); err != nil {
		s.entries[id] = previous
		return Secret{}, err
	}
	return Secret{
		ID: entry.Secret.ID, Provider: entry.Secret.Provider, Material: append([]byte(nil), material...),
		Endpoint: entry.Secret.Endpoint, ExpiresAt: entry.Secret.ExpiresAt, Revision: entry.Secret.Revision,
	}, nil
}

func (s *FileStore) Delete(ctx context.Context, id domain.CredentialID) error {
	if err := ctx.Err(); err != nil {
		return domain.Wrap(classifyContextError(err), "credentials.store", "delete canceled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[id]
	if !exists {
		return domain.Wrap(domain.ErrNotFound, "credentials.store", "credential not found")
	}
	delete(s.entries, id)
	if err := s.persist(); err != nil {
		s.entries[id] = entry
		return err
	}
	return nil
}

func (s *FileStore) persist() error {
	entries := make(map[string]fileEntry, len(s.entries))
	for id, entry := range s.entries {
		entries[string(id)] = entry
	}
	envelope := fileEnvelope{Entries: entries}
	data, err := json.Marshal(envelope)
	if err != nil {
		return domain.Wrap(err, "credentials.store", "encode store")
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return domain.Wrap(err, "credentials.store", "create store directory")
	}
	temp, err := os.CreateTemp(directory, ".credentials-*")
	if err != nil {
		return domain.Wrap(err, "credentials.store", "create temp store")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return domain.Wrap(err, "credentials.store", "chmod temp store")
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return domain.Wrap(err, "credentials.store", "write temp store")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return domain.Wrap(err, "credentials.store", "sync temp store")
	}
	if err := temp.Close(); err != nil {
		return domain.Wrap(err, "credentials.store", "close temp store")
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return domain.Wrap(err, "credentials.store", "replace store")
	}
	return nil
}
