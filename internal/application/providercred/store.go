// Package providercred stores encrypted provider credential material durably.
package providercred

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const recordKind = "provider_credential"

// Secret is one encrypted provider credential value.
type Secret struct {
	Workspace domain.WorkspaceID `json:"workspace"`
	Provider  domain.ProviderID  `json:"provider"`
	Key       string             `json:"key"`
	Value     string             `json:"-"`
	ExpiresAt time.Time          `json:"expires_at,omitempty"`
	Strategy  string             `json:"strategy,omitempty"`
	UpdatedAt time.Time          `json:"updated_at"`
}

type envelope struct {
	Workspace domain.WorkspaceID `json:"workspace"`
	Provider  domain.ProviderID  `json:"provider"`
	Key       string             `json:"key"`
	Nonce     string             `json:"nonce"`
	Value     string             `json:"value"`
	ExpiresAt time.Time          `json:"expires_at,omitempty"`
	Strategy  string             `json:"strategy,omitempty"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// Store encrypts values at rest with AES-256-GCM.
type Store struct {
	store lifecycle.Store
	aead  cipher.AEAD
	now   func() time.Time
}

// NewStore derives an encryption key from rawKey.
func NewStore(store lifecycle.Store, rawKey []byte) (*Store, error) {
	if store == nil || len(rawKey) == 0 {
		return nil, domain.Invalidf("providercred.store", "store and key are required")
	}
	key := sha256.Sum256(rawKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{store: store, aead: aead, now: time.Now}, nil
}

// Put stores one credential, replacing its previous value.
func (s *Store) Put(ctx context.Context, secret Secret) error {
	if !secret.Workspace.Valid() || secret.Provider == "" || secret.Key == "" || strings.Contains(secret.Key, "/") || secret.Value == "" {
		return domain.Invalidf("providercred.store", "workspace, provider, key and value are required")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := s.aead.Seal(nil, nonce, []byte(secret.Value), nil)
	secret.UpdatedAt = s.now().UTC()
	payload, err := json.Marshal(envelope{
		Workspace: secret.Workspace, Provider: secret.Provider, Key: secret.Key,
		Nonce: base64.RawStdEncoding.EncodeToString(nonce), Value: base64.RawStdEncoding.EncodeToString(ciphertext),
		ExpiresAt: secret.ExpiresAt, Strategy: secret.Strategy, UpdatedAt: secret.UpdatedAt,
	})
	if err != nil {
		return err
	}
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		version := uint64(0)
		if record, exists, err := tx.Get(recordKind, recordID(secret)); err != nil {
			return err
		} else if exists {
			version = record.Version
		}
		_, err := tx.Put(recordKind, recordID(secret), version, payload)
		return err
	})
}

// Get returns one decrypted credential.
func (s *Store) Get(ctx context.Context, workspace domain.WorkspaceID, provider domain.ProviderID, key string) (Secret, error) {
	var out Secret
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(recordKind, keyID(workspace, provider, key))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "providercred.store", "credential not found")
		}
		secret, err := s.decrypt(record.Payload)
		if err != nil {
			return err
		}
		out = secret
		return nil
	})
	return out, err
}

// Delete removes one credential.
func (s *Store) Delete(ctx context.Context, workspace domain.WorkspaceID, provider domain.ProviderID, key string) error {
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(recordKind, keyID(workspace, provider, key))
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		return tx.Delete(recordKind, keyID(workspace, provider, key), record.Version)
	})
}

// List returns all credentials for provider.
func (s *Store) List(ctx context.Context, workspace domain.WorkspaceID, provider domain.ProviderID) ([]Secret, error) {
	var out []Secret
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(recordKind)
		if err != nil {
			return err
		}
		prefix := string(workspace) + "/" + string(provider) + "/"
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			secret, err := s.decrypt(record.Payload)
			if err != nil {
				return err
			}
			out = append(out, secret)
		}
		return nil
	})
	return out, err
}

func (s *Store) decrypt(payload []byte) (Secret, error) {
	var value envelope
	if err := json.Unmarshal(payload, &value); err != nil {
		return Secret{}, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(value.Nonce)
	if err != nil {
		return Secret{}, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(value.Value)
	if err != nil {
		return Secret{}, err
	}
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Secret{}, domain.New(domain.CodeInternal, "providercred.store", "credential decryption failed")
	}
	return Secret{Workspace: value.Workspace, Provider: value.Provider, Key: value.Key, Value: string(plaintext), ExpiresAt: value.ExpiresAt, Strategy: value.Strategy, UpdatedAt: value.UpdatedAt}, nil
}

func keyID(workspace domain.WorkspaceID, provider domain.ProviderID, key string) string {
	return string(workspace) + "/" + string(provider) + "/" + key
}

func recordID(secret Secret) string { return keyID(secret.Workspace, secret.Provider, secret.Key) }
