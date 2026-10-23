package credentialstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// VaultConfig configures the Vault KV v2 store.
type VaultConfig struct {
	Address    string
	Token      string
	Namespace  string
	Mount      string
	PathPrefix string
	Key        []byte
	HTTPClient *http.Client
}

// VaultStore encrypts records locally and stores them in Vault KV v2. Vault
// never receives plaintext material.
type VaultStore struct {
	address   string
	token     string
	namespace string
	mount     string
	prefix    string
	client    *http.Client
	box       *cipherBox
}

type encryptedRecord struct {
	Nonce      string     `json:"nonce"`
	Ciphertext string     `json:"ciphertext"`
	Secret     fileSecret `json:"secret"`
}

type vaultResponse struct {
	Data struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Version uint64 `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// NewVaultStore validates configuration.
func NewVaultStore(config VaultConfig) (*VaultStore, error) {
	address, err := url.Parse(config.Address)
	if err != nil || (address.Scheme != "http" && address.Scheme != "https") || address.Host == "" || address.User != nil {
		return nil, domain.Invalidf("credentials.vault", "address must be an http(s) URL without credentials")
	}
	if strings.TrimSpace(config.Token) == "" {
		return nil, domain.Invalidf("credentials.vault", "token is required")
	}
	mount := strings.Trim(config.Mount, "/")
	if mount == "" {
		mount = "secret"
	}
	if strings.Contains(mount, "..") {
		return nil, domain.Invalidf("credentials.vault", "mount is invalid")
	}
	prefix := strings.Trim(config.PathPrefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	if strings.Contains(prefix, "..") {
		return nil, domain.Invalidf("credentials.vault", "path prefix is invalid")
	}
	box, err := newCipherBox(config.Key)
	if err != nil {
		return nil, err
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &VaultStore{
		address: strings.TrimRight(config.Address, "/"), token: config.Token, namespace: config.Namespace,
		mount: mount, prefix: prefix, client: client, box: box,
	}, nil
}

func (s *VaultStore) Put(ctx context.Context, secret Secret) (uint64, error) {
	if secret.ID == "" || secret.Provider == "" {
		return 0, domain.Invalidf("credentials.vault", "credential id and provider are required")
	}
	nonce, ciphertext, err := s.box.seal(secret.Material)
	if err != nil {
		return 0, err
	}
	record := encryptedRecord{
		Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Secret: fileSecret{ID: secret.ID, Provider: secret.Provider, Endpoint: secret.Endpoint, ExpiresAt: secret.ExpiresAt, Revision: 1},
	}
	if _, err := s.write(ctx, secret.ID, record, 0); err != nil {
		return 0, err
	}
	return 1, nil
}

func (s *VaultStore) Get(ctx context.Context, id domain.CredentialID) (Secret, error) {
	record, _, err := s.read(ctx, id)
	if err != nil {
		return Secret{}, err
	}
	return s.open(record)
}

func (s *VaultStore) Rotate(ctx context.Context, id domain.CredentialID, material []byte, expiresAt time.Time) (Secret, error) {
	existing, version, err := s.read(ctx, id)
	if err != nil {
		return Secret{}, err
	}
	nonce, ciphertext, err := s.box.seal(material)
	if err != nil {
		return Secret{}, err
	}
	existing.Nonce = base64.StdEncoding.EncodeToString(nonce)
	existing.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	existing.Secret.Revision++
	existing.Secret.ExpiresAt = expiresAt
	if _, err := s.write(ctx, id, existing, version); err != nil {
		return Secret{}, err
	}
	return Secret{
		ID: existing.Secret.ID, Provider: existing.Secret.Provider, Material: append([]byte(nil), material...),
		Endpoint: existing.Secret.Endpoint, ExpiresAt: existing.Secret.ExpiresAt, Revision: existing.Secret.Revision,
	}, nil
}

func (s *VaultStore) Delete(ctx context.Context, id domain.CredentialID) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.url("metadata", string(id)), nil)
	if err != nil {
		return domain.Wrap(err, "credentials.vault", "build delete request")
	}
	response, err := s.do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return domain.Wrap(domain.ErrNotFound, "credentials.vault", "credential not found")
	}
	if response.StatusCode >= 300 {
		return vaultStatusError(response.StatusCode)
	}
	return nil
}

func (s *VaultStore) read(ctx context.Context, id domain.CredentialID) (encryptedRecord, uint64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url("data", string(id)), nil)
	if err != nil {
		return encryptedRecord{}, 0, domain.Wrap(err, "credentials.vault", "build read request")
	}
	response, err := s.do(request)
	if err != nil {
		return encryptedRecord{}, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return encryptedRecord{}, 0, domain.Wrap(domain.ErrNotFound, "credentials.vault", "credential not found")
	}
	if response.StatusCode >= 300 {
		return encryptedRecord{}, 0, vaultStatusError(response.StatusCode)
	}
	var decoded vaultResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return encryptedRecord{}, 0, domain.Wrap(err, "credentials.vault", "decode response")
	}
	raw, ok := decoded.Data.Data["record"].(string)
	if !ok {
		return encryptedRecord{}, 0, domain.Invalidf("credentials.vault", "response record is missing")
	}
	var record encryptedRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return encryptedRecord{}, 0, domain.Wrap(err, "credentials.vault", "decode record")
	}
	return record, decoded.Data.Metadata.Version, nil
}

func (s *VaultStore) write(ctx context.Context, id domain.CredentialID, record encryptedRecord, cas uint64) (uint64, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return 0, domain.Wrap(err, "credentials.vault", "encode record")
	}
	body, err := json.Marshal(map[string]any{
		"data":    map[string]any{"record": string(encoded)},
		"options": map[string]any{"cas": cas},
	})
	if err != nil {
		return 0, domain.Wrap(err, "credentials.vault", "encode request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url("data", string(id)), bytes.NewReader(body))
	if err != nil {
		return 0, domain.Wrap(err, "credentials.vault", "build write request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusBadRequest {
		return 0, domain.New(domain.CodeConflict, "credentials.vault", "vault CAS conflict")
	}
	if response.StatusCode >= 300 {
		return 0, vaultStatusError(response.StatusCode)
	}
	return record.Secret.Revision, nil
}

func (s *VaultStore) open(record encryptedRecord) (Secret, error) {
	nonce, err := base64.StdEncoding.DecodeString(record.Nonce)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.vault", "decode nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.vault", "decode ciphertext")
	}
	material, err := s.box.open(nonce, ciphertext)
	if err != nil {
		return Secret{}, err
	}
	return Secret{
		ID: record.Secret.ID, Provider: record.Secret.Provider, Material: material,
		Endpoint: record.Secret.Endpoint, ExpiresAt: record.Secret.ExpiresAt, Revision: record.Secret.Revision,
	}, nil
}

func (s *VaultStore) do(request *http.Request) (*http.Response, error) {
	request.Header.Set("X-Vault-Token", s.token)
	if s.namespace != "" {
		request.Header.Set("X-Vault-Namespace", s.namespace)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, domain.Wrap(err, "credentials.vault", "request failed")
	}
	return response, nil
}

func (s *VaultStore) url(kind, id string) string {
	return fmt.Sprintf("%s/v1/%s/%s/%s", s.address, s.mount, kind, s.prefix+url.PathEscape(id))
}

func vaultStatusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return domain.Wrap(domain.ErrPermissionDenied, "credentials.vault", "vault denied the request")
	case http.StatusNotFound:
		return domain.Wrap(domain.ErrNotFound, "credentials.vault", "credential not found")
	default:
		return domain.New(domain.CodeUnavailable, "credentials.vault", "vault returned an error")
	}
}
