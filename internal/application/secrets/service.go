// Package secrets exposes credential metadata and handle lifecycle. Material is
// never returned by metadata reads.
package secrets

import (
	"context"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-credentials"
)

// Metadata is credential metadata without material.
type Metadata struct {
	ID        domain.CredentialID         `json:"id"`
	Provider  domain.ProviderID           `json:"provider"`
	Endpoint  credentials.EndpointBinding `json:"endpoint"`
	ExpiresAt time.Time                   `json:"expires_at,omitempty"`
	Revision  uint64                      `json:"revision"`
}

// Service owns credential metadata and handles.
type Service struct {
	store  credentials.Store
	broker *credentials.Broker
}

// NewService returns a secrets service.
func NewService(store credentials.Store, broker *credentials.Broker) (*Service, error) {
	if store == nil || broker == nil {
		return nil, domain.Invalidf("secrets.service", "store and broker are required")
	}
	return &Service{store: store, broker: broker}, nil
}

// Create stores material and returns metadata only.
func (s *Service) Create(ctx context.Context, id domain.CredentialID, provider domain.ProviderID, material []byte, endpoint credentials.EndpointBinding, expiresAt time.Time) (Metadata, error) {
	if len(material) == 0 {
		return Metadata{}, domain.Invalidf("secrets.create", "material is required")
	}
	revision, err := s.store.Put(ctx, credentials.Secret{ID: id, Provider: provider, Material: material, Endpoint: endpoint, ExpiresAt: expiresAt})
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{ID: id, Provider: provider, Endpoint: endpoint, ExpiresAt: expiresAt, Revision: revision}, nil
}

// Get returns metadata without material.
func (s *Service) Get(ctx context.Context, id domain.CredentialID) (Metadata, error) {
	secret, err := s.store.Get(ctx, id)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{ID: secret.ID, Provider: secret.Provider, Endpoint: secret.Endpoint, ExpiresAt: secret.ExpiresAt, Revision: secret.Revision}, nil
}

// Rotate replaces material and returns metadata.
func (s *Service) Rotate(ctx context.Context, id domain.CredentialID, material []byte, expiresAt time.Time) (Metadata, error) {
	if len(material) == 0 {
		return Metadata{}, domain.Invalidf("secrets.rotate", "material is required")
	}
	revision, err := s.broker.Rotate(ctx, id, material, expiresAt)
	if err != nil {
		return Metadata{}, err
	}
	secret, err := s.store.Get(ctx, id)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{ID: secret.ID, Provider: secret.Provider, Endpoint: secret.Endpoint, ExpiresAt: secret.ExpiresAt, Revision: revision}, nil
}

// Delete removes a credential and all handles are invalidated by the broker.
func (s *Service) Delete(ctx context.Context, id domain.CredentialID) error {
	_, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.store.Delete(ctx, id)
}

// Issue returns an endpoint-bound handle.
func (s *Service) Issue(ctx context.Context, request credentials.IssueRequest) (credentials.Handle, credentials.HandleInfo, error) {
	return s.broker.Issue(ctx, request)
}

// Revoke invalidates a handle.
func (s *Service) Revoke(ctx context.Context, handle credentials.Handle) error {
	return s.broker.Revoke(ctx, handle)
}

// ValidateMaterialLen is a small guard used by transports before storing.
func ValidateMaterialLen(material []byte, max int) error {
	if max > 0 && len(material) > max {
		return domain.Invalidf("secrets.create", "material exceeds limit")
	}
	if strings.TrimSpace(string(material)) == "" {
		return domain.Invalidf("secrets.create", "material is required")
	}
	return nil
}
