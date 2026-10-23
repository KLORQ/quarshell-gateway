package provider

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const (
	providerKind = "provider"
	profileKind  = "provider_profile"
)

// Provider is one configured provider definition.
type Provider struct {
	ID        domain.ProviderID `json:"id"`
	Name      string            `json:"name"`
	Driver    string            `json:"driver"`
	Config    []byte            `json:"config,omitempty"`
	Revision  uint64            `json:"revision"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Profile is one provider profile revision.
type Profile struct {
	Provider  domain.ProviderID `json:"provider"`
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Config    []byte            `json:"config,omitempty"`
	Revision  uint64            `json:"revision"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ProfileInput creates or updates one profile.
type ProfileInput struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Config []byte `json:"config,omitempty"`
}

// CreateRequest creates a provider and optional profiles.
type CreateRequest struct {
	ID             domain.ProviderID
	Name           string
	Driver         string
	Config         []byte
	Profiles       []ProfileInput
	IdempotencyKey domain.OperationID
}

// UpdateRequest replaces provider fields at an expected revision.
type UpdateRequest struct {
	ID               domain.ProviderID
	Name             string
	Driver           string
	Config           []byte
	ExpectedRevision uint64
	IdempotencyKey   domain.OperationID
}

// LintIssue reports one profile validation problem.
type LintIssue struct {
	Profile string `json:"profile"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Registry owns provider definitions and profiles.
type Registry struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
}

// NewRegistry returns a provider registry.
func NewRegistry(store lifecycle.Store) (*Registry, error) {
	if store == nil {
		return nil, domain.Invalidf("provider.registry", "store is required")
	}
	return &Registry{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// Create is idempotent per key.
func (r *Registry) Create(ctx context.Context, request CreateRequest) (Provider, bool, error) {
	if err := validateProvider(request.ID, request.Name, request.Driver, request.Config); err != nil {
		return Provider{}, false, err
	}
	if err := validateProfiles(request.Profiles); err != nil {
		return Provider{}, false, err
	}
	key := operationKey("provider.create", string(request.IdempotencyKey), string(request.ID))
	hash := digest(string(request.ID) + ":" + request.Name + ":" + request.Driver + ":" + digest(string(request.Config)) + ":" + profilesDigest(request.Profiles))
	now := r.now().UTC()
	payload, replayed, err := r.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		if _, exists, err := tx.Get(providerKind, string(request.ID)); err != nil {
			return nil, err
		} else if exists {
			return nil, domain.New(domain.CodeConflict, "provider.create", "provider already exists")
		}
		record := Provider{ID: request.ID, Name: request.Name, Driver: request.Driver, Config: append([]byte(nil), request.Config...), Revision: 1, CreatedAt: now, UpdatedAt: now}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(providerKind, string(request.ID), 0, encoded); err != nil {
			return nil, err
		}
		for _, input := range request.Profiles {
			profile := Profile{Provider: request.ID, ID: input.ID, Name: input.Name, Config: append([]byte(nil), input.Config...), Revision: 1, CreatedAt: now, UpdatedAt: now}
			profilePayload, err := json.Marshal(profile)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Put(profileKind, profileKey(request.ID, input.ID), 0, profilePayload); err != nil {
				return nil, err
			}
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":created", Topic: "provider.created", Payload: encoded}); err != nil {
			return nil, err
		}
		return encoded, nil
	})
	if err != nil {
		return Provider{}, false, err
	}
	var provider Provider
	if err := json.Unmarshal(payload, &provider); err != nil {
		return Provider{}, false, err
	}
	return provider, replayed, nil
}

// Get returns one provider.
func (r *Registry) Get(ctx context.Context, id domain.ProviderID) (Provider, error) {
	var provider Provider
	err := r.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(providerKind, string(id))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "provider.get", "provider not found")
		}
		return json.Unmarshal(record.Payload, &provider)
	})
	return provider, err
}

// List returns providers sorted by ID.
func (r *Registry) List(ctx context.Context) ([]Provider, error) {
	var result []Provider
	err := r.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(providerKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			var provider Provider
			if err := json.Unmarshal(record.Payload, &provider); err != nil {
				return err
			}
			result = append(result, provider)
		}
		return nil
	})
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, err
}

// Update replaces provider fields at the expected revision.
func (r *Registry) Update(ctx context.Context, request UpdateRequest) (Provider, error) {
	if err := validateProvider(request.ID, request.Name, request.Driver, request.Config); err != nil {
		return Provider{}, err
	}
	if request.ExpectedRevision == 0 {
		return Provider{}, domain.Invalidf("provider.update", "expected revision is required")
	}
	key := operationKey("provider.update", string(request.IdempotencyKey), string(request.ID)+":"+strconv.FormatUint(request.ExpectedRevision, 10))
	hash := digest(string(request.ID) + ":" + request.Name + ":" + request.Driver + ":" + digest(string(request.Config)) + ":" + strconv.FormatUint(request.ExpectedRevision, 10))
	now := r.now().UTC()
	payload, _, err := r.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(providerKind, string(request.ID))
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, domain.Wrap(domain.ErrNotFound, "provider.update", "provider not found")
		}
		if record.Version != request.ExpectedRevision {
			return nil, domain.New(domain.CodeConflict, "provider.update", "provider revision conflict")
		}
		var provider Provider
		if err := json.Unmarshal(record.Payload, &provider); err != nil {
			return nil, err
		}
		provider.Name = request.Name
		provider.Driver = request.Driver
		provider.Config = append([]byte(nil), request.Config...)
		provider.Revision = request.ExpectedRevision + 1
		provider.UpdatedAt = now
		encoded, err := json.Marshal(provider)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(providerKind, string(request.ID), request.ExpectedRevision, encoded); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":updated", Topic: "provider.updated", Payload: encoded}); err != nil {
			return nil, err
		}
		return encoded, nil
	})
	if err != nil {
		return Provider{}, err
	}
	var provider Provider
	if err := json.Unmarshal(payload, &provider); err != nil {
		return Provider{}, err
	}
	return provider, nil
}

// Delete removes a provider and its profiles.
func (r *Registry) Delete(ctx context.Context, id domain.ProviderID, idempotencyKey domain.OperationID) error {
	key := operationKey("provider.delete", string(idempotencyKey), string(id))
	_, _, err := r.coordinator.Execute(ctx, key, digest(string(id)), func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(providerKind, string(id))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		records, err := tx.List(profileKind)
		if err != nil {
			return nil, err
		}
		prefix := string(id) + "/"
		for _, profile := range records {
			if strings.HasPrefix(profile.ID, prefix) {
				if err := tx.Delete(profileKind, profile.ID, profile.Version); err != nil {
					return nil, err
				}
			}
		}
		if err := tx.Delete(providerKind, string(id), record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":deleted", Topic: "provider.deleted", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

// ListProfiles returns all profiles for a provider sorted by ID.
func (r *Registry) ListProfiles(ctx context.Context, id domain.ProviderID) ([]Profile, error) {
	var result []Profile
	err := r.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(profileKind)
		if err != nil {
			return err
		}
		prefix := string(id) + "/"
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			var profile Profile
			if err := json.Unmarshal(record.Payload, &profile); err != nil {
				return err
			}
			result = append(result, profile)
		}
		return nil
	})
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, err
}

// GetProfile returns one profile.
func (r *Registry) GetProfile(ctx context.Context, provider domain.ProviderID, id string) (Profile, error) {
	var profile Profile
	err := r.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(profileKind, profileKey(provider, id))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "provider.profile.get", "profile not found")
		}
		return json.Unmarshal(record.Payload, &profile)
	})
	return profile, err
}

// ImportProfiles upserts profiles atomically and is idempotent per key.
func (r *Registry) ImportProfiles(ctx context.Context, provider domain.ProviderID, inputs []ProfileInput, idempotencyKey domain.OperationID) ([]Profile, bool, error) {
	if !provider.Valid() || len(inputs) == 0 {
		return nil, false, domain.Invalidf("provider.profiles.import", "provider and profiles are required")
	}
	if err := validateProfiles(inputs); err != nil {
		return nil, false, err
	}
	key := operationKey("provider.profiles.import", string(idempotencyKey), string(provider))
	hash := digest(string(provider) + ":" + profilesDigest(inputs))
	now := r.now().UTC()
	payload, replayed, err := r.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		if _, exists, err := tx.Get(providerKind, string(provider)); err != nil {
			return nil, err
		} else if !exists {
			return nil, domain.Wrap(domain.ErrNotFound, "provider.profiles.import", "provider not found")
		}
		profiles := make([]Profile, 0, len(inputs))
		for _, input := range inputs {
			record, exists, err := tx.Get(profileKind, profileKey(provider, input.ID))
			if err != nil {
				return nil, err
			}
			profile := Profile{Provider: provider, ID: input.ID, Name: input.Name, Config: append([]byte(nil), input.Config...), Revision: 1, CreatedAt: now, UpdatedAt: now}
			version := uint64(0)
			if exists {
				if err := json.Unmarshal(record.Payload, &profile); err != nil {
					return nil, err
				}
				profile.Name = input.Name
				profile.Config = append([]byte(nil), input.Config...)
				profile.Revision++
				profile.UpdatedAt = now
				version = record.Version
			}
			encoded, err := json.Marshal(profile)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Put(profileKind, profileKey(provider, input.ID), version, encoded); err != nil {
				return nil, err
			}
			profiles = append(profiles, profile)
		}
		encoded, err := json.Marshal(profiles)
		if err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: key + ":imported", Topic: "provider.profiles.imported", Payload: encoded}); err != nil {
			return nil, err
		}
		return encoded, nil
	})
	if err != nil {
		return nil, false, err
	}
	var profiles []Profile
	if err := json.Unmarshal(payload, &profiles); err != nil {
		return nil, false, err
	}
	return profiles, replayed, nil
}

// DeleteProfile removes one profile idempotently.
func (r *Registry) DeleteProfile(ctx context.Context, provider domain.ProviderID, id string, idempotencyKey domain.OperationID) error {
	key := operationKey("provider.profile.delete", string(idempotencyKey), profileKey(provider, id))
	_, _, err := r.coordinator.Execute(ctx, key, digest(profileKey(provider, id)), func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(profileKind, profileKey(provider, id))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(profileKind, profileKey(provider, id), record.Version); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

// LintProfiles validates profiles without writing them.
func (r *Registry) LintProfiles(_ context.Context, _ domain.ProviderID, inputs []ProfileInput) ([]LintIssue, error) {
	var issues []LintIssue
	seen := map[string]bool{}
	for _, input := range inputs {
		if strings.TrimSpace(input.ID) == "" || strings.Contains(input.ID, "/") {
			issues = append(issues, LintIssue{Profile: input.ID, Field: "id", Message: "id is required and must not contain '/'"})
		}
		if seen[input.ID] {
			issues = append(issues, LintIssue{Profile: input.ID, Field: "id", Message: "duplicate profile id"})
		}
		seen[input.ID] = true
		if strings.TrimSpace(input.Name) == "" {
			issues = append(issues, LintIssue{Profile: input.ID, Field: "name", Message: "name is required"})
		}
		if len(input.Config) > 0 && !json.Valid(input.Config) {
			issues = append(issues, LintIssue{Profile: input.ID, Field: "config", Message: "config must be valid JSON"})
		}
	}
	return issues, nil
}

func validateProvider(id domain.ProviderID, name, driver string, config []byte) error {
	if !id.Valid() || strings.TrimSpace(name) == "" || strings.TrimSpace(driver) == "" {
		return domain.Invalidf("provider.validate", "id, name and driver are required")
	}
	if len(config) > 0 && !json.Valid(config) {
		return domain.Invalidf("provider.validate", "config must be valid JSON")
	}
	return nil
}

func validateProfiles(inputs []ProfileInput) error {
	seen := map[string]bool{}
	for _, input := range inputs {
		if strings.TrimSpace(input.ID) == "" || strings.Contains(input.ID, "/") || strings.TrimSpace(input.Name) == "" {
			return domain.Invalidf("provider.profiles.validate", "profile id and name are required")
		}
		if seen[input.ID] {
			return domain.Invalidf("provider.profiles.validate", "duplicate profile id")
		}
		seen[input.ID] = true
		if len(input.Config) > 0 && !json.Valid(input.Config) {
			return domain.Invalidf("provider.profiles.validate", "profile config must be valid JSON")
		}
	}
	return nil
}

func profileKey(provider domain.ProviderID, id string) string {
	return string(provider) + "/" + id
}

func operationKey(prefix, key, fallback string) string {
	if value := strings.TrimSpace(key); value != "" {
		return prefix + ":" + value
	}
	return prefix + ":" + fallback
}

func profilesDigest(inputs []ProfileInput) string {
	encoded, _ := json.Marshal(inputs)
	return digest(string(encoded))
}
