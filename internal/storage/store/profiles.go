// Package store persists quarshell-gateway registry state as JSON on disk.
package store

import (
	"fmt"
	"slices"
	"strconv"
	"time"
)

// State is durable gateway registry state (JSON on disk).

// UpsertProfile stores a custom profile YAML.
func (s *Store) UpsertProfile(id, yaml string) error {
	return s.UpsertProfileScoped("global", "", id, yaml)
}

func (s *Store) UpsertProfileScoped(scope, workspace, id, yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profilesWasNil := s.state.Profiles == nil
	if s.state.Profiles == nil {
		s.state.Profiles = map[string]ProfileRecord{}
	}
	key := profileStorageKey(scope, workspace, id)
	previous, existed := s.state.Profiles[key]
	if existed && previous.Version == ^uint64(0) {
		return fmt.Errorf("provider profile %q version overflow", id)
	}
	version := s.state.Profiles[key].Version + 1
	s.state.Profiles[key] = ProfileRecord{ID: id, Scope: scope, Workspace: workspace, YAML: yaml, ResourceVersion: strconv.FormatUint(version, 10), Version: version}
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Profiles[key] = previous
		} else {
			delete(s.state.Profiles, key)
		}
		if profilesWasNil {
			s.state.Profiles = nil
		}
		return err
	}
	return nil
}

// CreateProfile stores a custom profile only when its ID is not already imported.

// CreateProfile stores a custom profile only when its ID is not already imported.
func (s *Store) CreateProfile(id, yaml string) error {
	return s.CreateProfileScoped("global", "", id, yaml)
}

func (s *Store) CreateProfileScoped(scope, workspace, id, yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profilesWasNil := s.state.Profiles == nil
	if s.state.Profiles == nil {
		s.state.Profiles = map[string]ProfileRecord{}
	}
	key := profileStorageKey(scope, workspace, id)
	if _, exists := s.state.Profiles[key]; exists {
		return fmt.Errorf("provider profile %q already exists; use profile update", id)
	}
	s.state.Profiles[key] = ProfileRecord{ID: id, Scope: scope, Workspace: workspace, YAML: yaml, ResourceVersion: "1", Version: 1}
	if err := s.flushLocked(); err != nil {
		delete(s.state.Profiles, key)
		if profilesWasNil {
			s.state.Profiles = nil
		}
		return err
	}
	return nil
}

// ReplaceProfile updates an existing imported profile without silently creating it.

// ReplaceProfile updates an existing imported profile without silently creating it.
func (s *Store) ReplaceProfile(id, yaml string) error {
	return s.ReplaceProfileIfVersion(id, yaml, "")
}

// ReplaceProfileIfVersion atomically updates a profile when its current version
// matches expected. An empty expected value is retained for internal callers.

// ReplaceProfileIfVersion atomically updates a profile when its current version
// matches expected. An empty expected value is retained for internal callers.
func (s *Store) ReplaceProfileIfVersion(id, yaml, expected string) error {
	return s.ReplaceProfileIfVersionScoped("global", "", id, yaml, expected)
}

func (s *Store) ReplaceProfileIfVersionScoped(scope, workspace, id, yaml, expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := profileStorageKey(scope, workspace, id)
	current, exists := s.state.Profiles[key]
	if !exists {
		return fmt.Errorf("provider profile %q not found; use profile import", id)
	}
	currentVersion := strconv.FormatUint(current.Version, 10)
	if current.Version == 0 {
		currentVersion = "1" // legacy profile records start at the first numeric version
	}
	if expected != "" && currentVersion != expected {
		return fmt.Errorf("provider profile %q changed since it was read", id)
	}
	previous := current
	version := current.Version + 1
	if current.Version == ^uint64(0) {
		return fmt.Errorf("provider profile %q version overflow", id)
	}
	if version == 1 {
		version = 2 // migrate records written before numeric profile versions
	}
	s.state.Profiles[key] = ProfileRecord{ID: id, Scope: scope, Workspace: workspace, YAML: yaml, ResourceVersion: strconv.FormatUint(version, 10), Version: version}
	if err := s.flushLocked(); err != nil {
		s.state.Profiles[key] = previous
		return err
	}
	return nil
}

// DeleteProfile removes a custom profile.

// DeleteProfile removes a custom profile.
func (s *Store) DeleteProfile(id string) error {
	return s.DeleteProfileScoped("global", "", id)
}

func (s *Store) DeleteProfileScoped(scope, workspace, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := profileStorageKey(scope, workspace, id)
	previous, existed := s.state.Profiles[key]
	delete(s.state.Profiles, key)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Profiles[key] = previous
		}
		return err
	}
	return nil
}

// GetProfile returns a custom profile if present.

// GetProfile returns a custom profile if present.
func (s *Store) GetProfile(id string) (ProfileRecord, bool) {
	return s.GetProfileInScope("global", "", id)
}

// GetProfileScoped resolves a workspace override before the global catalog.

// GetProfileScoped resolves a workspace override before the global catalog.
func (s *Store) GetProfileScoped(id, workspace string) (ProfileRecord, bool) {
	if workspace != "" {
		if p, ok := s.GetProfileInScope("workspace", workspace, id); ok {
			return p, true
		}
	}
	return s.GetProfileInScope("global", "", id)
}

// GetProfileInScope reads one exact catalog scope without applying fallback.

// GetProfileInScope reads one exact catalog scope without applying fallback.
func (s *Store) GetProfileInScope(scope, workspace, id string) (ProfileRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := profileStorageKey(scope, workspace, id)
	p, ok := s.state.Profiles[key]
	if !ok && scope == "global" {
		p, ok = s.state.Profiles[id] // legacy records were keyed directly by ID
	}
	if ok {
		if p.Version > 0 {
			p.ResourceVersion = strconv.FormatUint(p.Version, 10)
		} else {
			p.Version = 1
			p.ResourceVersion = "1"
		}
	}
	return p, ok
}

func profileStorageKey(scope, workspace, id string) string {
	if scope == "workspace" {
		return "workspace/" + workspace + "/" + id
	}
	return id
}

// UpsertProvider stores a provider instance (env refs only).

// UpsertProvider stores a provider instance (env refs only).
func (s *Store) UpsertProvider(rec ProviderRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	providersWasNil := s.state.Providers == nil
	if s.state.Providers == nil {
		s.state.Providers = map[string]ProviderRecord{}
	}
	previous, existed := s.state.Providers[rec.Name]
	if existed {
		prev := previous
		if prev.ResourceVersion == ^uint64(0) {
			return fmt.Errorf("provider resource version overflow")
		}
		rec.ResourceVersion = prev.ResourceVersion + 1
		if rec.Refresh == nil && prev.Refresh != nil {
			rec.Refresh = prev.Refresh
		}
		if rec.CredentialExpiresAtMS == nil && prev.CredentialExpiresAtMS != nil {
			rec.CredentialExpiresAtMS = prev.CredentialExpiresAtMS
		}
	} else if rec.ResourceVersion == 0 {
		rec.ResourceVersion = 1
	}
	s.state.Providers[rec.Name] = cloneProvider(rec)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Providers[rec.Name] = previous
		} else {
			delete(s.state.Providers, rec.Name)
		}
		if providersWasNil {
			s.state.Providers = nil
		}
		return err
	}
	return nil
}

// DeleteProvider removes a provider instance.

// DeleteProvider removes a provider instance.
func (s *Store) DeleteProvider(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.state.Providers[name]
	delete(s.state.Providers, name)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Providers[name] = previous
		}
		return err
	}
	return nil
}

// GetProvider returns a provider instance.

// GetProvider returns a provider instance.
func (s *Store) GetProvider(name string) (ProviderRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.Providers[name]
	return cloneProvider(p), ok
}

// SetSetting stores a gateway setting key.

// AttachProvider appends a provider name to a sandbox attachment list.
func (s *Store) AttachProvider(sandbox, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandbox)
	}
	if slices.Contains(sb.AttachedProviders, provider) {
		return nil
	}
	sb = cloneSandbox(sb)
	sb.AttachedProviders = append(sb.AttachedProviders, provider)
	sb.UpdatedAt = time.Now().UTC()
	return s.putSandboxAndFlushLocked(sandbox, sb)
}

// DetachProvider removes a provider from a sandbox attachment list.

// DetachProvider removes a provider from a sandbox attachment list.
func (s *Store) DetachProvider(sandbox, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandbox)
	}
	sb = cloneSandbox(sb)
	out := sb.AttachedProviders[:0]
	for _, p := range sb.AttachedProviders {
		if p != provider {
			out = append(out, p)
		}
	}
	sb.AttachedProviders = out
	sb.UpdatedAt = time.Now().UTC()
	return s.putSandboxAndFlushLocked(sandbox, sb)
}

// defaultInferenceTimeoutSeconds is the default provider request deadline.
