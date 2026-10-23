// Package store persists quarshell-gateway registry state as JSON on disk.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// State is durable gateway registry state (JSON on disk).

// CreateScopedTemplate atomically creates a workspace-owned template.
func (s *Store) CreateScopedTemplate(t TemplateRecord) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	templatesWereNil := s.state.Templates == nil
	key := scopedTemplateKey(t.Workspace, t.Name)
	if _, exists := s.state.Templates[key]; exists {
		return false, nil
	}
	count := 0
	for _, existing := range s.state.Templates {
		if existing.Workspace == t.Workspace {
			count++
		}
	}
	if count >= 1000 {
		return false, ErrTemplateWorkspaceLimit
	}
	if t.ResourceVersion == 0 {
		t.ResourceVersion = 1
	}
	if templatesWereNil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	s.state.Templates[key] = cloneTemplate(t)
	if err := s.flushLocked(); err != nil {
		delete(s.state.Templates, key)
		if templatesWereNil {
			s.state.Templates = nil
		}
		return false, err
	}
	return true, nil
}

func scopedTemplateKey(workspace, name string) string { return workspace + "\x00" + name }

// GetScopedTemplate reads a workspace-owned template.

// GetScopedTemplate reads a workspace-owned template.
func (s *Store) GetScopedTemplate(workspace, name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[scopedTemplateKey(workspace, name)]
	return cloneTemplate(t), ok
}

// DeleteScopedTemplate removes only a template in the given workspace.

// DeleteScopedTemplate removes only a template in the given workspace.
func (s *Store) DeleteScopedTemplate(workspace, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopedTemplateKey(workspace, name)
	if _, ok := s.state.Templates[key]; !ok {
		return false, nil
	}
	previous := s.state.Templates[key]
	delete(s.state.Templates, key)
	if err := s.flushLocked(); err != nil {
		s.state.Templates[key] = previous
		return false, err
	}
	return true, nil
}

// ListScopedTemplates returns templates in deterministic name order.

// ListScopedTemplates returns templates in deterministic name order.
func (s *Store) ListScopedTemplates(workspace string) []TemplateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TemplateRecord, 0)
	for _, t := range s.state.Templates {
		if workspace == "" || t.Workspace == workspace {
			out = append(out, cloneTemplate(t))
		}
	}
	slices.SortFunc(out, func(a, b TemplateRecord) int {
		if byName := strings.Compare(a.Name, b.Name); byName != 0 {
			return byName
		}
		return strings.Compare(a.Workspace, b.Workspace)
	})
	return out
}

// Sandbox is one registered sandbox record.

// SetSetting stores a gateway setting key.
func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	settingsWereNil := s.state.Settings == nil
	if current, exists := s.state.Settings[key]; exists && current == value {
		return nil
	}
	if s.state.SettingsRevision == ^uint64(0) {
		return fmt.Errorf("settings revision overflow")
	}
	if settingsWereNil {
		s.state.Settings = map[string]string{}
	}
	previous, hadPrevious := s.state.Settings[key]
	previousRevision := s.state.SettingsRevision
	s.state.Settings[key] = value
	s.state.SettingsRevision++
	if err := s.flushLocked(); err != nil {
		if hadPrevious {
			s.state.Settings[key] = previous
		} else {
			delete(s.state.Settings, key)
		}
		s.state.SettingsRevision = previousRevision
		if settingsWereNil {
			s.state.Settings = nil
		}
		return err
	}
	return nil
}

// GetSetting returns a setting.

// GetSetting returns a setting.
func (s *Store) GetSetting(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.state.Settings[key]
	return v, ok
}

// DeleteSetting removes a setting.

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Settings[key]; !exists {
		return nil
	}
	if s.state.SettingsRevision == ^uint64(0) {
		return fmt.Errorf("settings revision overflow")
	}
	previous := s.state.Settings[key]
	previousRevision := s.state.SettingsRevision
	delete(s.state.Settings, key)
	s.state.SettingsRevision++
	if err := s.flushLocked(); err != nil {
		s.state.Settings[key] = previous
		s.state.SettingsRevision = previousRevision
		return err
	}
	return nil
}

// AllSettings returns a copy of settings.

// AllSettings returns a copy of settings.
func (s *Store) AllSettings() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	maps.Copy(out, s.state.Settings)
	return out
}

// SettingsSnapshot returns global settings and their monotonic revision from
// one consistent store snapshot.

// SettingsSnapshot returns global settings and their monotonic revision from
// one consistent store snapshot.
func (s *Store) SettingsSnapshot() (map[string]string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	maps.Copy(out, s.state.Settings)
	return out, s.state.SettingsRevision
}

// SandboxSettingsSnapshot returns one sandbox's scoped settings and revision.

// SandboxSettingsSnapshot returns one sandbox's scoped settings and revision.
func (s *Store) SandboxSettingsSnapshot(name string) (map[string]string, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return nil, 0, false
	}
	return maps.Clone(sb.Settings), sb.SettingsRevision, true
}

// SetSandboxSetting writes one setting and increments its sandbox revision only
// when the value changes.

// SetSandboxSetting writes one setting and increments its sandbox revision only
// when the value changes.
func (s *Store) SetSandboxSetting(name, key, value string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return 0, fmt.Errorf("sandbox %q not found", name)
	}
	sb = cloneSandbox(sb)
	if sb.Settings == nil {
		sb.Settings = map[string]string{}
	}
	if current, exists := sb.Settings[key]; exists && current == value {
		return sb.SettingsRevision, nil
	}
	if sb.SettingsRevision == ^uint64(0) {
		return sb.SettingsRevision, fmt.Errorf("sandbox settings revision overflow")
	}
	if sb.ResourceVersion == ^uint64(0) {
		return sb.SettingsRevision, fmt.Errorf("sandbox resource version overflow")
	}
	sb.Settings[key] = value
	sb.SettingsRevision++
	sb.ResourceVersion++
	if err := s.putSandboxAndFlushLocked(name, sb); err != nil {
		return sb.SettingsRevision - 1, err
	}
	return sb.SettingsRevision, nil
}

// UpsertTemplate stores a workload template.

// UpsertTemplate stores a workload template.
func (s *Store) UpsertTemplate(t TemplateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	templatesWereNil := s.state.Templates == nil
	if templatesWereNil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	previous, hadPrevious := s.state.Templates[t.Name]
	s.state.Templates[t.Name] = cloneTemplate(t)
	if err := s.flushLocked(); err != nil {
		if hadPrevious {
			s.state.Templates[t.Name] = previous
		} else {
			delete(s.state.Templates, t.Name)
		}
		if templatesWereNil {
			s.state.Templates = nil
		}
		return err
	}
	return nil
}

// GetTemplate returns a template.

// GetTemplate returns a template.
func (s *Store) GetTemplate(name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[name]
	return cloneTemplate(t), ok
}

// DeleteTemplate removes a template.

// DeleteTemplate removes a template.
func (s *Store) DeleteTemplate(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.state.Templates[name]
	delete(s.state.Templates, name)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Templates[name] = previous
		}
		return err
	}
	return nil
}

// ListTemplates returns all templates.

// ListTemplates returns all templates.
func (s *Store) ListTemplates() []TemplateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TemplateRecord, 0, len(s.state.Templates))
	for _, t := range s.state.Templates {
		out = append(out, cloneTemplate(t))
	}
	return out
}

// EnsureAuthToken returns (and creates if needed) a local-dev bearer token.

// EnsureAuthToken returns (and creates if needed) a local-dev bearer token.
func (s *Store) EnsureAuthToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.AuthToken == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		s.state.AuthToken = hex.EncodeToString(b[:])
		if err := s.flushLocked(); err != nil {
			s.state.AuthToken = ""
			return "", err
		}
	}
	return s.state.AuthToken, nil
}

// AuthToken returns the configured bearer token (may be empty).

// AuthToken returns the configured bearer token (may be empty).
func (s *Store) AuthToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.AuthToken
}

// AttachProvider appends a provider name to a sandbox attachment list.
