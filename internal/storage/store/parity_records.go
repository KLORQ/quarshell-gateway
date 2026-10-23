package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ErrWorkspaceNotEmpty is returned when the gateway still stores resources
// owned by a workspace.
var ErrWorkspaceNotEmpty = errors.New("workspace still contains resources")
var ErrWorkspaceConflict = errors.New("workspace changed during deletion")
var ErrWorkspaceNotFound = errors.New("workspace not found")
var ErrWorkspaceQuotaConflict = errors.New("workspace quota resource version conflict")
var ErrServiceConflict = errors.New("service name is already owned by another sandbox")

func randomRecordID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Sprintf("record-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(id[:])
}

// ServiceRecord is an exposed HTTP service routed via *.openshell.localhost.
type ServiceRecord struct {
	ID              string    `json:"id,omitempty"`
	Workspace       string    `json:"workspace,omitempty"`
	SandboxID       string    `json:"sandbox_id,omitempty"`
	Name            string    `json:"name"`
	Sandbox         string    `json:"sandbox"`
	Port            int       `json:"port"` // guest/target port
	CreatedAt       time.Time `json:"created_at,omitempty"`
	ResourceVersion uint64    `json:"resource_version,omitempty"`
	// Domain distinguishes explicit false from legacy records that default true.
	Domain            *bool     `json:"domain,omitempty"`
	AuthorizationMode string    `json:"authorization_mode,omitempty"`
	BackendHost       string    `json:"backend_host"`
	BackendPort       int       `json:"backend_port"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// WorkspaceMember is a subject with a role in a workspace.
type WorkspaceMember struct {
	ID              string    `json:"id,omitempty"`
	Subject         string    `json:"subject"`
	Role            string    `json:"role"`
	CreatedAt       time.Time `json:"created_at,omitempty"`
	ResourceVersion uint64    `json:"resource_version,omitempty"`
}

// WorkspaceRecord is a named workspace with members.
type WorkspaceRecord struct {
	Name              string            `json:"name"`
	ID                string            `json:"id,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Members           []WorkspaceMember `json:"members,omitempty"`
	Quota             WorkspaceQuota    `json:"quota,omitempty"`
	ResourceVersion   uint64            `json:"resource_version,omitempty"`
	DeletionTimestamp time.Time         `json:"deletion_timestamp,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// WorkspaceQuota caps aggregate allocations. Zero means unlimited.
type WorkspaceQuota struct {
	CPUMilliCores         uint64 `json:"cpu_millicores,omitempty"`
	MemoryBytes           uint64 `json:"memory_bytes,omitempty"`
	GPUCount              uint32 `json:"gpu_count,omitempty"`
	ConcurrentSandboxes   uint32 `json:"concurrent_sandboxes,omitempty"`
	ConcurrentGUISessions uint32 `json:"concurrent_gui_sessions,omitempty"`
}

// CreateWorkspace inserts a workspace without replacing an existing record.
func (s *Store) CreateWorkspace(ws WorkspaceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	workspacesWereNil := s.state.Workspaces == nil
	if s.state.Workspaces == nil {
		s.state.Workspaces = map[string]WorkspaceRecord{}
	}
	if _, exists := s.state.Workspaces[ws.Name]; exists {
		return fmt.Errorf("workspace %q already exists", ws.Name)
	}
	now := time.Now().UTC()
	if ws.CreatedAt.IsZero() {
		ws.CreatedAt = now
	}
	ws.UpdatedAt = now
	if ws.ResourceVersion == 0 {
		ws.ResourceVersion = 1
	}
	s.state.Workspaces[ws.Name] = cloneWorkspace(ws)
	if err := s.flushLocked(); err != nil {
		delete(s.state.Workspaces, ws.Name)
		if workspacesWereNil {
			s.state.Workspaces = nil
		}
		return err
	}
	return nil
}

// UpsertService stores an exposed service.
func (s *Store) UpsertService(rec ServiceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	servicesWereNil := s.state.Services == nil
	if s.state.Services == nil {
		s.state.Services = map[string]ServiceRecord{}
	}
	key := serviceStoreKey(rec.Sandbox, rec.Name)
	rec.UpdatedAt = time.Now().UTC()
	previous, existed := s.state.Services[key]
	legacyKey := ""
	if !existed {
		for candidate, current := range s.state.Services {
			if current.Sandbox == rec.Sandbox && current.Name == rec.Name {
				legacyKey, previous, existed = candidate, current, true
				break
			}
		}
	}
	if existed && previous.Sandbox != rec.Sandbox {
		return ErrServiceConflict
	}
	if existed && previous.ID != "" {
		rec.ID = previous.ID
	} else {
		rec.ID = randomRecordID()
	}
	if rec.Workspace == "" && existed {
		rec.Workspace = previous.Workspace
	}
	if rec.SandboxID == "" && existed {
		rec.SandboxID = previous.SandboxID
	}
	if existed {
		rec.CreatedAt = previous.CreatedAt
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = rec.UpdatedAt
		}
		rec.ResourceVersion = previous.ResourceVersion + 1
	} else {
		rec.CreatedAt = rec.UpdatedAt
		rec.ResourceVersion = 1
	}
	if rec.Domain == nil {
		if existed && previous.Domain != nil {
			rec.Domain = previous.Domain
		} else {
			domain := true
			rec.Domain = &domain
		}
	}
	if rec.AuthorizationMode == "" && existed && previous.AuthorizationMode != "" {
		rec.AuthorizationMode = previous.AuthorizationMode
	}
	if rec.AuthorizationMode == "" {
		rec.AuthorizationMode = "SERVICE_AUTHORIZATION_MODE_STRIP"
	}
	rec = cloneServiceRecord(rec)
	if legacyKey != "" {
		delete(s.state.Services, legacyKey)
	}
	s.state.Services[key] = rec
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Services[key] = previous
			if legacyKey != "" {
				delete(s.state.Services, key)
				s.state.Services[legacyKey] = previous
			}
		} else {
			delete(s.state.Services, key)
		}
		if servicesWereNil {
			s.state.Services = nil
		}
		return err
	}
	return nil
}

func serviceStoreKey(sandbox, name string) string {
	if name == "" {
		return "@openshell-default-service:" + sandbox
	}
	return sandbox + "--" + name
}

// GetService returns a service by name.
func (s *Store) GetService(name string) (ServiceRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.state.Services[name]; ok {
		return cloneServiceRecord(rec), true
	}
	for _, rec := range s.state.Services {
		if rec.Name == name {
			return cloneServiceRecord(rec), true
		}
	}
	return ServiceRecord{}, false
}

func (s *Store) GetServiceForSandbox(sandbox, name string) (ServiceRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.Services[serviceStoreKey(sandbox, name)]
	if ok && rec.Sandbox == sandbox {
		return cloneServiceRecord(rec), true
	}
	for _, rec := range s.state.Services {
		if rec.Sandbox == sandbox && rec.Name == name {
			return cloneServiceRecord(rec), true
		}
	}
	return ServiceRecord{}, false
}

// DeleteService removes a service.
func (s *Store) DeleteService(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := name
	previous, existed := s.state.Services[key]
	if !existed {
		for candidate, rec := range s.state.Services {
			if rec.Name == name {
				key, previous, existed = candidate, rec, true
				break
			}
		}
	}
	delete(s.state.Services, key)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Services[key] = previous
		}
		return err
	}
	return nil
}

func (s *Store) DeleteServiceForSandbox(sandbox, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := serviceStoreKey(sandbox, name)
	previous, existed := s.state.Services[key]
	if !existed || previous.Sandbox != sandbox {
		for candidate, rec := range s.state.Services {
			if rec.Sandbox == sandbox && rec.Name == name {
				key, previous, existed = candidate, rec, true
				break
			}
		}
	}
	delete(s.state.Services, key)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Services[key] = previous
		}
		return err
	}
	return nil
}

// ListServices returns all services.
func (s *Store) ListServices() []ServiceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ServiceRecord, 0, len(s.state.Services))
	for _, rec := range s.state.Services {
		out = append(out, cloneServiceRecord(rec))
	}
	return out
}

func cloneServiceRecord(rec ServiceRecord) ServiceRecord {
	if rec.Domain != nil {
		domain := *rec.Domain
		rec.Domain = &domain
	}
	return rec
}

// UpsertWorkspace stores a workspace.
func (s *Store) UpsertWorkspace(ws WorkspaceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	workspacesWereNil := s.state.Workspaces == nil
	if s.state.Workspaces == nil {
		s.state.Workspaces = map[string]WorkspaceRecord{}
	}
	now := time.Now().UTC()
	previous, existed := s.state.Workspaces[ws.Name]
	if ws.CreatedAt.IsZero() {
		if existed && !previous.CreatedAt.IsZero() {
			ws.CreatedAt = previous.CreatedAt
		} else {
			ws.CreatedAt = now
		}
	}
	if ws.ResourceVersion == 0 {
		if existed {
			if previous.ResourceVersion == ^uint64(0) {
				return fmt.Errorf("workspace resource version overflow")
			}
			ws.ResourceVersion = previous.ResourceVersion + 1
		} else {
			ws.ResourceVersion = 1
		}
	}
	if ws.ID == "" {
		if existed {
			ws.ID = previous.ID
		}
		if ws.ID == "" {
			ws.ID = randomRecordID()
		}
	}
	for i := range ws.Members {
		if ws.Members[i].ID == "" {
			ws.Members[i].ID = randomRecordID()
		}
		if ws.Members[i].CreatedAt.IsZero() {
			ws.Members[i].CreatedAt = now
		}
		if ws.Members[i].ResourceVersion == 0 {
			ws.Members[i].ResourceVersion = 1
		}
	}
	ws.UpdatedAt = now
	s.state.Workspaces[ws.Name] = cloneWorkspace(ws)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Workspaces[ws.Name] = previous
		} else {
			delete(s.state.Workspaces, ws.Name)
		}
		if workspacesWereNil {
			s.state.Workspaces = nil
		}
		return err
	}
	return nil
}

// GetWorkspace returns a workspace.
func (s *Store) GetWorkspace(name string) (WorkspaceRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	return cloneWorkspace(ws), ok
}

// UpdateWorkspaceQuota updates a workspace quota under its current resource version.
func (s *Store) UpdateWorkspaceQuota(name string, expectedResourceVersion uint64, quota WorkspaceQuota) (WorkspaceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	if !ok {
		if name == "default" && expectedResourceVersion == 0 {
			workspacesWereNil := s.state.Workspaces == nil
			now := time.Now().UTC()
			ws = WorkspaceRecord{Name: name, ID: randomRecordID(), Quota: quota, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
			if s.state.Workspaces == nil {
				s.state.Workspaces = map[string]WorkspaceRecord{}
			}
			s.state.Workspaces[name] = ws
			if err := s.flushLocked(); err != nil {
				delete(s.state.Workspaces, name)
				if workspacesWereNil {
					s.state.Workspaces = nil
				}
				return WorkspaceRecord{}, err
			}
			return cloneWorkspace(ws), nil
		}
		return WorkspaceRecord{}, ErrWorkspaceNotFound
	}
	if expectedResourceVersion == 0 || ws.ResourceVersion != expectedResourceVersion {
		return WorkspaceRecord{}, ErrWorkspaceQuotaConflict
	}
	if ws.Quota == quota {
		return cloneWorkspace(ws), nil
	}
	if ws.ResourceVersion == ^uint64(0) {
		return WorkspaceRecord{}, fmt.Errorf("workspace resource version overflow")
	}
	previous := ws
	ws.Quota = quota
	ws.ResourceVersion++
	ws.UpdatedAt = time.Now().UTC()
	s.state.Workspaces[name] = ws
	if err := s.flushLocked(); err != nil {
		s.state.Workspaces[name] = previous
		return WorkspaceRecord{}, err
	}
	return cloneWorkspace(ws), nil
}

// DeleteWorkspace removes a workspace.
func (s *Store) DeleteWorkspace(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteWorkspaceLocked(name)
}

// DeleteWorkspaceCAS removes only the workspace instance that was marked for
// deletion, preventing a delayed retry from deleting a recreated same-name record.
func (s *Store) DeleteWorkspaceCAS(name, expectedID string, expectedResourceVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	if !ok {
		return ErrWorkspaceNotFound
	}
	if ws.ID != expectedID || ws.ResourceVersion != expectedResourceVersion {
		return ErrWorkspaceConflict
	}
	return s.deleteWorkspaceLocked(name)
}

func (s *Store) deleteWorkspaceLocked(name string) error {
	if blockers := s.workspaceBlockersLocked(name); len(blockers) != 0 {
		return fmt.Errorf("%w: %s", ErrWorkspaceNotEmpty, strings.Join(blockers, ", "))
	}
	previous, existed := s.state.Workspaces[name]
	delete(s.state.Workspaces, name)
	if err := s.flushLocked(); err != nil {
		if existed {
			s.state.Workspaces[name] = previous
		}
		return err
	}
	return nil
}

// MarkWorkspaceTerminating durably fences new gateway RPC writes before the
// resource blocker scan. Repeated calls are idempotent so cleanup can retry.
func (s *Store) MarkWorkspaceTerminating(name string) (WorkspaceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	if !ok {
		return WorkspaceRecord{}, ErrWorkspaceNotFound
	}
	if ws.DeletionTimestamp.IsZero() {
		if ws.ResourceVersion == ^uint64(0) {
			return WorkspaceRecord{}, fmt.Errorf("workspace resource version overflow")
		}
		previous := ws
		ws.DeletionTimestamp = time.Now().UTC()
		ws.ResourceVersion++
		ws.UpdatedAt = ws.DeletionTimestamp
		s.state.Workspaces[name] = ws
		if err := s.flushLocked(); err != nil {
			s.state.Workspaces[name] = previous
			return WorkspaceRecord{}, err
		}
	}
	return cloneWorkspace(ws), nil
}

// MarkWorkspaceTerminatingCAS marks only the workspace instance observed by
// the caller. A stale name lookup cannot terminate a replacement record.
func (s *Store) MarkWorkspaceTerminatingCAS(name, expectedID string, expectedResourceVersion uint64) (WorkspaceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	if !ok {
		return WorkspaceRecord{}, ErrWorkspaceNotFound
	}
	if ws.ID != expectedID || ws.ResourceVersion != expectedResourceVersion {
		return WorkspaceRecord{}, ErrWorkspaceConflict
	}
	if ws.DeletionTimestamp.IsZero() {
		if ws.ResourceVersion == ^uint64(0) {
			return WorkspaceRecord{}, fmt.Errorf("workspace resource version overflow")
		}
		previous := ws
		ws.DeletionTimestamp = time.Now().UTC()
		ws.ResourceVersion++
		ws.UpdatedAt = ws.DeletionTimestamp
		s.state.Workspaces[name] = ws
		if err := s.flushLocked(); err != nil {
			s.state.Workspaces[name] = previous
			return WorkspaceRecord{}, err
		}
	}
	return cloneWorkspace(ws), nil
}

func (s *Store) workspaceBlockersLocked(workspace string) []string {
	blockers := map[string]bool{}
	sandboxes := map[string]bool{}
	for name, sb := range s.state.Sandboxes {
		if sb.Workspace == workspace {
			blockers["sandbox"] = true
			sandboxes[name] = true
		}
	}
	for _, template := range s.state.Templates {
		if template.Workspace == workspace {
			blockers["sandbox template"] = true
		}
	}
	for _, provider := range s.state.Providers {
		owner := provider.Workspace
		if owner == "" {
			owner = "default"
		}
		if owner == workspace {
			blockers["provider"] = true
		}
	}
	for _, profile := range s.state.Profiles {
		if profile.Workspace == workspace {
			blockers["provider profile"] = true
		}
	}
	for _, session := range s.state.SSHSessions {
		if sandboxes[session.Sandbox] {
			blockers["ssh session"] = true
		}
	}
	for _, service := range s.state.Services {
		if sandboxes[service.Sandbox] {
			blockers["service"] = true
		}
	}
	for _, proposal := range s.state.Proposals {
		if sandboxes[proposal.Sandbox] {
			blockers["policy proposal"] = true
		}
	}
	out := make([]string, 0, len(blockers))
	for label := range blockers {
		out = append(out, label)
	}
	slices.Sort(out)
	return out
}

// ListWorkspaces returns all workspaces.
func (s *Store) ListWorkspaces() []WorkspaceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WorkspaceRecord, 0, len(s.state.Workspaces))
	for _, ws := range s.state.Workspaces {
		out = append(out, cloneWorkspace(ws))
	}
	return out
}

// WorkspaceMemberUpsert adds or updates a member role.
func (s *Store) WorkspaceMemberUpsert(name, subject, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	if !ok {
		return fmt.Errorf("workspace %q not found", name)
	}
	previous := cloneWorkspace(ws)
	ws = cloneWorkspace(ws)
	if role == "" {
		role = "user"
	}
	found := false
	for i := range ws.Members {
		if ws.Members[i].Subject == subject {
			if ws.Members[i].ResourceVersion == ^uint64(0) {
				return fmt.Errorf("workspace member resource version overflow")
			}
			ws.Members[i].Role = role
			found = true
			break
		}
	}
	if !found {
		ws.Members = append(ws.Members, WorkspaceMember{ID: randomRecordID(), Subject: subject, Role: role, CreatedAt: time.Now().UTC(), ResourceVersion: 1})
	} else {
		for i := range ws.Members {
			if ws.Members[i].Subject == subject {
				ws.Members[i].ResourceVersion++
				break
			}
		}
	}
	ws.UpdatedAt = time.Now().UTC()
	s.state.Workspaces[name] = ws
	if err := s.flushLocked(); err != nil {
		s.state.Workspaces[name] = previous
		return err
	}
	return nil
}

// WorkspaceMemberRemove deletes a member.
func (s *Store) WorkspaceMemberRemove(name, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.state.Workspaces[name]
	if !ok {
		return fmt.Errorf("workspace %q not found", name)
	}
	previous := cloneWorkspace(ws)
	ws = cloneWorkspace(ws)
	out := ws.Members[:0]
	for _, m := range ws.Members {
		if m.Subject != subject {
			out = append(out, m)
		}
	}
	ws.Members = out
	ws.UpdatedAt = time.Now().UTC()
	s.state.Workspaces[name] = ws
	if err := s.flushLocked(); err != nil {
		s.state.Workspaces[name] = previous
		return err
	}
	return nil
}
