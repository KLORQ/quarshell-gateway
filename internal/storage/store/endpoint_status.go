package store

import (
	"fmt"
	"time"
)

// ReplaceEndpointStatuses replaces the complete endpoint inventory for one
// sandbox under an optional resource-version precondition. A successful update
// increments the sandbox resource version so concurrent report cursors observe
// one durable authority transition.
func (s *Store) ReplaceEndpointStatuses(name string, expectedResourceVersion uint64, statuses []EndpointStatusRecord) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedResourceVersion != 0 && expectedResourceVersion != sb.ResourceVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if sb.ResourceVersion == ^uint64(0) {
		return Sandbox{}, fmt.Errorf("sandbox resource version overflow")
	}
	previous := cloneSandbox(sb)
	sb = cloneSandbox(sb)
	now := time.Now().UTC()
	next := make([]EndpointStatusRecord, len(statuses))
	for i, status := range statuses {
		if status.EndpointID == "" || status.Host == "" || status.Path == "" {
			return Sandbox{}, fmt.Errorf("endpoint status identity is incomplete")
		}
		if status.LastResult < 0 {
			return Sandbox{}, fmt.Errorf("endpoint status result is invalid")
		}
		next[i] = status
		next[i].Ports = append([]uint32(nil), status.Ports...)
		if status.LastReportedAt.IsZero() {
			next[i].LastReportedAt = time.Time{}
		} else {
			next[i].LastReportedAt = status.LastReportedAt.UTC()
		}
	}
	sb.EndpointStatuses = next
	sb.ResourceVersion++
	sb.UpdatedAt = now
	s.state.Sandboxes[name] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[name] = previous
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// EndpointStatuses returns a copy of the durable endpoint inventory.
func (s *Store) EndpointStatuses(name string) []EndpointStatusRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return nil
	}
	return cloneEndpointStatuses(sb.EndpointStatuses)
}
