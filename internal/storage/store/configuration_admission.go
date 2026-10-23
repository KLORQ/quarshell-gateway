package store

import (
	"fmt"
	"time"
)

const (
	ConfigurationAdmissionPending  = "PENDING"
	ConfigurationAdmissionAccepted = "ACCEPTED"
	ConfigurationAdmissionRejected = "REJECTED"
)

// SetConfigurationAdmission replaces the gateway-owned admission record for one
// sandbox under an optional resource-version precondition. The sandbox resource
// version advances so concurrent reports reconcile against one generation.
func (s *Store) SetConfigurationAdmission(name string, expectedResourceVersion uint64, admission ConfigurationAdmissionRecord) (Sandbox, error) {
	switch admission.State {
	case ConfigurationAdmissionPending, ConfigurationAdmissionAccepted, ConfigurationAdmissionRejected:
	default:
		return Sandbox{}, fmt.Errorf("configuration admission state is invalid")
	}
	if admission.InstanceID == "" || len(admission.InstanceID) > 128 || len(admission.Error) > 1024 {
		return Sandbox{}, fmt.Errorf("configuration admission identity is invalid")
	}
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
	admission.UpdatedAt = time.Now().UTC()
	if admission.State == ConfigurationAdmissionAccepted {
		admission.Activated = true
	}
	sb.ConfigurationAdmission = &admission
	if admission.State == ConfigurationAdmissionAccepted {
		sb.ConfigurationActivated = true
	}
	sb.ResourceVersion++
	sb.UpdatedAt = admission.UpdatedAt
	s.state.Sandboxes[name] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[name] = previous
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}
