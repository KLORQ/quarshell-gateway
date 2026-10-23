// Package health exposes liveness, readiness, and backend capabilities without
// importing the legacy gateway engine.
package health

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-spi/compute"
)

// Status is the current gateway health snapshot.
type Status struct {
	Live         bool     `json:"live"`
	Ready        bool     `json:"ready"`
	Backend      string   `json:"backend,omitempty"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// Service derives readiness from the configured compute backend.
type Service struct {
	compute compute.Compute
}

// New creates a health service for a compute backend.
func New(backend compute.Compute) *Service {
	return &Service{compute: backend}
}

// Check reports liveness and backend readiness.
func (s *Service) Check(ctx context.Context) (Status, error) {
	if s == nil || s.compute == nil {
		return Status{Live: true, Ready: false}, domain.New(domain.CodeUnavailable, "health.check", "no compute backend configured")
	}
	capabilities, err := s.compute.Describe(ctx)
	if err != nil {
		return Status{Live: true, Ready: false}, err
	}
	values := capabilities.Capabilities.Values()
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, string(value))
	}
	return Status{
		Live:         true,
		Ready:        capabilities.Backend != "",
		Backend:      capabilities.Backend,
		Version:      capabilities.Version,
		Capabilities: names,
	}, nil
}
