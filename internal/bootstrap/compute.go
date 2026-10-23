package bootstrap

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-spi/compute"
)

// UnconfiguredCompute is a fail-closed compute backend used until a platform
// backend is selected. It reports no capabilities and rejects mutations.
type UnconfiguredCompute struct{}

// Describe returns an empty capability set.
func (UnconfiguredCompute) Describe(context.Context) (compute.Capabilities, error) {
	return compute.Capabilities{}, nil
}

// Validate rejects every request.
func (UnconfiguredCompute) Validate(context.Context, compute.CreateSpec) error {
	return domain.New(domain.CodeUnsupported, "compute.validate", "no compute backend configured")
}

// Ensure rejects every request.
func (UnconfiguredCompute) Ensure(context.Context, compute.DesiredSandbox) (compute.ObservedSandbox, error) {
	return compute.ObservedSandbox{}, domain.New(domain.CodeUnsupported, "compute.ensure", "no compute backend configured")
}

// Delete rejects every request.
func (UnconfiguredCompute) Delete(context.Context, domain.SandboxRef) error {
	return domain.New(domain.CodeUnsupported, "compute.delete", "no compute backend configured")
}
