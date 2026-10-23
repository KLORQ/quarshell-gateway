package health

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/compute"
)

type fakeCompute struct {
	capabilities compute.Capabilities
	err          error
}

func (f fakeCompute) Describe(context.Context) (compute.Capabilities, error) {
	return f.capabilities, f.err
}

func (f fakeCompute) Validate(context.Context, compute.CreateSpec) error { return nil }

func (f fakeCompute) Ensure(context.Context, compute.DesiredSandbox) (compute.ObservedSandbox, error) {
	return compute.ObservedSandbox{}, nil
}

func (f fakeCompute) Delete(context.Context, domain.SandboxRef) error { return nil }

func TestCheckReady(t *testing.T) {
	service := New(fakeCompute{capabilities: compute.Capabilities{
		Backend:      "fake",
		Version:      "1",
		Capabilities: domain.NewCapabilitySet(domain.CapExec),
	}})
	status, err := service.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !status.Live || !status.Ready || status.Backend != "fake" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if len(status.Capabilities) != 1 || status.Capabilities[0] != string(domain.CapExec) {
		t.Fatalf("capabilities = %v", status.Capabilities)
	}
}

func TestCheckUnavailableBackend(t *testing.T) {
	service := New(fakeCompute{err: domain.New(domain.CodeUnavailable, "compute.describe", "backend down")})
	status, err := service.Check(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !status.Live || status.Ready {
		t.Fatalf("unexpected status: %+v", status)
	}
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckWithoutBackend(t *testing.T) {
	status, err := New(nil).Check(context.Background())
	if err == nil || status.Ready {
		t.Fatalf("nil backend must be unready: %+v, %v", status, err)
	}
}
