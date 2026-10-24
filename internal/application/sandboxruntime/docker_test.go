package sandboxruntime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-driver/driver"
)

type exitRecorderBackend struct {
	driver.Backend
	id         core.ID
	instanceID string
	exitCode   int32
}

func (b *exitRecorderBackend) RecordMainProcessExit(_ context.Context, id core.ID, instanceID string, exitCode int32) error {
	b.id, b.instanceID, b.exitCode = id, instanceID, exitCode
	return nil
}

func TestRecordMainProcessExitForwardsToBackend(t *testing.T) {
	backend := &exitRecorderBackend{}
	runtime := &Docker{Backend: backend}
	if err := runtime.RecordMainProcessExit(context.Background(), Sandbox{Sandbox: "sb"}, "supervisor-1", 137); err != nil {
		t.Fatal(err)
	}
	if backend.id != "sb" || backend.instanceID != "supervisor-1" || backend.exitCode != 137 {
		t.Fatalf("recorded exit = id %q instance %q code %d", backend.id, backend.instanceID, backend.exitCode)
	}
}

func TestCreateRequestRestoresVMRuntimeAssetsAndProxy(t *testing.T) {
	proxyEnv := []string{"QUARSHELL_VM_TEST=value"}
	runtime := &Docker{
		WorkspaceKind: driver.WorkspaceGuestOverlay,
		GatewayURL:    "https://gateway.example:7444",
		Runtime:       driver.RuntimeAssets{InitBinary: "/opt/quarshell/init", SupervisorBinary: "/opt/quarshell/supervisor", SSHBinary: "/opt/quarshell/sshd", EnableSSH: true},
		Proxy:         &driver.ProxySpec{Binary: "/opt/quarshell/quarshell", PolicyPath: "/var/lib/quarshell/policy.yaml", Port: 3128, Environment: proxyEnv},
	}
	request, err := runtime.createRequest(Sandbox{
		Workspace: "ws", Sandbox: "sb", Image: "image", TTY: true, AwaitMainProcessAttachment: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.Workspace.Kind != driver.WorkspaceGuestOverlay || request.Network.GatewayURL != runtime.GatewayURL {
		t.Fatalf("workspace/network = %+v / %+v", request.Workspace, request.Network)
	}
	if request.Runtime.InitBinary != runtime.Runtime.InitBinary || request.Runtime.SupervisorBinary != runtime.Runtime.SupervisorBinary || !request.Runtime.EnableSSH {
		t.Fatalf("runtime assets = %+v", request.Runtime)
	}
	if !request.Workload.TTY || !request.Workload.AwaitMainProcessAttachment {
		t.Fatalf("workload terminal settings = %+v", request.Workload)
	}
	if request.Network.Proxy == nil || request.Network.Proxy.Binary != runtime.Proxy.Binary || request.Network.Proxy.PolicyPath != runtime.Proxy.PolicyPath || len(request.Network.Proxy.Environment) != 1 {
		t.Fatalf("proxy config = %+v", request.Network.Proxy)
	}
	request.Network.Proxy.Environment[0] = "mutated"
	if proxyEnv[0] != "QUARSHELL_VM_TEST=value" {
		t.Fatalf("proxy environment aliases gateway config: %q", proxyEnv)
	}
}

func TestSelectedDriverConfigForBackend(t *testing.T) {
	config, err := selectedDriverConfig(`{"vm":{"grpc_endpoint":"http://127.0.0.1:7444"},"docker":{"network":"isolated"}}`, driver.BackendID("vm"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"grpc_endpoint":"http://127.0.0.1:7444"}` {
		t.Fatalf("selected VM config = %s", encoded)
	}
	missing, err := selectedDriverConfig(`{"docker":{"network":"isolated"}}`, driver.BackendID("vm"))
	if err != nil || missing != nil {
		t.Fatalf("missing backend config = %#v, %v", missing, err)
	}
	if _, err := selectedDriverConfig(`{"vm":[]}`, driver.BackendID("vm")); err == nil {
		t.Fatal("selected non-object driver config was accepted")
	}
}
