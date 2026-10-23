package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSandboxRPC(t *testing.T) {
	sandboxes, err := sandbox.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	ctx := context.Background()
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	driverConfig, err := structpb.NewStruct(map[string]any{
		"vm": map[string]any{"grpc_endpoint": "http://127.0.0.1:7444"},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := server.CreateSandbox(ctx, &gatewayv1.CreateSandboxRequest{
		WorkspaceScope: selector, Name: "sb", Labels: map[string]string{"team": "x"},
		AwaitMainProcessAttachment: true,
		Spec:                       &gatewayv1.SandboxSpec{Tty: true, Template: &gatewayv1.SandboxTemplate{Image: "ubuntu:24.04", DriverConfig: driverConfig}},
	})
	if err != nil || created.GetSandbox().GetMetadata().GetName() != "sb" {
		t.Fatalf("CreateSandbox = %+v err=%v", created, err)
	}
	stored, err := sandboxes.Get(ctx, domain.SandboxRef{Workspace: "ws", Sandbox: "sb"})
	if err != nil || stored.DriverConfigJSON != `{"vm":{"grpc_endpoint":"http://127.0.0.1:7444"}}` || !stored.AwaitMainProcessAttachment || !stored.TTY {
		t.Fatalf("persisted sandbox = %+v, err=%v", stored, err)
	}
	if _, err := server.GetSandbox(ctx, &gatewayv1.GetSandboxRequest{WorkspaceScope: selector, Name: "sb"}); err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	list, err := server.ListSandboxes(ctx, &gatewayv1.ListSandboxesRequest{WorkspaceScope: selector})
	if err != nil || len(list.GetSandboxes()) != 1 {
		t.Fatalf("ListSandboxes = %+v err=%v", list, err)
	}
	started, err := server.StartSandbox(ctx, &gatewayv1.StartSandboxRequest{WorkspaceScope: selector, Name: "sb"})
	if err != nil || started.GetSandbox().GetStatus().GetPhase() != gatewayv1.SandboxPhase_SANDBOX_PHASE_READY {
		t.Fatalf("StartSandbox = %+v err=%v", started, err)
	}
	stopped, err := server.StopSandbox(ctx, &gatewayv1.StopSandboxRequest{WorkspaceScope: selector, Name: "sb"})
	if err != nil || stopped.GetSandbox().GetStatus().GetPhase() != gatewayv1.SandboxPhase_SANDBOX_PHASE_STOPPED {
		t.Fatalf("StopSandbox = %+v err=%v", stopped, err)
	}
	deleted, err := server.DeleteSandbox(ctx, &gatewayv1.DeleteSandboxRequest{WorkspaceScope: selector, Name: "sb"})
	if err != nil || deleted.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("DeleteSandbox = %+v err=%v", deleted, err)
	}
	missing, err := server.DeleteSandbox(ctx, &gatewayv1.DeleteSandboxRequest{WorkspaceScope: selector, Name: "sb", AllowMissing: true})
	if err != nil || missing.GetOutcome() != gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT {
		t.Fatalf("Delete missing = %+v err=%v", missing, err)
	}
}

func TestSandboxPhaseMapsCanonicalProcessExitStates(t *testing.T) {
	for state, want := range map[string]gatewayv1.SandboxPhase{
		"completed": gatewayv1.SandboxPhase_SANDBOX_PHASE_COMPLETED,
		"error":     gatewayv1.SandboxPhase_SANDBOX_PHASE_ERROR,
		"failed":    gatewayv1.SandboxPhase_SANDBOX_PHASE_ERROR,
	} {
		if got := sandboxProto(sandbox.Sandbox{Sandbox: "sb", State: state}, nil).GetStatus().GetPhase(); got != want {
			t.Errorf("state %q phase=%s want=%s", state, got, want)
		}
	}
	exitCode := int32(17)
	status := sandboxProto(sandbox.Sandbox{
		Sandbox: "sb", State: "completed", MainProcessInstanceID: "instance-1", MainProcessExitCode: &exitCode,
	}, nil).GetStatus()
	if status.GetMainProcessInstanceId() != "instance-1" || status.GetExitCode() != exitCode {
		t.Fatalf("process result not projected to sandbox status: %+v", status)
	}
}

func TestSandboxProtoReportsObservedWorkloadIdentity(t *testing.T) {
	status := sandboxProto(sandbox.Sandbox{Sandbox: "sb", State: "running", WorkloadUID: 1000, WorkloadGID: 1001}, nil).GetStatus()
	if len(status.GetConditions()) != 1 {
		t.Fatalf("conditions = %+v", status.GetConditions())
	}
	condition := status.GetConditions()[0]
	if condition.GetType() != "WorkloadIdentity" || condition.GetStatus() != "True" || condition.GetMessage() != "Resolved workload UID:GID is 1000:1001" {
		t.Fatalf("workload identity condition = %+v", condition)
	}
}
