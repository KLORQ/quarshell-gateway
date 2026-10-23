package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/sshrelay"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMainProcessExitHandlersPersistAndFinalizeActiveSupervisorResult(t *testing.T) {
	ctx := context.Background()
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxes.ClaimSupervisorSession(ctx, ref, started.RuntimeGenerationOrInitial(), started.CredentialEpochOrInitial(), "session-instance-1-1", "instance-1", 1); err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	defer close(done)
	_, err = hub.RegisterSupervisor("sb", "instance-1", 1, func(string, string) error { return nil }, done, func() {})
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.SupervisorHub = hub
	ctx = context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "sb", generation: started.RuntimeGeneration,
		credentialEpoch: started.CredentialEpoch,
	})

	if _, err := server.ReportMainProcessExit(ctx, &gatewayv1.ReportMainProcessExitRequest{SandboxId: "sb", InstanceId: "wrong", ExitCode: 0}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unowned report status=%s err=%v", status.Code(err), err)
	}
	if _, err := server.ReportMainProcessExit(ctx, &gatewayv1.ReportMainProcessExitRequest{SandboxId: "other", InstanceId: "instance-1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox report status=%s err=%v", status.Code(err), err)
	}
	if _, err := server.ReportMainProcessExit(ctx, &gatewayv1.ReportMainProcessExitRequest{SandboxId: "sb", InstanceId: "instance-1", ExitCode: 0}); err != nil {
		t.Fatalf("report exit: %v", err)
	}
	current, err := sandboxes.Get(ctx, ref)
	if err != nil || current.State != "completed" || current.MainProcessExitCode == nil || *current.MainProcessExitCode != 0 {
		t.Fatalf("reported sandbox=%+v err=%v", current, err)
	}
	if _, err := server.FinalizeMainProcessExit(ctx, &gatewayv1.FinalizeMainProcessExitRequest{SandboxId: "sb", InstanceId: "instance-1"}); err != nil {
		t.Fatalf("finalize exit: %v", err)
	}
	current, err = sandboxes.Get(ctx, ref)
	if err != nil || !current.MainProcessFinalized {
		t.Fatalf("finalized sandbox=%+v err=%v", current, err)
	}
	if _, ok := hub.SupervisorInstance("sb"); ok {
		t.Fatal("finalization retained the supervisor session")
	}

	stale := context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "sb", generation: started.RuntimeGeneration - 1,
		credentialEpoch: started.CredentialEpoch,
	})
	if _, err := server.ReportMainProcessExit(stale, &gatewayv1.ReportMainProcessExitRequest{SandboxId: "sb", InstanceId: "instance-1"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stale generation report status=%s err=%v", status.Code(err), err)
	}
}
