package reconcile

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

type fakeRuntime struct{ status string }

func (f fakeRuntime) Create(context.Context, sandboxruntime.Sandbox) (string, error) { return "", nil }
func (f fakeRuntime) Start(context.Context, sandboxruntime.Sandbox) error            { return nil }
func (f fakeRuntime) Stop(context.Context, sandboxruntime.Sandbox) error             { return nil }
func (f fakeRuntime) Delete(context.Context, sandboxruntime.Sandbox) error           { return nil }
func (f fakeRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{Status: f.status}, nil
}

type recoveringRuntime struct {
	status     string
	startCalls int
	stopCalls  int
}

func (f *recoveringRuntime) Create(context.Context, sandboxruntime.Sandbox) (string, error) {
	return "", nil
}
func (f *recoveringRuntime) Start(context.Context, sandboxruntime.Sandbox) error {
	f.startCalls++
	f.status = "running"
	return nil
}
func (f *recoveringRuntime) Stop(context.Context, sandboxruntime.Sandbox) error {
	f.stopCalls++
	f.status = "stopped"
	return nil
}
func (f *recoveringRuntime) Delete(context.Context, sandboxruntime.Sandbox) error { return nil }
func (f *recoveringRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{Status: f.status}, nil
}

type tokenRecoveringRuntime struct {
	recoveringRuntime
	token string
}

type restartIntentRuntime struct {
	statuses   map[string]string
	startCalls int
	stopCalls  int
}

func (*restartIntentRuntime) Create(context.Context, sandboxruntime.Sandbox) (string, error) {
	return "", nil
}
func (r *restartIntentRuntime) Start(_ context.Context, sandbox sandboxruntime.Sandbox) error {
	r.startCalls++
	r.statuses[string(sandbox.Sandbox)] = "running"
	return nil
}
func (r *restartIntentRuntime) Stop(_ context.Context, sandbox sandboxruntime.Sandbox) error {
	r.stopCalls++
	r.statuses[string(sandbox.Sandbox)] = "stopped"
	return nil
}
func (*restartIntentRuntime) Delete(context.Context, sandboxruntime.Sandbox) error { return nil }
func (r *restartIntentRuntime) Inspect(_ context.Context, sandbox sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{Status: r.statuses[string(sandbox.Sandbox)]}, nil
}

func (f *tokenRecoveringRuntime) StartWithToken(ctx context.Context, _ sandboxruntime.Sandbox, token string) error {
	f.token = token
	return f.Start(ctx, sandboxruntime.Sandbox{})
}

func sandboxRef(workspace, name string) domain.SandboxRef {
	return domain.SandboxRef{Workspace: domain.WorkspaceID(workspace), Sandbox: domain.SandboxID(name)}
}

func TestRunReconcilesState(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	ctx := context.Background()
	if _, _, err := workspaces.Create(ctx, workspace.CreateRequest{ID: "ws", Name: "ws", Owner: "alice"}); err != nil {
		t.Fatalf("Create workspace: %v", err)
	}
	if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"}); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	if err := Run(ctx, workspaces, sandboxes, fakeRuntime{status: "running"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	current, err := sandboxes.Get(ctx, sandboxRef("ws", "sb"))
	if err != nil || current.State != "running" {
		t.Fatalf("state = %+v err=%v", current, err)
	}
}

func TestRunRestoresPersistedRunningIntent(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	ctx := context.Background()
	if _, _, err := workspaces.Create(ctx, workspace.CreateRequest{ID: "ws", Name: "ws", Owner: "alice"}); err != nil {
		t.Fatalf("Create workspace: %v", err)
	}
	current, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 1, Image: "img"})
	if err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}
	if _, _, err := sandboxes.Start(ctx, sandboxRef("ws", "sb"), 1, "start-1"); err != nil {
		t.Fatalf("Start sandbox: %v", err)
	}
	backend := &tokenRecoveringRuntime{recoveringRuntime: recoveringRuntime{status: "stopped"}}
	sandboxes.Tokens, err = tokenapp.NewService([]byte("0123456789abcdef0123456789abcdef"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, workspaces, sandboxes, backend); err != nil {
		t.Fatalf("Run: %v", err)
	}
	current, err = sandboxes.Get(ctx, sandboxRef("ws", "sb"))
	claims, tokenErr := sandboxes.Tokens.Verify(backend.token)
	if err != nil || tokenErr != nil || current.State != "running" || backend.startCalls != 1 || claims.Generation != current.RuntimeGeneration || claims.Sandbox != "sb" {
		t.Fatalf("recovered state=%+v startCalls=%d claims=%+v err=%v tokenErr=%v", current, backend.startCalls, claims, err, tokenErr)
	}
}

func TestRunPreservesRunningAndStoppedIntentAfterSQLiteRestart(t *testing.T) {
	ctx := context.Background()
	database := t.TempDir() + "/lifecycle.db"
	store, err := lifecycle.NewSQLiteStore(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	if _, _, err := workspaces.Create(ctx, workspace.CreateRequest{ID: "ws", Name: "ws", Owner: "alice"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"running", "stopped"} {
		if _, _, err := sandboxes.Create(ctx, sandbox.Request{Workspace: "ws", Sandbox: domain.SandboxID(name), Generation: 1, Image: "img"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := sandboxes.Start(ctx, sandboxRef("ws", name), 1, domain.OperationID("start-"+name)); err != nil {
			t.Fatal(err)
		}
		if name == "stopped" {
			if _, _, err := sandboxes.Stop(ctx, sandboxRef("ws", name), 1, "stop-stopped"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = lifecycle.NewSQLiteStore(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	workspaces, _ = workspace.NewService(store)
	sandboxes, _ = sandbox.NewService(store)
	runtime := &restartIntentRuntime{statuses: map[string]string{"running": "running", "stopped": "running"}}
	if err := Run(ctx, workspaces, sandboxes, runtime); err != nil {
		t.Fatalf("reconcile after database reopen: %v", err)
	}
	for name, wantState := range map[string]string{"running": "running", "stopped": "stopped"} {
		current, err := sandboxes.Get(ctx, sandboxRef("ws", name))
		if err != nil || current.State != wantState {
			t.Errorf("sandbox %s after restart = state %q err=%v, want %q", name, current.State, err, wantState)
		}
	}
	if runtime.startCalls != 0 || runtime.stopCalls != 1 {
		t.Fatalf("reconcile calls after restart: starts=%d stops=%d, want 0 and 1", runtime.startCalls, runtime.stopCalls)
	}
}
