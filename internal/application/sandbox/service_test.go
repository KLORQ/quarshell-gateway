package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
)

type recordingRuntime struct {
	created sandboxruntime.Sandbox
	starts  int
	stops   int
}

type identityRecordingRuntime struct{ recordingRuntime }

func (*identityRecordingRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{Status: "running", WorkloadUID: 1000, WorkloadGID: 1001}, nil
}

func (r *recordingRuntime) Create(_ context.Context, input sandboxruntime.Sandbox) (string, error) {
	r.created = input
	return "runtime-id", nil
}
func (r *recordingRuntime) Start(context.Context, sandboxruntime.Sandbox) error {
	r.starts++
	return nil
}
func (r *recordingRuntime) Stop(context.Context, sandboxruntime.Sandbox) error {
	r.stops++
	return nil
}
func (*recordingRuntime) Delete(context.Context, sandboxruntime.Sandbox) error { return nil }
func (*recordingRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{}, nil
}

type tokenRecordingRuntime struct {
	recordingRuntime
	token string
}

func (r *tokenRecordingRuntime) StartWithToken(_ context.Context, _ sandboxruntime.Sandbox, token string) error {
	r.starts++
	r.token = token
	return nil
}

type credentialRecordingRuntime struct {
	recordingRuntime
	credentials driver.RuntimeLaunchCredentials
}

type recordingSupervisorSessions struct{ released []string }

func (r *recordingSupervisorSessions) ReleaseSupervisor(sandbox string) {
	r.released = append(r.released, sandbox)
}

func (r *credentialRecordingRuntime) StartWithCredentials(_ context.Context, _ sandboxruntime.Sandbox, credentials driver.RuntimeLaunchCredentials) error {
	r.starts++
	r.credentials = credentials
	return nil
}

func testRequest() Request {
	return Request{
		Workspace:      "ws",
		Sandbox:        "sb",
		Generation:     1,
		Image:          "ubuntu:24.04",
		Command:        []string{"/bin/true"},
		Labels:         map[string]string{"team": "platform"},
		IdempotencyKey: "create-1",
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	first, replayed, err := service.Create(context.Background(), testRequest())
	if err != nil || replayed {
		t.Fatalf("first = %+v replayed=%v err=%v", first, replayed, err)
	}
	second, replayed, err := service.Create(context.Background(), testRequest())
	if err != nil || !replayed {
		t.Fatalf("second = %+v replayed=%v err=%v", second, replayed, err)
	}
	if first.Image != second.Image || first.Generation != second.Generation {
		t.Fatalf("replay differs: first=%+v second=%+v", first, second)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 1 {
			t.Fatalf("pending outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStartPersistsRuntimeWorkloadIdentity(t *testing.T) {
	service, err := NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	service.Runtime = &identityRecordingRuntime{}
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	started, _, err := service.Start(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "start-identity")
	if err != nil {
		t.Fatal(err)
	}
	if started.WorkloadUID != 1000 || started.WorkloadGID != 1001 {
		t.Fatalf("started identity = %d:%d", started.WorkloadUID, started.WorkloadGID)
	}
	stored, err := service.Get(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"})
	if err != nil || stored.WorkloadUID != 1000 || stored.WorkloadGID != 1001 {
		t.Fatalf("stored identity=%d:%d err=%v", stored.WorkloadUID, stored.WorkloadGID, err)
	}
}

func TestCreateConflictsOnDifferentRequest(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	changed := testRequest()
	changed.Image = "alpine:3.20"
	if _, _, err := service.Create(context.Background(), changed); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("different request = %v", err)
	}
}

func TestCreatePassesNetworkConfigurationToRuntime(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	runtime := &recordingRuntime{}
	service.Runtime = runtime
	request := testRequest()
	request.Network = Network{
		GatewayURL: "https://gateway.example:443", ExtraHosts: []string{"host.internal:192.0.2.10"},
		PortPublish: []PortPublish{{Host: 8080, Guest: 80}},
	}
	request.DriverConfigJSON = `{"vm":{"grpc_endpoint":"http://127.0.0.1:7444"}}`
	created, _, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.RuntimeID != "runtime-id" || runtime.created.Network.GatewayURL != request.Network.GatewayURL ||
		len(runtime.created.Network.ExtraHosts) != 1 || runtime.created.Network.ExtraHosts[0] != request.Network.ExtraHosts[0] ||
		len(runtime.created.Network.PortPublish) != 1 || runtime.created.Network.PortPublish[0] != (sandboxruntime.PortPublish{Host: 8080, Guest: 80}) {
		t.Fatalf("runtime create input = %+v, stored sandbox = %+v", runtime.created, created)
	}
	if runtime.created.DriverConfigJSON != request.DriverConfigJSON || created.DriverConfigJSON != request.DriverConfigJSON {
		t.Fatalf("driver config was not persisted and forwarded: created=%q runtime=%q", created.DriverConfigJSON, runtime.created.DriverConfigJSON)
	}
}

func TestStartAndStopCallRuntimeAfterPersistingIntent(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	runtime := &recordingRuntime{}
	service.Runtime = runtime
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	started, _, err := service.Start(context.Background(), ref, 1, "start-1")
	if err != nil || started.State != "running" || started.CredentialEpoch != 2 || runtime.starts != 1 {
		t.Fatalf("Start = %+v calls=%d err=%v", started, runtime.starts, err)
	}
	stopped, _, err := service.Stop(context.Background(), ref, 1, "stop-1")
	if err != nil || stopped.State != "stopped" || runtime.stops != 1 {
		t.Fatalf("Stop = %+v calls=%d err=%v", stopped, runtime.stops, err)
	}
}

func TestStartIssuesGenerationBoundTokenOnlyToRuntime(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	service.Tokens, _ = tokenapp.NewService([]byte("0123456789abcdef0123456789abcdef"), 0)
	runtime := &tokenRecordingRuntime{}
	service.Runtime = runtime
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	started, _, err := service.Start(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "start-token")
	if err != nil || started.CredentialEpoch != 2 {
		t.Fatalf("Start()=%+v err=%v, want epoch 2", started, err)
	}
	claims, err := service.Tokens.Verify(runtime.token)
	if err != nil || claims.Generation != started.RuntimeGeneration || claims.CredentialEpoch != 2 || claims.Workspace != "" || claims.Sandbox != "sb" || claims.Subject != "openshell-supervisor" {
		t.Fatalf("runtime token claims=%+v err=%v", claims, err)
	}
	stored, err := service.Get(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"})
	if err != nil || stored.CredentialEpoch != 2 {
		t.Fatalf("stored credential epoch=%d err=%v, want 2", stored.CredentialEpoch, err)
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), runtime.token) {
		t.Fatal("supervisor token was persisted in sandbox state")
	}
	firstToken := runtime.token
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, replayed, err := service.Start(context.Background(), ref, 1, "start-token"); err != nil || !replayed || runtime.starts != 1 {
		t.Fatalf("idempotent Start replayed=%t calls=%d err=%v", replayed, runtime.starts, err)
	}
	if _, _, err := service.Stop(context.Background(), ref, 1, "stop-token"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Start(context.Background(), ref, 1, "restart-token"); err != nil {
		t.Fatal(err)
	}
	claims, err = service.Tokens.Verify(runtime.token)
	if err != nil || runtime.token == firstToken || claims.CredentialEpoch != 3 {
		t.Fatalf("restarted runtime token=%+v same=%t err=%v, want new token at epoch 3", claims, runtime.token == firstToken, err)
	}
}

func TestStartIssuesOpenShellPairedRuntimeCredentials(t *testing.T) {
	service, err := NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	service.Tokens, err = tokenapp.NewService([]byte("0123456789abcdef0123456789abcdef"), 0)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &credentialRecordingRuntime{}
	service.Runtime = runtime
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	started, _, err := service.Start(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "paired-start")
	if err != nil || started.CredentialEpoch != 2 || runtime.starts != 1 {
		t.Fatalf("Start()=%+v calls=%d err=%v", started, runtime.starts, err)
	}
	gatewayClaims, gatewayErr := service.Tokens.Verify(runtime.credentials.GatewayToken)
	sandboxClaims, sandboxErr := service.Tokens.Verify(runtime.credentials.SandboxToken)
	if gatewayErr != nil || sandboxErr != nil || gatewayClaims.Audience != "gateway" || sandboxClaims.Audience != "sandbox" || gatewayClaims.Generation != started.RuntimeGeneration || sandboxClaims.Generation != started.RuntimeGeneration || gatewayClaims.CredentialEpoch != 2 || sandboxClaims.CredentialEpoch != 2 || runtime.credentials.RuntimeGeneration != "g0000000000000002" || started.RuntimeGeneration != 2 || !canonicalSandboxSessionID(started.SessionID) || runtime.credentials.SessionID != started.SessionID || runtime.credentials.CredentialEpoch != 2 || runtime.credentials.SessionRotation != 1 || !runtime.credentials.GatewayExpiresAt.After(time.Now()) || !runtime.credentials.SandboxExpiresAt.After(time.Now()) || runtime.credentials.GatewayID != service.Tokens.GatewayID() || len(runtime.credentials.VerificationKeys) != 1 || runtime.credentials.VerificationKeys[0].KeyID != service.Tokens.KeyID() || len(runtime.credentials.VerificationKeys[0].PublicKeyPEM) == 0 {
		t.Fatalf("paired credentials=%+v Gateway claims=%+v err=%v Sandbox claims=%+v err=%v", runtime.credentials, gatewayClaims, gatewayErr, sandboxClaims, sandboxErr)
	}
	stored, err := service.Get(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), runtime.credentials.GatewayToken) || strings.Contains(string(encoded), runtime.credentials.SandboxToken) {
		t.Fatal("paired supervisor credentials were persisted in sandbox state")
	}
	firstSession := runtime.credentials.SessionID
	if err := service.StartRuntime(context.Background(), runtime, stored); err != nil {
		t.Fatalf("reconcile StartRuntime(): %v", err)
	}
	if runtime.credentials.SessionID != firstSession {
		t.Fatalf("reconcile changed durable session ID from %q to %q", firstSession, runtime.credentials.SessionID)
	}
	if _, _, err := service.Stop(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "paired-stop"); err != nil {
		t.Fatalf("Stop(): %v", err)
	}
	restarted, _, err := service.Start(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "paired-restart")
	if err != nil {
		t.Fatalf("restart Start(): %v", err)
	}
	if restarted.SessionID == firstSession || runtime.credentials.SessionID != restarted.SessionID || restarted.CredentialEpoch != 3 || restarted.RuntimeGeneration != 3 || runtime.credentials.RuntimeGeneration != "g0000000000000003" {
		t.Fatalf("restart identity=%q credentials=%q generation=%d runtime-generation=%q epoch=%d; want a new session/runtime generation at epoch 3", restarted.SessionID, runtime.credentials.SessionID, restarted.RuntimeGeneration, runtime.credentials.RuntimeGeneration, restarted.CredentialEpoch)
	}
}

func TestGetAndDelete(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	stored, err := service.Get(context.Background(), ref)
	if err != nil || stored.State != "requested" {
		t.Fatalf("Get = %+v err=%v", stored, err)
	}
	if err := service.Delete(context.Background(), ref, "delete-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := service.Get(context.Background(), ref); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	if err := service.Delete(context.Background(), ref, "delete-1"); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 2 {
			t.Fatalf("pending outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestSandboxIDsAreGloballyUniqueForOpenShellSessionClaims(t *testing.T) {
	service, err := NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Create(context.Background(), Request{Workspace: "workspace-a", Sandbox: "sandbox-global", Generation: 1, Image: "img"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Create(context.Background(), Request{Workspace: "workspace-b", Sandbox: "sandbox-global", Generation: 1, Image: "img"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate global sandbox ID error=%v, want conflict", err)
	}
	resolved, err := service.GetBySandboxID(context.Background(), "sandbox-global")
	if err != nil || resolved.Workspace != "workspace-a" {
		t.Fatalf("GetBySandboxID()=%+v err=%v", resolved, err)
	}
}

func TestReconcileOutbox(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	topics := []string{}
	reconciler := &lifecycle.Reconciler{
		Store: store,
		Handler: func(_ context.Context, message lifecycle.OutboxMessage) error {
			topics = append(topics, message.Topic)
			return nil
		},
	}
	result, err := reconciler.RunOnce(context.Background())
	if err != nil || result.Acknowledged != 1 {
		t.Fatalf("reconcile = %+v err=%v", result, err)
	}
	if len(topics) != 1 || topics[0] != "sandbox.created" {
		t.Fatalf("topics = %v", topics)
	}
}

func TestCreateValidatesRequest(t *testing.T) {
	service, _ := NewService(lifecycle.NewMemoryStore())
	cases := map[string]func(*Request){
		"missing workspace":  func(r *Request) { r.Workspace = "" },
		"missing generation": func(r *Request) { r.Generation = 0 },
		"missing image":      func(r *Request) { r.Image = " " },
		"nul command":        func(r *Request) { r.Command = []string{"a\x00b"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := testRequest()
			mutate(&request)
			if _, _, err := service.Create(context.Background(), request); err == nil {
				t.Fatalf("invalid request accepted")
			}
		})
	}
}

func TestReplayAfterRestart(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	first, _ := NewService(store)
	if _, _, err := first.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	restarted, _ := NewService(store)
	result, replayed, err := restarted.Create(context.Background(), testRequest())
	if err != nil || !replayed || result.Sandbox != "sb" {
		t.Fatalf("replay after restart = %+v replayed=%v err=%v", result, replayed, err)
	}
	reconciler := &lifecycle.Reconciler{Store: store, Handler: func(context.Context, lifecycle.OutboxMessage) error { return nil }}
	pass, err := reconciler.RunOnce(context.Background())
	if err != nil || pass.Acknowledged != 1 {
		t.Fatalf("reconcile after restart = %+v err=%v", pass, err)
	}
}

func TestSandboxObserveGenerationFence(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	observed, err := service.Observe(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "running")
	if err != nil || observed.State != "running" || observed.Generation != 1 {
		t.Fatalf("Observe = %+v %v", observed, err)
	}
	observed, err = service.Observe(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 2, "stopped")
	if err != nil || observed.Generation != 2 || observed.State != "stopped" {
		t.Fatalf("Observe newer = %+v %v", observed, err)
	}
	if _, err := service.Observe(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 1, "running"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale Observe = %v", err)
	}
	if _, err := service.Observe(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "missing"}, 3, "running"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing Observe = %v", err)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	service, _ := NewService(store)
	sessions := &recordingSupervisorSessions{}
	service.SupervisorSessions = sessions
	if _, _, err := service.Create(context.Background(), testRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	started, replayed, err := service.Start(context.Background(), ref, 1, "start-1")
	if err != nil || replayed || started.State != "running" {
		t.Fatalf("Start = %+v replayed=%v err=%v", started, replayed, err)
	}
	again, replayed, err := service.Start(context.Background(), ref, 1, "start-1")
	if err != nil || !replayed || again.State != "running" {
		t.Fatalf("Start replay = %+v replayed=%v err=%v", again, replayed, err)
	}
	stopped, replayed, err := service.Stop(context.Background(), ref, 1, "stop-1")
	if err != nil || replayed || stopped.State != "stopped" {
		t.Fatalf("Stop = %+v replayed=%v err=%v", stopped, replayed, err)
	}
	if len(sessions.released) != 1 || sessions.released[0] != "sb" {
		t.Fatalf("Stop released supervisor sessions %v, want [sb]", sessions.released)
	}
	if _, _, err := service.Start(context.Background(), ref, 0, "start-bad"); err == nil {
		t.Fatalf("zero generation accepted")
	}
	if _, _, err := service.Start(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "missing"}, 1, "start-missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing start = %v", err)
	}
}

func TestMainProcessExitIsDurableIdempotentAndGenerationBound(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := service.Create(ctx, testRequest()); err != nil {
		t.Fatal(err)
	}
	started, _, err := service.Start(ctx, ref, 1, "start-1")
	if err != nil {
		t.Fatal(err)
	}
	generation := started.RuntimeGenerationOrInitial()
	if err := service.RecordMainProcessExit(ctx, ref, generation, "supervisor-1", 17); err != nil {
		t.Fatal(err)
	}
	if err := service.RecordMainProcessExit(ctx, ref, generation, "supervisor-1", 17); err != nil {
		t.Fatalf("idempotent report: %v", err)
	}
	if err := service.RecordMainProcessExit(ctx, ref, generation, "supervisor-2", 0); err != nil {
		t.Fatalf("duplicate report did not preserve first result: %v", err)
	}
	current, err := service.Get(ctx, ref)
	if err != nil || current.State != "error" || current.MainProcessExitCode == nil || *current.MainProcessExitCode != 17 || current.MainProcessFinalized {
		t.Fatalf("recorded terminal state=%+v err=%v", current, err)
	}
	if err := service.FinalizeMainProcessExit(ctx, ref, generation, "wrong-instance"); err == nil {
		t.Fatal("finalized result from a different supervisor")
	}
	if err := service.FinalizeMainProcessExit(ctx, ref, generation, "supervisor-1"); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	current, err = service.Get(ctx, ref)
	if err != nil || !current.MainProcessFinalized {
		t.Fatalf("finalized state=%+v err=%v", current, err)
	}
	if _, _, err := service.Start(ctx, ref, 1, "start-2"); err != nil {
		t.Fatal(err)
	}
	current, err = service.Get(ctx, ref)
	if err != nil || current.MainProcessExitCode != nil || current.MainProcessInstanceID != "" || current.MainProcessFinalized {
		t.Fatalf("restart retained old terminal result: state=%+v err=%v", current, err)
	}
	if err := service.RecordMainProcessExit(ctx, ref, generation, "supervisor-1", 17); err == nil {
		t.Fatal("accepted result from a stale runtime generation")
	}
}
