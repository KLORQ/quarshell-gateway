package applicationgrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	dm "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
)

type captureSandboxWatchStream struct {
	grpc.ServerStream
	ctx    context.Context
	events chan *gatewayv1.SandboxStreamEvent
}

type watchPlatformRuntime struct {
	events    chan driver.PlatformEventResult
	runtimeID string
}

func (r *watchPlatformRuntime) Create(context.Context, sandboxruntime.Sandbox) (string, error) {
	return r.runtimeID, nil
}
func (*watchPlatformRuntime) Start(context.Context, sandboxruntime.Sandbox) error  { return nil }
func (*watchPlatformRuntime) Stop(context.Context, sandboxruntime.Sandbox) error   { return nil }
func (*watchPlatformRuntime) Delete(context.Context, sandboxruntime.Sandbox) error { return nil }
func (*watchPlatformRuntime) Inspect(context.Context, sandboxruntime.Sandbox) (driver.Info, error) {
	return driver.Info{}, nil
}
func (r *watchPlatformRuntime) WatchPlatformEvents(context.Context, sandboxruntime.Sandbox) (<-chan driver.PlatformEventResult, error) {
	return r.events, nil
}

func (s *captureSandboxWatchStream) Context() context.Context { return s.ctx }
func (s *captureSandboxWatchStream) Send(event *gatewayv1.SandboxStreamEvent) error {
	select {
	case s.events <- event:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func TestWatchSandboxReplaysTailAndPollsLogsFromOtherGatewayInstance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(context.Background(), sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(context.Background(), ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	logs, err := sandboxlogs.New(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logs.Append(context.Background(), "sb", []sandboxlogs.Line{{SandboxID: "sb", Source: "sandbox", Level: "INFO", Message: "older"}, {SandboxID: "sb", Source: "sandbox", Level: "INFO", Message: "tail"}}); err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.SandboxLogs = logs
	stream := &captureSandboxWatchStream{ctx: ctx, events: make(chan *gatewayv1.SandboxStreamEvent, 8)}
	request := &gatewayv1.WatchSandboxRequest{WorkspaceScope: &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: "ws"}}, Sandbox: "sb", FollowLogs: true, LogTailLines: 1, LogSources: []string{"sandbox"}}
	done := make(chan error, 1)
	go func() { done <- server.WatchSandbox(request, stream) }()
	select {
	case event := <-stream.events:
		if event.GetSandbox() == nil {
			t.Fatalf("initial snapshot event=%v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial sandbox snapshot")
	}
	tailCursor := ""
	select {
	case event := <-stream.events:
		if line := event.GetLog(); line == nil || line.GetMessage() != "tail" {
			t.Fatalf("tail replay event=%v", event)
		}
		tailCursor = event.GetCursor()
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tail replay")
	}

	sandboxCtx := context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "sb", generation: started.RuntimeGeneration, credentialEpoch: started.CredentialEpoch,
	})
	writerServer := New("writer", nil, sandboxes, nil, nil, nil, nil, nil)
	writerServer.SandboxLogs = logs
	push := &sandboxLogsStream{ctx: sandboxCtx, requests: []*gatewayv1.PushSandboxLogsRequest{{SandboxId: "sb", Logs: []*gatewayv1.SandboxLogLine{{SandboxId: "sb", Source: "sandbox", Level: "WARN", Message: "cross-instance"}}}}}
	if err := writerServer.PushSandboxLogs(push); err != nil {
		t.Fatal(err)
	}
	liveCursor := ""
	select {
	case event := <-stream.events:
		if line := event.GetLog(); line == nil || line.GetMessage() != "cross-instance" {
			t.Fatalf("live event=%v", event)
		}
		liveCursor = event.GetCursor()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for cross-instance live log")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stop error=%v", err)
	}

	resumeCtx, resumeCancel := context.WithCancel(context.Background())
	resumeStream := &captureSandboxWatchStream{ctx: resumeCtx, events: make(chan *gatewayv1.SandboxStreamEvent, 8)}
	resumeDone := make(chan error, 1)
	reopenedLogs, err := sandboxlogs.New(store)
	if err != nil {
		t.Fatal(err)
	}
	resumedServer := New("test-restarted", nil, sandboxes, nil, nil, nil, nil, nil)
	resumedServer.SandboxLogs = reopenedLogs
	go func() {
		resumeDone <- resumedServer.WatchSandbox(&gatewayv1.WatchSandboxRequest{
			WorkspaceScope: request.GetWorkspaceScope(), Sandbox: "sb", FollowLogs: true, ResumeAfterCursor: tailCursor,
		}, resumeStream)
	}()
	select {
	case event := <-resumeStream.events:
		if event.GetSandbox() == nil {
			t.Fatalf("resume initial snapshot event=%v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for resume sandbox snapshot")
	}
	select {
	case event := <-resumeStream.events:
		if line := event.GetLog(); line == nil || line.GetMessage() != "cross-instance" || event.GetCursor() != liveCursor {
			t.Fatalf("resumed event=%v cursor=%q want=%q", event, event.GetCursor(), liveCursor)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cursor replay")
	}
	resumeCancel()
	if err := <-resumeDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("resumed watch stop error=%v", err)
	}
}

func TestWatchSandboxStopsAtInitialTerminalPhase(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(context.Background(), sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(context.Background(), ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxes.RecordMainProcessExit(context.Background(), ref, started.RuntimeGeneration, "instance", 0); err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	stream := &captureSandboxWatchStream{ctx: context.Background(), events: make(chan *gatewayv1.SandboxStreamEvent, 1)}
	err = server.WatchSandbox(&gatewayv1.WatchSandboxRequest{
		WorkspaceScope: &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: "ws"}},
		Sandbox:        "sb", FollowStatus: true, StopOnTerminal: true,
	}, stream)
	if err != nil {
		t.Fatal(err)
	}
	event := <-stream.events
	if got := event.GetSandbox().GetStatus().GetPhase(); got != gatewayv1.SandboxPhase_SANDBOX_PHASE_COMPLETED {
		t.Fatalf("terminal watch phase=%s", got)
	}
}

func TestWatchSandboxStreamsVMPlatformEvents(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan driver.PlatformEventResult, 2)
	runtime := &watchPlatformRuntime{events: events, runtimeID: "vm-runtime-uuid"}
	sandboxes.Runtime = runtime
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(context.Background(), sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	events <- driver.PlatformEventResult{Event: driver.PlatformEvent{SandboxID: "another-runtime-uuid", Time: time.Now(), Source: "vm", Type: "sandbox_state", Reason: "spoofed", Terminal: true}}
	events <- driver.PlatformEventResult{Event: driver.PlatformEvent{SandboxID: "vm-runtime-uuid", Time: time.Now(), Source: "vm", Type: "sandbox_state", Reason: "stopped", Message: "stopped", Metadata: map[string]string{"status": "stopped"}, Terminal: true}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	stream := &captureSandboxWatchStream{ctx: ctx, events: make(chan *gatewayv1.SandboxStreamEvent, 2)}
	done := make(chan error, 1)
	go func() {
		done <- server.WatchSandbox(&gatewayv1.WatchSandboxRequest{
			WorkspaceScope: &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: "ws"}},
			Sandbox:        "sb", FollowEvents: true, StopOnTerminal: true,
		}, stream)
	}()
	if event := <-stream.events; event.GetSandbox() == nil {
		t.Fatalf("initial event=%v", event)
	}
	select {
	case event := <-stream.events:
		platform := event.GetEvent()
		if platform == nil || platform.GetSource() != "vm" || platform.GetReason() != "stopped" || platform.GetMetadata()["status"] != "stopped" {
			t.Fatalf("platform event=%v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for platform event")
	}
	if err := <-done; err != nil {
		t.Fatalf("terminal watch stop error=%v", err)
	}
	cancel()
}

func TestWatchSandboxReplaysAndResumesPlatformEvents(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(context.Background(), sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	logs, err := sandboxlogs.New(store)
	if err != nil {
		t.Fatal(err)
	}
	eventTime := time.Now().UTC()
	firstStored, created, err := logs.AppendPlatformEvent(context.Background(), sandboxlogs.PlatformEvent{
		SandboxID: "sb", EventTime: eventTime, Source: "vm", Type: "sandbox_state", Reason: "created", DedupKey: "created-event",
	})
	if err != nil || !created {
		t.Fatalf("seed event=(%+v, %v, %v)", firstStored, created, err)
	}
	if _, err := logs.Append(context.Background(), "sb", []sandboxlogs.Line{{SandboxID: "sb", EventTime: eventTime.Add(500 * time.Millisecond), Level: "INFO", Source: "sandbox", Message: "between events"}}); err != nil {
		t.Fatal(err)
	}
	runtime := &watchPlatformRuntime{events: make(chan driver.PlatformEventResult, 2)}
	sandboxes.Runtime = runtime
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.SandboxLogs = logs
	workspaceScope := &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: "ws"}}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstStream := &captureSandboxWatchStream{ctx: firstCtx, events: make(chan *gatewayv1.SandboxStreamEvent, 4)}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- server.WatchSandbox(&gatewayv1.WatchSandboxRequest{
			WorkspaceScope: workspaceScope, Sandbox: "sb", FollowLogs: true, FollowEvents: true, EventTail: 1,
		}, firstStream)
	}()
	var initialEvent *gatewayv1.SandboxStreamEvent
	select {
	case initialEvent = <-firstStream.events:
	case watchErr := <-firstDone:
		t.Fatalf("watch returned before initial snapshot: %v", watchErr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial sandbox watch snapshot")
	}
	if event := initialEvent; event.GetSandbox() == nil {
		t.Fatalf("initial snapshot=%v", event)
	}
	firstReplay := receiveSandboxWatchEvent(t, firstStream.events)
	if firstReplay.GetEvent() == nil || firstReplay.GetEvent().GetReason() != "created" || firstReplay.GetCursor() == "" {
		t.Fatalf("platform event replay=%v", firstReplay)
	}
	mergedLog := receiveSandboxWatchEvent(t, firstStream.events)
	if mergedLog.GetLog() == nil || mergedLog.GetCursor() <= firstReplay.GetCursor() {
		t.Fatalf("merged log replay=%v after platform cursor %q", mergedLog, firstReplay.GetCursor())
	}
	eventB := driver.PlatformEvent{SandboxID: "sb", Time: eventTime.Add(time.Second), Source: "vm", Type: "sandbox_state", Reason: "running", Metadata: map[string]string{"status": "running"}}
	runtime.events <- driver.PlatformEventResult{Event: eventB}
	firstLive := receiveSandboxWatchEvent(t, firstStream.events)
	if firstLive.GetEvent() == nil || firstLive.GetEvent().GetReason() != "running" || firstLive.GetCursor() <= mergedLog.GetCursor() {
		t.Fatalf("live platform event=%v after cursor %q", firstLive, mergedLog.GetCursor())
	}
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first watch stop error=%v", err)
	}

	secondEvents := make(chan driver.PlatformEventResult, 2)
	secondEvents <- driver.PlatformEventResult{Event: eventB}
	runtime.events = secondEvents
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	secondStream := &captureSandboxWatchStream{ctx: secondCtx, events: make(chan *gatewayv1.SandboxStreamEvent, 4)}
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- server.WatchSandbox(&gatewayv1.WatchSandboxRequest{
			WorkspaceScope: workspaceScope, Sandbox: "sb", FollowLogs: true, FollowEvents: true, ResumeAfterCursor: firstReplay.GetCursor(), StopOnTerminal: true,
		}, secondStream)
	}()
	if event := receiveSandboxWatchEvent(t, secondStream.events); event.GetSandbox() == nil {
		t.Fatalf("resume initial snapshot=%v", event)
	}
	resumedLog := receiveSandboxWatchEvent(t, secondStream.events)
	if resumedLog.GetLog() == nil || resumedLog.GetCursor() != mergedLog.GetCursor() {
		t.Fatalf("resumed log=%v, want cursor %q", resumedLog, mergedLog.GetCursor())
	}
	resumed := receiveSandboxWatchEvent(t, secondStream.events)
	if resumed.GetEvent() == nil || resumed.GetEvent().GetReason() != "running" || resumed.GetCursor() != firstLive.GetCursor() {
		t.Fatalf("resumed platform event=%v, want cursor %q", resumed, firstLive.GetCursor())
	}
	eventC := driver.PlatformEvent{SandboxID: "sb", Time: eventTime.Add(2 * time.Second), Source: "vm", Type: "sandbox_state", Reason: "stopped", Terminal: true}
	if _, created, err := logs.AppendPlatformEvent(context.Background(), sandboxlogs.PlatformEvent{
		SandboxID: "sb", EventTime: eventC.Time, Source: eventC.Source, Type: eventC.Type, Reason: eventC.Reason,
		Terminal: true, DedupKey: sandboxPlatformEventDedupKey(eventC, eventC.Time),
	}); err != nil || !created {
		t.Fatalf("seed terminal event=(created %v, err %v)", created, err)
	}
	if _, err := logs.Append(context.Background(), "sb", []sandboxlogs.Line{{SandboxID: "sb", EventTime: eventTime.Add(2500 * time.Millisecond), Level: "INFO", Source: "sandbox", Message: "after terminal event"}}); err != nil {
		t.Fatal(err)
	}
	// Simulate another Gateway replica persisting this event and the following
	// log line into the shared lifecycle store. The watch must poll and catch up.
	liveAfterResume := receiveSandboxWatchEvent(t, secondStream.events)
	if liveAfterResume.GetEvent() == nil || liveAfterResume.GetEvent().GetReason() != "stopped" || liveAfterResume.GetCursor() <= resumed.GetCursor() {
		t.Fatalf("event after resume=%v", liveAfterResume)
	}
	liveLog := receiveSandboxWatchEvent(t, secondStream.events)
	if liveLog.GetLog() == nil || liveLog.GetCursor() <= liveAfterResume.GetCursor() {
		t.Fatalf("live log after terminal event=%v", liveLog)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("terminal event watch stop error=%v", err)
	}
	cancelSecond()
}

func receiveSandboxWatchEvent(t *testing.T, events <-chan *gatewayv1.SandboxStreamEvent) *gatewayv1.SandboxStreamEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for sandbox watch event")
		return nil
	}
}
