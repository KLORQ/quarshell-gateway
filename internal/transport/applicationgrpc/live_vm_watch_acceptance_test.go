//go:build darwin && arm64

package applicationgrpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/KLORQ/quarshell-core"
	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver-vm/vm"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	dm "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
)

type liveVMWatchRuntime struct {
	backend             *vm.Driver
	rootfsTar           string
	terminalOpenCalls   int
	terminalAttachCalls int
}

func (r *liveVMWatchRuntime) Create(ctx context.Context, sandbox sandboxruntime.Sandbox) (string, error) {
	request := driver.BackendCreateRequest{
		SandboxID: core.ID(string(sandbox.Sandbox)), Name: string(sandbox.Sandbox),
		Workspace: driver.WorkspaceTarget{Kind: driver.WorkspaceGuestOverlay, ID: string(sandbox.Workspace), Persist: true},
		Workload:  driver.WorkloadSpec{Image: sandbox.Image, Command: append([]string(nil), sandbox.Command...), TTY: sandbox.TTY},
		Runtime:   driver.RuntimeAssets{},
		Config:    vm.SandboxDriverConfig{RootfsTarPath: r.rootfsTar},
	}
	handle, err := r.backend.Create(ctx, request)
	return string(handle.ID), err
}

func (r *liveVMWatchRuntime) Start(ctx context.Context, sandbox sandboxruntime.Sandbox) error {
	return r.backend.Start(ctx, core.ID(sandbox.RuntimeID))
}
func (r *liveVMWatchRuntime) Stop(ctx context.Context, sandbox sandboxruntime.Sandbox) error {
	return r.backend.Stop(ctx, core.ID(sandbox.RuntimeID))
}
func (r *liveVMWatchRuntime) Delete(ctx context.Context, sandbox sandboxruntime.Sandbox) error {
	return r.backend.Delete(ctx, core.ID(sandbox.RuntimeID))
}
func (r *liveVMWatchRuntime) Inspect(ctx context.Context, sandbox sandboxruntime.Sandbox) (driver.Info, error) {
	return r.backend.Inspect(ctx, sandbox.RuntimeID)
}
func (r *liveVMWatchRuntime) WatchPlatformEvents(ctx context.Context, sandbox sandboxruntime.Sandbox) (<-chan driver.PlatformEventResult, error) {
	return r.backend.WatchPlatformEvents(ctx, driver.PlatformEventWatchRequest{SandboxID: core.ID(sandbox.RuntimeID), SandboxName: string(sandbox.Sandbox)})
}

func (r *liveVMWatchRuntime) OpenExecStream(ctx context.Context, sandbox sandboxruntime.Sandbox, request driver.ExecTerminalRequest) (driver.ExecStreamSession, error) {
	return r.backend.OpenExecStream(ctx, core.ID(sandbox.RuntimeID), request)
}

func (r *liveVMWatchRuntime) OpenExecTerminal(ctx context.Context, sandbox sandboxruntime.Sandbox, request driver.ExecTerminalRequest) (driver.ExecTerminalSession, error) {
	r.terminalOpenCalls++
	return r.backend.OpenExecTerminal(ctx, core.ID(sandbox.RuntimeID), request)
}

func (r *liveVMWatchRuntime) AttachExecTerminal(ctx context.Context, sandbox sandboxruntime.Sandbox, sessionID string) (driver.ExecTerminalSession, error) {
	r.terminalAttachCalls++
	return r.backend.AttachExecTerminal(ctx, core.ID(sandbox.RuntimeID), sessionID)
}

func (r *liveVMWatchRuntime) Exec(ctx context.Context, sandbox sandboxruntime.Sandbox, request driver.ExecRequest) (driver.ExecResult, error) {
	return r.backend.Exec(ctx, core.ID(sandbox.RuntimeID), request)
}

type liveGatewayOCIObject struct {
	mediaType string
	body      []byte
}

func liveGatewayBootstrapImage(t *testing.T, rootfsTar string) string {
	t.Helper()
	rootfs, err := os.ReadFile(rootfsTar)
	if err != nil {
		t.Fatalf("read live Gateway bootstrap rootfs: %v", err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(rootfs); err != nil {
		t.Fatalf("compress live Gateway bootstrap rootfs: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("finish live Gateway bootstrap layer: %v", err)
	}
	digest := func(payload []byte) string {
		hash := sha256.Sum256(payload)
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	rootfsDigest := digest(rootfs)
	layer := compressed.Bytes()
	layerDigest := digest(layer)
	config, err := json.Marshal(map[string]any{
		"architecture": runtime.GOARCH,
		"os":           "linux",
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{rootfsDigest}},
		"config":       map[string]any{},
	})
	if err != nil {
		t.Fatalf("encode live Gateway bootstrap image config: %v", err)
	}
	configDigest := digest(config)
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    configDigest,
			"size":      len(config),
		},
		"layers": []map[string]any{{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest":    layerDigest,
			"size":      len(layer),
		}},
	})
	if err != nil {
		t.Fatalf("encode live Gateway bootstrap manifest: %v", err)
	}
	manifestDigest := digest(manifest)
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest":    manifestDigest,
			"size":      len(manifest),
			"platform":  map[string]string{"os": "linux", "architecture": runtime.GOARCH},
		}},
	})
	if err != nil {
		t.Fatalf("encode live Gateway bootstrap image index: %v", err)
	}
	indexDigest := digest(index)
	objects := map[string]liveGatewayOCIObject{
		"manifest:" + indexDigest:    {mediaType: "application/vnd.oci.image.index.v1+json", body: index},
		"manifest:" + manifestDigest: {mediaType: "application/vnd.oci.image.manifest.v1+json", body: manifest},
		"blob:" + configDigest:       {mediaType: "application/vnd.oci.image.config.v1+json", body: config},
		"blob:" + layerDigest:        {mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", body: layer},
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/" {
			response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
			response.WriteHeader(http.StatusOK)
			return
		}
		key := ""
		switch {
		case strings.HasPrefix(request.URL.Path, "/v2/agent/manifests/"):
			name := strings.TrimPrefix(request.URL.Path, "/v2/agent/manifests/")
			if name == "latest" {
				name = indexDigest
			}
			key = "manifest:" + name
		case strings.HasPrefix(request.URL.Path, "/v2/agent/blobs/"):
			key = "blob:" + strings.TrimPrefix(request.URL.Path, "/v2/agent/blobs/")
		default:
			http.NotFound(response, request)
			return
		}
		object, ok := objects[key]
		if !ok {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", object.mediaType)
		objectDigest := strings.TrimPrefix(strings.TrimPrefix(key, "manifest:"), "blob:")
		response.Header().Set("Docker-Content-Digest", objectDigest)
		response.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
		if request.Method != http.MethodHead {
			_, _ = response.Write(object.body)
		}
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://") + "/agent:latest"
}

func TestLiveVMWatchSandboxComposition(t *testing.T) {
	if os.Getenv("QUARSHELL_VM_ACCEPTANCE") != "1" {
		t.Skip("set QUARSHELL_VM_ACCEPTANCE=1 to run live HVF Gateway watch acceptance")
	}
	rootfsTar := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_ROOTFS_TAR"))
	if rootfsTar == "" {
		t.Fatal("QUARSHELL_VM_TEST_ROOTFS_TAR is required")
	}
	host := vm.DefaultHostConfig()
	host.StateDir = t.TempDir()
	host.RootfsTarDir = filepath.Join(host.StateDir, "rootfs-tar-staging")
	requestDir := filepath.Join(host.RootfsTarDir, "live-watch-request")
	if err := os.MkdirAll(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stagedRootfsTar := filepath.Join(requestDir, "rootfs.tar")
	sourceRootfs, err := os.Open(rootfsTar)
	if err != nil {
		t.Fatal(err)
	}
	stagedRootfs, err := os.OpenFile(stagedRootfsTar, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = sourceRootfs.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(stagedRootfs, sourceRootfs)
	if err := errors.Join(copyErr, stagedRootfs.Close(), sourceRootfs.Close()); err != nil {
		t.Fatalf("stage live VM rootfs tar: %v", err)
	}
	host.GuestAgentPath = strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_GUEST_AGENT"))
	host.WorkerPath = strings.TrimSpace(os.Getenv("QUARSHELL_VM_WORKER"))
	host.FormatterPath = strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_E2FS_FORMATTER"))
	host.AllowDriverConfig = true
	// Serve the staged rootfs as a local OCI bootstrap image so this live lane
	// does not depend on Docker Hub availability.
	bootstrapImage := liveGatewayBootstrapImage(t, stagedRootfsTar)
	host.BootstrapImage = bootstrapImage
	host.DefaultImage = bootstrapImage
	backend := vm.NewWithHostConfig(host)
	runtime := &liveVMWatchRuntime{backend: backend, rootfsTar: stagedRootfsTar}
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	sandboxes.Runtime = runtime
	server := New("live-vm-watch", nil, sandboxes, nil, nil, nil, nil, nil)
	logs, err := sandboxlogs.New(store)
	if err != nil {
		t.Fatal(err)
	}
	server.SandboxLogs = logs
	ref := domain.SandboxRef{Workspace: "live-vm-watch", Sandbox: "live-vm-watch"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	created, _, err := sandboxes.Create(ctx, sandboxapp.Request{
		Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "alpine:3.22",
		Command:          []string{"/bin/sh", "-c", "while :; do sleep 3600; done"},
		DriverConfigJSON: fmt.Sprintf(`{"vm":{"rootfs_tar_path":%q}}`, stagedRootfsTar),
		IdempotencyKey:   "live-vm-watch-create",
	})
	if err != nil {
		t.Fatalf("create live VM through Gateway sandbox service: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if current, getErr := sandboxes.Get(cleanupCtx, ref); getErr == nil && current.State == "running" {
			_, _, _ = sandboxes.Stop(cleanupCtx, ref, current.Generation, "live-vm-watch-cleanup-stop")
		}
		current, getErr := sandboxes.Get(cleanupCtx, ref)
		if getErr == nil {
			_ = runtime.Delete(cleanupCtx, sandboxruntime.Sandbox{Sandbox: current.Sandbox, RuntimeID: current.RuntimeID})
		}
	})
	if created.RuntimeID == "" {
		t.Fatal("Gateway sandbox service did not retain the VM runtime ID")
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	stream := &captureSandboxWatchStream{ctx: watchCtx, events: make(chan *gatewayv1.SandboxStreamEvent, 16)}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- server.WatchSandbox(&gatewayv1.WatchSandboxRequest{
			WorkspaceScope: &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: string(ref.Workspace)}},
			Sandbox:        string(ref.Sandbox), FollowEvents: true, StopOnTerminal: true,
		}, stream)
	}()
	select {
	case event := <-stream.events:
		if event.GetSandbox() == nil {
			t.Fatalf("Gateway watch initial snapshot=%v", event)
		}
	case <-ctx.Done():
		t.Fatalf("waiting for Gateway watch snapshot: %v", ctx.Err())
	}
	started, _, err := sandboxes.Start(ctx, ref, created.Generation, "live-vm-watch-start")
	if err != nil {
		t.Fatalf("start VM through Gateway sandbox service: %v", err)
	}
	seenRunning := false
	for !seenRunning {
		select {
		case event := <-stream.events:
			platform := event.GetEvent()
			if platform != nil && platform.GetSource() == "vm" && platform.GetReason() == "running" {
				seenRunning = true
			}
		case <-ctx.Done():
			t.Fatalf("waiting for live VM running event through Gateway WatchSandbox (runtime=%s, state=%s): %v", started.RuntimeID, started.State, ctx.Err())
		}
	}
	assertLiveVMGatewayPTYInterrupt(t, server, ref, ctx)
	assertLiveVMGatewayPTYReconnect(t, server, runtime, ref, ctx)
	assertLiveVMArchiveTransferThroughGateway(t, server, ref, ctx)
	stopped, _, err := sandboxes.Stop(ctx, ref, started.Generation, "live-vm-watch-stop")
	if err != nil {
		t.Fatalf("stop VM through Gateway sandbox service: %v", err)
	}
	seenStopped := false
	for !seenStopped {
		select {
		case event := <-stream.events:
			platform := event.GetEvent()
			if platform != nil && platform.GetSource() == "vm" && platform.GetReason() == "stopped" {
				seenStopped = true
			}
		case <-ctx.Done():
			t.Fatalf("waiting for live VM stopped event through Gateway WatchSandbox (state=%s): %v", stopped.State, ctx.Err())
		}
	}
	stopWatch()
	if err := <-watchDone; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Gateway WatchSandbox returned %v", err)
	}
}

func assertLiveVMGatewayPTYReconnect(t *testing.T, server *Server, runtime *liveVMWatchRuntime, ref domain.SandboxRef, ctx context.Context) {
	t.Helper()
	request := &gatewayv1.ExecSandboxRequest{
		WorkspaceScope: &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: string(ref.Workspace)}},
		Sandbox:        string(ref.Sandbox), Command: []string{"sh", "-c", "printf 'gateway-ready\\n'; IFS= read -r line; printf 'gateway-received:%s\\n' \"$line\""},
		Tty: true, Cols: 80, Rows: 24, RequestId: "e3fc1bb6-ea1a-42fc-8670-5c2fa6b1f907",
	}
	first := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 1), sendErr: io.ErrClosedPipe}
	first.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	firstDone := make(chan error, 1)
	go func() { firstDone <- server.ExecSandboxInteractive(first) }()
	if err := <-firstDone; !errors.Is(err, io.ErrClosedPipe) {
		close(first.inputs)
		t.Fatalf("first Gateway TTY stream result = %v, want transport close", err)
	}
	close(first.inputs)
	if runtime.terminalOpenCalls == 0 {
		t.Fatal("initial Gateway exec did not open a VM terminal")
	}
	openedBeforeRetry := runtime.terminalOpenCalls
	attachedBeforeRetry := runtime.terminalAttachCalls

	resumed := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 2)}
	resumed.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: request}}
	resumed.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Stdin{Stdin: []byte("resume-input\n")}}
	close(resumed.inputs)
	if err := server.ExecSandboxInteractive(resumed); err != nil {
		t.Fatalf("reattach Gateway TTY request: %v", err)
	}
	if runtime.terminalOpenCalls != openedBeforeRetry || runtime.terminalAttachCalls != attachedBeforeRetry+1 {
		t.Fatalf("Gateway retry opened %d more terminals and attached %d times", runtime.terminalOpenCalls-openedBeforeRetry, runtime.terminalAttachCalls-attachedBeforeRetry)
	}
	var output strings.Builder
	for _, event := range resumed.events {
		if stdout := event.GetStdout(); stdout != nil {
			output.Write(stdout.GetData())
		}
	}
	if len(resumed.events) == 0 || resumed.events[len(resumed.events)-1].GetExit() == nil || resumed.events[len(resumed.events)-1].GetExit().GetExitCode() != 0 || !strings.Contains(output.String(), "gateway-received:resume-input") {
		t.Fatalf("reconnected Gateway TTY events = %+v, output=%q", resumed.events, output.String())
	}
}

func assertLiveVMGatewayPTYInterrupt(t *testing.T, server *Server, ref domain.SandboxRef, ctx context.Context) {
	t.Helper()
	stream := &interactiveExecTestStream{ctx: ctx, inputs: make(chan *gatewayv1.ExecSandboxInput, 2)}
	stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Start{Start: &gatewayv1.ExecSandboxRequest{
		WorkspaceScope: &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: string(ref.Workspace)}},
		Sandbox:        string(ref.Sandbox), Command: []string{"sh", "-c", "trap 'echo interrupted; exit 42' INT; while :; do sleep 1; done"},
		Tty: true, Cols: 80, Rows: 24,
	}}}
	go func() {
		time.Sleep(300 * time.Millisecond)
		stream.inputs <- &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Stdin{Stdin: []byte{3}}}
		close(stream.inputs)
	}()
	if err := server.ExecSandboxInteractive(stream); err != nil {
		t.Fatalf("Gateway interactive VM PTY exec: %v", err)
	}
	stream.mu.Lock()
	events := append([]*gatewayv1.ExecSandboxEvent(nil), stream.events...)
	stream.mu.Unlock()
	var output strings.Builder
	var exitCode *int32
	for _, event := range events {
		if data := event.GetStdout(); data != nil {
			output.Write(data.GetData())
		}
		if exit := event.GetExit(); exit != nil {
			code := exit.GetExitCode()
			exitCode = &code
		}
	}
	if !strings.Contains(output.String(), "interrupted") || exitCode == nil || *exitCode != 42 {
		t.Fatalf("Gateway PTY interrupt output=%q exit=%v events=%+v", output.String(), exitCode, events)
	}
}

func assertLiveVMArchiveTransferThroughGateway(t *testing.T, server *Server, ref domain.SandboxRef, ctx context.Context) {
	t.Helper()
	cliBinary := strings.TrimSpace(os.Getenv("QUARSHELL_VM_TEST_CLI"))
	if cliBinary == "" {
		t.Fatal("QUARSHELL_VM_TEST_CLI is required for live CLI-to-Gateway VM archive acceptance")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for live Gateway gRPC fixture: %v", err)
	}
	grpcServer := grpc.NewServer()
	gatewayv1.RegisterOpenShellServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	sourceDir := filepath.Join(t.TempDir(), "gateway-transfer")
	if err := os.MkdirAll(filepath.Join(sourceDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "nested", "payload.txt"), []byte("gateway-live-vm-archive"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload.txt", filepath.Join(sourceDir, "nested", "relative-link")); err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	command := func(args ...string) {
		t.Helper()
		cliArgs := append([]string{"--gateway-endpoint", endpoint, "--workspace", string(ref.Workspace)}, args...)
		output, err := exec.CommandContext(ctx, cliBinary, cliArgs...).CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %v failed: %v\n%s", args, err, output)
		}
	}
	command("sandbox", "upload", string(ref.Sandbox), sourceDir, "/sandbox", "--no-git-ignore")
	downloadDir := filepath.Join(t.TempDir(), "downloaded")
	command("sandbox", "download", string(ref.Sandbox), "/sandbox/gateway-transfer", downloadDir)
	filePath := filepath.Join(downloadDir, "gateway-transfer", "nested", "payload.txt")
	body, err := os.ReadFile(filePath)
	if err != nil || string(body) != "gateway-live-vm-archive" {
		t.Fatalf("CLI downloaded payload=%q err=%v", body, err)
	}
	linkPath := filepath.Join(downloadDir, "gateway-transfer", "nested", "relative-link")
	link, err := os.Readlink(linkPath)
	if err != nil || link != "payload.txt" {
		t.Fatalf("CLI downloaded symlink target=%q err=%v", link, err)
	}
}

var _ sandboxruntime.Runtime = (*liveVMWatchRuntime)(nil)
var _ interface {
	WatchPlatformEvents(context.Context, sandboxruntime.Sandbox) (<-chan driver.PlatformEventResult, error)
} = (*liveVMWatchRuntime)(nil)
