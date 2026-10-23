package applicationgrpc

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func sandboxappRef(workspace, name string) domain.SandboxRef {
	return domain.SandboxRef{Workspace: domain.WorkspaceID(workspace), Sandbox: domain.SandboxID(name)}
}

func TestRootfsTarStagingConsumedByCreate(t *testing.T) {
	dir := t.TempDir()
	sandboxes, _ := sandboxapp.NewService(lifecycle.NewMemoryStore())
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.RootfsStaging = func(context.Context) (string, uint64, error) { return dir, 1024, nil }
	ctx := context.Background()
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	if _, err := server.BeginRootfsTarStaging(ctx, &gatewayv1.BeginRootfsTarStagingRequest{WorkspaceScope: selector, FileName: "../bad", SizeBytes: 4}); err == nil {
		t.Fatal("accepted traversal file name")
	}
	staged, err := server.BeginRootfsTarStaging(ctx, &gatewayv1.BeginRootfsTarStagingRequest{WorkspaceScope: selector, FileName: "rootfs.tar", SizeBytes: 4})
	if err != nil || staged.GetStagingToken() == "" {
		t.Fatalf("BeginRootfsTarStaging = %+v err=%v", staged, err)
	}
	if err := os.WriteFile(staged.GetUploadPath(), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, _ := structpb.NewStruct(map[string]any{"rootfs_tar_staging_token": staged.GetStagingToken()})
	if _, err := server.CreateSandbox(ctx, &gatewayv1.CreateSandboxRequest{
		WorkspaceScope: selector, Name: "sb",
		Spec: &gatewayv1.SandboxSpec{Template: &gatewayv1.SandboxTemplate{Image: "ubuntu:24.04", DriverConfig: config}},
	}); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	current, err := sandboxes.Get(ctx, sandboxappRef("ws", "sb"))
	if err != nil {
		t.Fatal(err)
	}
	var driverConfig map[string]any
	if err := json.Unmarshal([]byte(current.DriverConfigJSON), &driverConfig); err != nil {
		t.Fatal(err)
	}
	path, _ := driverConfig["rootfs_tar_path"].(string)
	if !strings.HasPrefix(path, dir+string(os.PathSeparator)) {
		t.Fatalf("rootfs path = %q", path)
	}
	if _, err := server.BeginRootfsTarStaging(ctx, &gatewayv1.BeginRootfsTarStagingRequest{WorkspaceScope: selector, FileName: "rootfs.tar", SizeBytes: 2048}); err == nil {
		t.Fatal("accepted oversize archive")
	}
}
