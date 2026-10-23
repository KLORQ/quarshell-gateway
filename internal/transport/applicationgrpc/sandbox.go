package applicationgrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateSandbox creates one sandbox generation.
func (s *Server) CreateSandbox(ctx context.Context, request *gatewayv1.CreateSandboxRequest) (*gatewayv1.SandboxResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	workspace := workspaceID(request.GetWorkspaceScope())
	driverConfigJSON, err := s.prepareDriverConfig(ctx, workspace, request.GetSpec().GetTemplate().GetDriverConfig())
	if err != nil {
		return nil, err
	}
	created, _, err := s.Sandboxes.Create(ctx, sandbox.Request{
		Workspace: workspace, Sandbox: domain.SandboxID(request.GetName()),
		Generation: 1, Image: imageFromSpec(request.GetSpec()), Command: request.GetSpec().GetCommand(), TTY: request.GetSpec().GetTty(),
		AwaitMainProcessAttachment: request.GetAwaitMainProcessAttachment(),
		Resources:                  resourcesFromSpec(request.GetSpec()), Labels: request.GetLabels(), DriverConfigJSON: driverConfigJSON,
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.SandboxResponse{Sandbox: sandboxProto(created, request.GetSpec())}, nil
}

// GetSandbox returns one sandbox.
func (s *Server) GetSandbox(ctx context.Context, request *gatewayv1.GetSandboxRequest) (*gatewayv1.SandboxResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	found, err := s.Sandboxes.Get(ctx, sandboxRef(request.GetWorkspaceScope(), request.GetName()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.SandboxResponse{Sandbox: sandboxProto(found, nil)}, nil
}

// ListSandboxes returns a bounded page.
func (s *Server) ListSandboxes(ctx context.Context, request *gatewayv1.ListSandboxesRequest) (*gatewayv1.ListSandboxesResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	items, err := s.Sandboxes.List(ctx, workspaceID(request.GetWorkspaceScope()))
	if err != nil {
		return nil, grpcError(err)
	}
	start, end, next, err := page(len(items), request.GetPageSize(), request.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*gatewayv1.Sandbox, 0, end-start)
	for _, item := range items[start:end] {
		out = append(out, sandboxProto(item, nil))
	}
	return &gatewayv1.ListSandboxesResponse{Sandboxes: out, NextPageToken: next}, nil
}

// DeleteSandbox removes a sandbox idempotently.
func (s *Server) DeleteSandbox(ctx context.Context, request *gatewayv1.DeleteSandboxRequest) (*gatewayv1.DeleteSandboxResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetName())
	if request.GetAllowMissing() {
		if _, err := s.Sandboxes.Get(ctx, ref); err != nil {
			if domain.CodeOf(err) == domain.CodeNotFound {
				return &gatewayv1.DeleteSandboxResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
			}
			return nil, grpcError(err)
		}
	}
	if err := s.Sandboxes.Delete(ctx, ref, domain.OperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.DeleteSandboxResponse{Outcome: gatewayv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED, SandboxId: request.GetName()}, nil
}

// StartSandbox moves the current generation to running.
func (s *Server) StartSandbox(ctx context.Context, request *gatewayv1.StartSandboxRequest) (*gatewayv1.SandboxResponse, error) {
	return s.sandboxTransition(ctx, request.GetWorkspaceScope(), request.GetName(), request.GetRequestId(), true)
}

// StopSandbox moves the current generation to stopped.
func (s *Server) StopSandbox(ctx context.Context, request *gatewayv1.StopSandboxRequest) (*gatewayv1.SandboxResponse, error) {
	return s.sandboxTransition(ctx, request.GetWorkspaceScope(), request.GetName(), request.GetRequestId(), false)
}

func (s *Server) sandboxTransition(ctx context.Context, selector *datamodelv1.WorkspaceSelector, name, key string, start bool) (*gatewayv1.SandboxResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	ref := sandboxRef(selector, name)
	if key == "" {
		key = "transition:" + name
	}
	current, err := s.Sandboxes.Get(ctx, ref)
	if err != nil {
		return nil, grpcError(err)
	}
	var updated sandbox.Sandbox
	if start {
		updated, _, err = s.Sandboxes.Start(ctx, ref, current.Generation, domain.OperationID(key))
	} else {
		updated, _, err = s.Sandboxes.Stop(ctx, ref, current.Generation, domain.OperationID(key))
	}
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.SandboxResponse{Sandbox: sandboxProto(updated, nil)}, nil
}

func (s *Server) prepareDriverConfig(ctx context.Context, workspace domain.WorkspaceID, config *structpb.Struct) (string, error) {
	if config == nil {
		return "", nil
	}
	values := config.AsMap()
	token, _ := values["rootfs_tar_staging_token"].(string)
	if token != "" {
		path, err := s.consumeStagingToken(workspace, token)
		if err != nil {
			return "", err
		}
		delete(values, "rootfs_tar_staging_token")
		values["rootfs_tar_path"] = path
	}
	for _, raw := range values {
		envelope, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		token, _ = envelope["rootfs_tar_staging_token"].(string)
		if token == "" {
			continue
		}
		path, err := s.consumeStagingToken(workspace, token)
		if err != nil {
			return "", err
		}
		delete(envelope, "rootfs_tar_staging_token")
		envelope["rootfs_tar_path"] = path
	}
	if s.RuntimeBackendID == "vm" {
		vmConfig, _ := values["vm"].(map[string]any)
		if vmConfig == nil {
			vmConfig = map[string]any{}
			values["vm"] = vmConfig
		}
		for key, env := range map[string]string{
			"guest_tls_ca": "QUARSHELL_GUEST_TLS_CA", "guest_tls_cert": "QUARSHELL_GUEST_TLS_CERT",
			"guest_tls_key": "QUARSHELL_GUEST_TLS_KEY", "grpc_endpoint": "OPENSHELL_GRPC_ENDPOINT",
		} {
			if _, exists := vmConfig[key]; !exists {
				if value := strings.TrimSpace(os.Getenv(env)); value != "" {
					vmConfig[key] = value
				}
			}
		}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, "sandbox driver_config is invalid")
	}
	return string(encoded), nil
}

func sandboxRef(selector *datamodelv1.WorkspaceSelector, name string) domain.SandboxRef {
	return domain.SandboxRef{Workspace: workspaceID(selector), Sandbox: domain.SandboxID(name)}
}

func workspaceID(selector *datamodelv1.WorkspaceSelector) domain.WorkspaceID {
	if selector == nil {
		return ""
	}
	return domain.WorkspaceID(selector.GetWorkspace())
}

func resourcesFromSpec(spec *gatewayv1.SandboxSpec) sandbox.Resources {
	if spec == nil || spec.GetResourceRequirements().GetGpu() == nil {
		return sandbox.Resources{}
	}
	count := 1
	if spec.GetResourceRequirements().GetGpu().Count != nil {
		count = int(spec.GetResourceRequirements().GetGpu().GetCount())
	}
	return sandbox.Resources{GPU: true, GPUCount: count}
}

func imageFromSpec(spec *gatewayv1.SandboxSpec) string {
	if spec == nil || spec.GetTemplate() == nil {
		return ""
	}
	return spec.GetTemplate().GetImage()
}

func sandboxProto(item sandbox.Sandbox, spec *gatewayv1.SandboxSpec) *gatewayv1.Sandbox {
	if spec == nil {
		spec = &gatewayv1.SandboxSpec{Template: &gatewayv1.SandboxTemplate{Image: item.Image}}
	}
	status := &gatewayv1.SandboxStatus{
		Phase:                 phaseFromState(item.State),
		MainProcessInstanceId: item.MainProcessInstanceID,
	}
	if item.WorkloadUID != 0 && item.WorkloadGID != 0 {
		status.Conditions = append(status.Conditions, &gatewayv1.SandboxCondition{
			Type: "WorkloadIdentity", Status: "True", Reason: "Observed",
			Message:        fmt.Sprintf("Resolved workload UID:GID is %d:%d", item.WorkloadUID, item.WorkloadGID),
			TransitionTime: timestamppb.New(item.UpdatedAt),
		})
	}
	if item.MainProcessExitCode != nil {
		status.ExitCode = item.MainProcessExitCode
	}
	return &gatewayv1.Sandbox{
		Metadata: &datamodelv1.ObjectMeta{Id: string(item.Sandbox), Name: string(item.Sandbox), Labels: item.Labels, CreatedTime: timestamppb.New(item.CreatedAt)},
		Spec:     spec,
		Status:   status,
	}
}

func phaseFromState(state string) gatewayv1.SandboxPhase {
	switch state {
	case "running":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_READY
	case "stopped":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_STOPPED
	case "stopping":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_STOPPING
	case "starting":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_STARTING
	case "deleted":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_DELETING
	case "completed":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_COMPLETED
	case "error", "failed":
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_ERROR
	default:
		return gatewayv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING
	}
}
