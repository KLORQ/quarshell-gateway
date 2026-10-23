// Package reconcile brings durable sandbox state back in line with the backend.
package reconcile

import (
	"context"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

// Run inspects every sandbox and records backend state transitions.
func Run(ctx context.Context, workspaces *workspace.Service, sandboxes *sandbox.Service, runtime sandboxruntime.Runtime) error {
	if workspaces == nil || sandboxes == nil || runtime == nil {
		return nil
	}
	items, err := workspaces.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		list, err := sandboxes.List(ctx, item.ID)
		if err != nil {
			return err
		}
		for _, current := range list {
			input := sandboxruntime.Sandbox{
				Workspace: current.Workspace, Sandbox: current.Sandbox, RuntimeID: current.RuntimeID,
				Image: current.Image, Command: append([]string(nil), current.Command...), TTY: current.TTY,
				Labels: current.Labels,
				Resources: sandboxruntime.Resources{
					CPUCores: current.Resources.CPUCores, MemoryBytes: current.Resources.MemoryBytes,
					PIDs: current.Resources.PIDs, GPU: current.Resources.GPU, GPUCount: current.Resources.GPUCount,
				},
				Network: sandboxruntime.Network{
					GatewayURL: current.Network.GatewayURL, ExtraHosts: append([]string(nil), current.Network.ExtraHosts...),
				},
			}
			info, err := runtime.Inspect(ctx, input)
			if err != nil {
				continue
			}
			state := stateFromBackend(info.Status)
			if current.State == "running" && state != "running" {
				if err := sandboxes.StartRuntime(ctx, runtime, current); err != nil {
					return err
				}
				info, err = runtime.Inspect(ctx, input)
				if err != nil {
					return err
				}
				state = stateFromBackend(info.Status)
			}
			if current.State == "stopped" && state == "running" {
				if err := runtime.Stop(ctx, input); err != nil {
					return err
				}
				info, err = runtime.Inspect(ctx, input)
				if err != nil {
					return err
				}
				state = stateFromBackend(info.Status)
			}
			if state == "" || state == current.State {
				continue
			}
			ref := domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}
			if _, err := sandboxes.Observe(ctx, ref, current.Generation, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func stateFromBackend(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return "running"
	case "created", "exited", "stopped":
		return "stopped"
	case "dead", "removing":
		return "failed"
	case "paused":
		return "paused"
	default:
		return ""
	}
}
