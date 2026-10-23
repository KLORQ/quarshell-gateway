// Package sandbox implements the durable sandbox use case on top of the
// lifecycle store. Transport layers call this package; they do not own state.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/admission"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
)

const recordKind = "sandbox"

// Request creates one sandbox generation.
type Request struct {
	Workspace                  domain.WorkspaceID
	Sandbox                    domain.SandboxID
	Generation                 domain.Generation
	Image                      string
	Command                    []string
	TTY                        bool
	AwaitMainProcessAttachment bool
	Resources                  Resources
	Network                    Network
	Labels                     map[string]string
	DriverConfigJSON           string
	IdempotencyKey             domain.OperationID
}

// Resources are portable sandbox limits.
type Resources struct {
	CPUCores    float64 `json:"cpu_cores,omitempty"`
	MemoryBytes int64   `json:"memory_bytes,omitempty"`
	PIDs        int64   `json:"pids,omitempty"`
	GPU         bool    `json:"gpu,omitempty"`
	GPUCount    int     `json:"gpu_count,omitempty"`
}

// Network is the sandbox egress and host-network configuration.
type Network struct {
	GatewayURL  string        `json:"gateway_url,omitempty"`
	ExtraHosts  []string      `json:"extra_hosts,omitempty"`
	PortPublish []PortPublish `json:"port_publish,omitempty"`
}

// PortPublish maps a host loopback port to a sandbox port.
type PortPublish struct {
	Host  int `json:"host"`
	Guest int `json:"guest"`
}

// Sandbox is the durable sandbox record.
type Sandbox struct {
	Workspace                  domain.WorkspaceID `json:"workspace"`
	Sandbox                    domain.SandboxID   `json:"sandbox"`
	Generation                 domain.Generation  `json:"generation"`
	RuntimeGeneration          domain.Generation  `json:"runtime_generation,omitempty"`
	CredentialEpoch            uint64             `json:"credential_epoch"`
	SessionID                  string             `json:"session_id,omitempty"`
	MainProcessInstanceID      string             `json:"main_process_instance_id,omitempty"`
	MainProcessExitCode        *int32             `json:"main_process_exit_code,omitempty"`
	MainProcessFinalized       bool               `json:"main_process_finalized,omitempty"`
	WorkloadUID                uint32             `json:"workload_uid,omitempty"`
	WorkloadGID                uint32             `json:"workload_gid,omitempty"`
	State                      string             `json:"state"`
	Image                      string             `json:"image"`
	RuntimeID                  string             `json:"runtime_id,omitempty"`
	Command                    []string           `json:"command,omitempty"`
	TTY                        bool               `json:"tty,omitempty"`
	AwaitMainProcessAttachment bool               `json:"await_main_process_attachment,omitempty"`
	Resources                  Resources          `json:"resources,omitempty"`
	Network                    Network            `json:"network,omitempty"`
	Labels                     map[string]string  `json:"labels,omitempty"`
	DriverConfigJSON           string             `json:"driver_config_json,omitempty"`
	CreatedAt                  time.Time          `json:"created_at"`
	UpdatedAt                  time.Time          `json:"updated_at"`
}

// CredentialEpochOrInitial preserves compatibility with records written before
// durable credential epochs were introduced.
func (sandbox Sandbox) CredentialEpochOrInitial() uint64 {
	if sandbox.CredentialEpoch == 0 {
		return 1
	}
	return sandbox.CredentialEpoch
}

func (sandbox Sandbox) RuntimeGenerationOrInitial() domain.Generation {
	if sandbox.RuntimeGeneration == 0 {
		return sandbox.Generation
	}
	return sandbox.RuntimeGeneration
}

// Service owns sandbox mutations and reads.
type Service struct {
	store              lifecycle.Store
	coordinator        *lifecycle.Coordinator
	now                func() time.Time
	Gate               admission.Gate
	Runtime            sandboxruntime.Runtime
	Tokens             *tokenapp.Service
	SupervisorSessions interface{ ReleaseSupervisor(string) }
}

// NewService returns a sandbox service backed by store.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("sandbox.service", "store is required")
	}
	return &Service{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// Create is idempotent per key. A repeated key with the same request returns
// the stored record; a different request under the same key conflicts.
func (s *Service) Create(ctx context.Context, request Request) (Sandbox, bool, error) {
	if err := validateRequest(request); err != nil {
		return Sandbox{}, false, err
	}
	key, hash, err := operationIdentity("create", request)
	if err != nil {
		return Sandbox{}, false, err
	}
	ref := domain.SandboxRef{Workspace: request.Workspace, Sandbox: request.Sandbox}
	now := s.now().UTC()
	created := Sandbox{
		Workspace: request.Workspace, Sandbox: request.Sandbox, Generation: request.Generation,
		RuntimeGeneration: request.Generation, CredentialEpoch: 1,
		State: "requested", Image: request.Image, Command: append([]string(nil), request.Command...), TTY: request.TTY,
		AwaitMainProcessAttachment: request.AwaitMainProcessAttachment,
		Resources:                  request.Resources, Network: cloneNetwork(request.Network), Labels: cloneLabels(request.Labels), DriverConfigJSON: request.DriverConfigJSON, CreatedAt: now, UpdatedAt: now,
	}
	payload, err := json.Marshal(created)
	if err != nil {
		return Sandbox{}, false, domain.Wrap(err, "sandbox.create", "encode sandbox")
	}
	result, replayed, err := s.coordinator.Execute(ctx, key, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		if _, exists, err := tx.Get(recordKind, refKey(ref)); err != nil {
			return nil, err
		} else if exists {
			return nil, domain.New(domain.CodeConflict, "sandbox.create", "sandbox already exists")
		}
		records, err := tx.List(recordKind)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			var existing Sandbox
			if err := json.Unmarshal(record.Payload, &existing); err != nil {
				return nil, err
			}
			if existing.Sandbox == ref.Sandbox {
				return nil, domain.New(domain.CodeConflict, "sandbox.create", "sandbox ID must be globally unique")
			}
		}
		record, err := tx.Put(recordKind, refKey(ref), 0, payload)
		if err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{
			ID: key + ":created", Topic: "sandbox.created", Payload: record.Payload,
		}); err != nil {
			return nil, err
		}
		return record.Payload, nil
	})
	if err != nil {
		return Sandbox{}, false, err
	}
	var stored Sandbox
	if err := json.Unmarshal(result, &stored); err != nil {
		return Sandbox{}, false, domain.Wrap(err, "sandbox.create", "decode sandbox")
	}
	if !replayed && s.Runtime != nil {
		runtimeID, err := s.Runtime.Create(ctx, runtimeInput(stored))
		if err != nil {
			slog.ErrorContext(ctx, "sandbox runtime creation failed", "workspace", stored.Workspace, "sandbox", stored.Sandbox, "error", err)
			return Sandbox{}, false, domain.Wrap(err, "sandbox.create", "provision runtime")
		}
		if runtimeID != "" {
			if err := s.setRuntimeID(ctx, ref, runtimeID); err != nil {
				return Sandbox{}, false, err
			}
			stored.RuntimeID = runtimeID
		}
	}
	return stored, replayed, nil
}

// Get returns the current sandbox record.
func (s *Service) Get(ctx context.Context, ref domain.SandboxRef) (Sandbox, error) {
	if !ref.Valid() {
		return Sandbox{}, domain.Invalidf("sandbox.get", "sandbox reference is invalid")
	}
	var payload []byte
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "sandbox.get", "sandbox not found")
		}
		payload = record.Payload
		return nil
	})
	if err != nil {
		return Sandbox{}, err
	}
	var stored Sandbox
	if err := json.Unmarshal(payload, &stored); err != nil {
		return Sandbox{}, domain.Wrap(err, "sandbox.get", "decode sandbox")
	}
	return stored, nil
}

// GetBySandboxID resolves the globally unique OpenShell sandbox identity from
// a session JWT, whose interoperable claim set does not include workspace.
func (s *Service) GetBySandboxID(ctx context.Context, id domain.SandboxID) (Sandbox, error) {
	if !id.Valid() {
		return Sandbox{}, domain.Invalidf("sandbox.get_by_id", "sandbox ID is invalid")
	}
	var found Sandbox
	count := 0
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(recordKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			var current Sandbox
			if err := json.Unmarshal(record.Payload, &current); err != nil {
				return err
			}
			if current.Sandbox == id {
				found = current
				count++
			}
		}
		return nil
	})
	if err != nil {
		return Sandbox{}, err
	}
	if count == 0 {
		return Sandbox{}, domain.Wrap(domain.ErrNotFound, "sandbox.get_by_id", "sandbox not found")
	}
	if count != 1 {
		return Sandbox{}, domain.New(domain.CodeConflict, "sandbox.get_by_id", "sandbox ID is not globally unique")
	}
	return found, nil
}

// Exec runs one command in the current sandbox generation when the configured
// runtime exposes the optional interactive-exec contract.
func (s *Service) Exec(ctx context.Context, ref domain.SandboxRef, request driver.ExecRequest) (driver.ExecResult, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return driver.ExecResult{}, err
	}
	executor, ok := s.Runtime.(interface {
		Exec(context.Context, sandboxruntime.Sandbox, driver.ExecRequest) (driver.ExecResult, error)
	})
	if !ok {
		return driver.ExecResult{}, domain.New(domain.CodeUnavailable, "sandbox.exec", "runtime does not support command execution")
	}
	return executor.Exec(ctx, runtimeInput(current), request)
}

// OpenExecTerminal opens a PTY for one command in the current sandbox generation.
func (s *Service) OpenExecTerminal(ctx context.Context, ref domain.SandboxRef, request driver.ExecTerminalRequest) (driver.ExecTerminalSession, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	executor, ok := s.Runtime.(interface {
		OpenExecTerminal(context.Context, sandboxruntime.Sandbox, driver.ExecTerminalRequest) (driver.ExecTerminalSession, error)
	})
	if !ok {
		return nil, domain.New(domain.CodeUnavailable, "sandbox.exec_terminal", "runtime does not support interactive terminals")
	}
	return executor.OpenExecTerminal(ctx, runtimeInput(current), request)
}

// AttachExecTerminal reconnects to an existing interactive process in the
// current sandbox generation.
func (s *Service) AttachExecTerminal(ctx context.Context, ref domain.SandboxRef, sessionID string) (driver.ExecTerminalSession, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	executor, ok := s.Runtime.(interface {
		AttachExecTerminal(context.Context, sandboxruntime.Sandbox, string) (driver.ExecTerminalSession, error)
	})
	if !ok {
		return nil, domain.New(domain.CodeUnavailable, "sandbox.exec_terminal.attach", "runtime does not support terminal attachment")
	}
	return executor.AttachExecTerminal(ctx, runtimeInput(current), sessionID)
}

// OpenExecStream opens a non-TTY interactive command in the current generation.
func (s *Service) OpenExecStream(ctx context.Context, ref domain.SandboxRef, request driver.ExecTerminalRequest) (driver.ExecStreamSession, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	executor, ok := s.Runtime.(interface {
		OpenExecStream(context.Context, sandboxruntime.Sandbox, driver.ExecTerminalRequest) (driver.ExecStreamSession, error)
	})
	if !ok {
		return nil, domain.New(domain.CodeUnavailable, "sandbox.exec_stream", "runtime does not support interactive non-TTY execution")
	}
	return executor.OpenExecStream(ctx, runtimeInput(current), request)
}

// OpenMainProcessTTY attaches to the canonical workload PTY.
func (s *Service) OpenMainProcessTTY(ctx context.Context, ref domain.SandboxRef, columns, rows uint32) (io.ReadWriteCloser, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	pty, ok := s.Runtime.(interface {
		PTY(context.Context, sandboxruntime.Sandbox, uint32, uint32) (io.ReadWriteCloser, error)
	})
	if !ok {
		return nil, domain.New(domain.CodeUnavailable, "sandbox.main_process.pty", "runtime does not support main-process PTY attachment")
	}
	return pty.PTY(ctx, runtimeInput(current), columns, rows)
}

// OpenMainProcessStream attaches to the retained stdout/stderr/stdin pipes of
// a canonical workload started without a TTY.
func (s *Service) OpenMainProcessStream(ctx context.Context, ref domain.SandboxRef) (driver.ExecStreamSession, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	streamer, ok := s.Runtime.(interface {
		MainProcessStream(context.Context, sandboxruntime.Sandbox) (driver.ExecStreamSession, error)
	})
	if !ok {
		return nil, domain.New(domain.CodeUnavailable, "sandbox.main_process.stream", "runtime does not support retained non-TTY process attachment")
	}
	return streamer.MainProcessStream(ctx, runtimeInput(current))
}

// ResizeMainProcessTTY resizes the canonical workload PTY.
func (s *Service) ResizeMainProcessTTY(ctx context.Context, ref domain.SandboxRef, columns, rows uint32) error {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return err
	}
	pty, ok := s.Runtime.(interface {
		ResizePTY(context.Context, sandboxruntime.Sandbox, uint32, uint32) error
	})
	if !ok {
		return domain.New(domain.CodeUnavailable, "sandbox.main_process.pty.resize", "runtime does not support main-process PTY resize")
	}
	return pty.ResizePTY(ctx, runtimeInput(current), columns, rows)
}

// WaitMainProcess waits for the canonical workload exit status.
func (s *Service) WaitMainProcess(ctx context.Context, ref domain.SandboxRef) (int, error) {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return 0, err
	}
	waiter, ok := s.Runtime.(interface {
		WaitMainProcess(context.Context, sandboxruntime.Sandbox) (int, error)
	})
	if !ok {
		return 0, domain.New(domain.CodeUnavailable, "sandbox.main_process.wait", "runtime cannot observe main-process exit")
	}
	return waiter.WaitMainProcess(ctx, runtimeInput(current))
}

// SignalMainProcess sends an allowlisted signal to the canonical workload.
func (s *Service) SignalMainProcess(ctx context.Context, ref domain.SandboxRef, signal driver.ExecProcessSignal) error {
	current, err := s.Get(ctx, ref)
	if err != nil {
		return err
	}
	signaler, ok := s.Runtime.(interface {
		SignalMainProcess(context.Context, sandboxruntime.Sandbox, driver.ExecProcessSignal) error
	})
	if !ok {
		return domain.New(domain.CodeUnavailable, "sandbox.main_process.signal", "runtime cannot signal the main process")
	}
	return signaler.SignalMainProcess(ctx, runtimeInput(current), signal)
}

// List returns sandboxes for one workspace sorted by sandbox ID.
func (s *Service) List(ctx context.Context, workspace domain.WorkspaceID) ([]Sandbox, error) {
	if !workspace.Valid() {
		return nil, domain.Invalidf("sandbox.list", "workspace is invalid")
	}
	var result []Sandbox
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(recordKind)
		if err != nil {
			return err
		}
		for _, record := range records {
			var sandbox Sandbox
			if err := json.Unmarshal(record.Payload, &sandbox); err != nil {
				return err
			}
			if sandbox.Workspace == workspace {
				result = append(result, sandbox)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Sandbox < result[right].Sandbox })
	return result, nil
}

// Observe applies an observed runtime generation and state. Stale generations
// are rejected.
func (s *Service) Observe(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, state string) (Sandbox, error) {
	if !ref.Valid() || strings.TrimSpace(state) == "" {
		return Sandbox{}, domain.Invalidf("sandbox.observe", "sandbox and state are required")
	}
	var result Sandbox
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "sandbox.observe", "sandbox not found")
		}
		var sandbox Sandbox
		if err := json.Unmarshal(record.Payload, &sandbox); err != nil {
			return err
		}
		if err := s.Gate.Admit(generation, sandbox.Generation); err != nil {
			return err
		}
		if generation > sandbox.Generation {
			if sandbox.CredentialEpoch == ^uint64(0) {
				return domain.New(domain.CodeConflict, "sandbox.observe", "credential epoch overflow")
			}
			sandbox.Generation = generation
			sandbox.CredentialEpoch++
			if sandbox.RuntimeGeneration == ^domain.Generation(0) {
				return domain.New(domain.CodeConflict, "sandbox.observe", "runtime generation overflow")
			}
			sandbox.RuntimeGeneration++
		}
		sandbox.State = state
		sandbox.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(sandbox)
		if err != nil {
			return err
		}
		if _, err := tx.Put(recordKind, refKey(ref), record.Version, payload); err != nil {
			return err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: refKey(ref) + ":observed:" + strconv.FormatUint(uint64(generation), 10), Topic: "sandbox.observed", Payload: payload}); err != nil {
			return err
		}
		result = sandbox
		return nil
	})
	return result, err
}

// Start moves a sandbox generation to running. It is idempotent per key.
func (s *Service) Start(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, key domain.OperationID) (Sandbox, bool, error) {
	current, replayed, changed, err := s.transition(ctx, "start", "running", "sandbox.started", ref, generation, key)
	if err != nil {
		return Sandbox{}, false, err
	}
	if s.Runtime != nil && changed {
		if err := s.startRuntime(ctx, s.Runtime, current); err != nil {
			slog.ErrorContext(ctx, "sandbox runtime start failed", "workspace", current.Workspace, "sandbox", current.Sandbox, "generation", current.RuntimeGenerationOrInitial(), "error", err)
			if latest, getErr := s.Get(ctx, ref); getErr == nil {
				current = latest
			}
			return current, replayed, domain.Wrap(err, "sandbox.start", "start runtime")
		}
		if err := s.observeRuntimeWorkloadIdentity(ctx, s.Runtime, current); err != nil {
			return Sandbox{}, replayed, err
		}
		if latest, getErr := s.Get(ctx, ref); getErr == nil {
			current = latest
		}
	}
	return current, replayed, nil
}

// StartRuntime starts an existing durable running intent during reconciliation.
// Token-aware runtimes receive a fresh generation-bound credential per boot.
func (s *Service) StartRuntime(ctx context.Context, runtime sandboxruntime.Runtime, current Sandbox) error {
	if err := s.startRuntime(ctx, runtime, current); err != nil {
		return err
	}
	return s.observeRuntimeWorkloadIdentity(ctx, runtime, current)
}

func (s *Service) observeRuntimeWorkloadIdentity(ctx context.Context, runtime sandboxruntime.Runtime, current Sandbox) error {
	if runtime == nil {
		return nil
	}
	info, err := runtime.Inspect(ctx, runtimeInput(current))
	if err != nil || info.WorkloadUID == 0 || info.WorkloadGID == 0 {
		return nil
	}
	ref := domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "sandbox.identity", "sandbox not found")
		}
		var item Sandbox
		if err := json.Unmarshal(record.Payload, &item); err != nil {
			return err
		}
		if item.RuntimeGenerationOrInitial() != current.RuntimeGenerationOrInitial() || item.State != "running" {
			return nil
		}
		item.WorkloadUID, item.WorkloadGID = info.WorkloadUID, info.WorkloadGID
		item.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(item)
		if err != nil {
			return err
		}
		_, err = tx.Put(recordKind, refKey(ref), record.Version, payload)
		return err
	})
}

func (s *Service) startRuntime(ctx context.Context, runtime sandboxruntime.Runtime, current Sandbox) error {
	if runtime == nil {
		return nil
	}
	if starter, ok := runtime.(interface {
		StartWithCredentials(context.Context, sandboxruntime.Sandbox, driver.RuntimeLaunchCredentials) error
	}); ok && runtimeSupportsPairedCredentials(runtime) {
		if !canonicalSandboxSessionID(current.SessionID) {
			return domain.New(domain.CodeUnavailable, "sandbox.start", "durable runtime session identity is missing")
		}
		if s.Tokens == nil {
			return domain.New(domain.CodeUnavailable, "sandbox.start", "token service is required by this runtime")
		}
		epoch := current.CredentialEpochOrInitial()
		ref := domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}
		runtimeGeneration := current.RuntimeGenerationOrInitial()
		gatewayToken, gatewayClaims, err := s.Tokens.IssueForAudienceEpoch(ref, runtimeGeneration, epoch, "gateway", "quarshell-supervisor", 0)
		if err != nil {
			return domain.Wrap(err, "sandbox.start", "issue Gateway runtime credential")
		}
		sandboxToken, sandboxClaims, err := s.Tokens.IssueForAudienceEpoch(ref, runtimeGeneration, epoch, "sandbox", "quarshell-supervisor", 0)
		if err != nil {
			return domain.Wrap(err, "sandbox.start", "issue Sandbox Protocol runtime credential")
		}
		verificationKey, err := s.Tokens.VerificationKeyPEM()
		if err != nil {
			return domain.Wrap(err, "sandbox.start", "export session verification key")
		}
		return starter.StartWithCredentials(ctx, runtimeInput(current), driver.RuntimeLaunchCredentials{
			SandboxID:         string(current.Sandbox),
			RuntimeGeneration: fmt.Sprintf("g%016x", uint64(runtimeGeneration)),
			SessionID:         current.SessionID,
			GatewayID:         s.Tokens.GatewayID(),
			VerificationKeys: []driver.RuntimeVerificationKey{{
				KeyID: s.Tokens.KeyID(), PublicKeyPEM: verificationKey,
			}},
			GatewayToken: gatewayToken, GatewayExpiresAt: gatewayClaims.ExpiresAt,
			SandboxToken: sandboxToken, SandboxExpiresAt: sandboxClaims.ExpiresAt,
			CredentialEpoch: epoch, SessionRotation: 1,
		})
	}
	starter, ok := runtime.(interface {
		StartWithToken(context.Context, sandboxruntime.Sandbox, string) error
	})
	if !ok {
		return runtime.Start(ctx, runtimeInput(current))
	}
	if s.Tokens == nil {
		return domain.New(domain.CodeUnavailable, "sandbox.start", "token service is required by this runtime")
	}
	epoch := current.CredentialEpochOrInitial()
	raw, _, err := s.Tokens.IssueForAudienceEpoch(domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, current.RuntimeGenerationOrInitial(), epoch, "gateway", "quarshell-supervisor", 0)
	if err != nil {
		return domain.Wrap(err, "sandbox.start", "issue runtime credential")
	}
	return starter.StartWithToken(ctx, runtimeInput(current), raw)
}

func canonicalSandboxSessionID(value string) bool {
	if len(value) != 36 || strings.ToLower(value) != value || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && decoded[6]&0xf0 == 0x40 && decoded[8]&0xc0 == 0x80
}

func runtimeSupportsPairedCredentials(runtime sandboxruntime.Runtime) bool {
	if capabilities, ok := runtime.(interface{ SupportsRuntimeCredentials() bool }); ok {
		return capabilities.SupportsRuntimeCredentials()
	}
	return true
}

// Stop moves a sandbox generation to stopped. It is idempotent per key.
func (s *Service) Stop(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, key domain.OperationID) (Sandbox, bool, error) {
	current, replayed, _, err := s.transition(ctx, "stop", "stopped", "sandbox.stopped", ref, generation, key)
	if err != nil {
		return Sandbox{}, false, err
	}
	if s.Runtime != nil {
		if err := s.Runtime.Stop(ctx, runtimeInput(current)); err != nil {
			return current, replayed, domain.Wrap(err, "sandbox.stop", "stop runtime")
		}
	}
	if s.SupervisorSessions != nil {
		s.SupervisorSessions.ReleaseSupervisor(string(current.Sandbox))
	}
	return current, replayed, nil
}

func (s *Service) transition(ctx context.Context, operation, state, topic string, ref domain.SandboxRef, generation domain.Generation, key domain.OperationID) (Sandbox, bool, bool, error) {
	if !ref.Valid() || generation == 0 || key == "" {
		return Sandbox{}, false, false, domain.Invalidf("sandbox."+operation, "sandbox, generation and key are required")
	}
	opKey := string(key) + ":" + operation
	hash := refKey(ref) + ":" + strconv.FormatUint(uint64(generation), 10)
	var result Sandbox
	var replayed bool
	var changed bool
	payload, replayed, err := s.coordinator.Execute(ctx, opKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, domain.Wrap(domain.ErrNotFound, "sandbox."+operation, "sandbox not found")
		}
		var current Sandbox
		if err := json.Unmarshal(record.Payload, &current); err != nil {
			return nil, err
		}
		if err := s.Gate.Admit(generation, current.Generation); err != nil {
			return nil, err
		}
		if current.State == state && current.Generation == generation {
			result = current
			return record.Payload, nil
		}
		changed = true
		if operation == "start" && state == "running" {
			if err := deleteSupervisorLease(tx, ref); err != nil {
				return nil, err
			}
			current.MainProcessInstanceID = ""
			current.MainProcessExitCode = nil
			current.MainProcessFinalized = false
			if current.CredentialEpoch == 0 {
				current.CredentialEpoch = 1
			}
			if current.CredentialEpoch == ^uint64(0) {
				return nil, domain.New(domain.CodeConflict, "sandbox.start", "credential epoch overflow")
			}
			current.CredentialEpoch++
			runtimeGeneration := current.RuntimeGenerationOrInitial()
			if runtimeGeneration == ^domain.Generation(0) {
				return nil, domain.New(domain.CodeConflict, "sandbox.start", "runtime generation overflow")
			}
			current.RuntimeGeneration = runtimeGeneration + 1
			sessionID, err := newSandboxSessionID()
			if err != nil {
				return nil, domain.Wrap(err, "sandbox.start", "create runtime session identity")
			}
			current.SessionID = sessionID
		}
		if state == "stopped" {
			if err := deleteSupervisorLease(tx, ref); err != nil {
				return nil, err
			}
		}
		current.State = state
		current.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(current)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(recordKind, refKey(ref), record.Version, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{
			ID: opKey + ":" + strconv.FormatUint(uint64(generation), 10), Topic: topic, Payload: payload,
		}); err != nil {
			return nil, err
		}
		result = current
		return payload, nil
	})
	if err == nil && replayed && len(payload) > 0 {
		changed = false
		if decodeErr := json.Unmarshal(payload, &result); decodeErr != nil {
			return Sandbox{}, false, false, domain.Wrap(decodeErr, "sandbox."+operation, "decode sandbox")
		}
	}
	return result, replayed, changed, err
}

// RecordMainProcessExit durably records the first terminal result reported by
// the authenticated supervisor. Repeated reports are idempotent; the first
// result wins, matching the pinned Gateway contract.
func (s *Service) RecordMainProcessExit(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, instanceID string, exitCode int32) error {
	if !ref.Valid() || generation == 0 || strings.TrimSpace(instanceID) == "" {
		return domain.Invalidf("sandbox.process_exit", "sandbox, runtime generation and instance ID are required")
	}
	return s.updateProcessExit(ctx, ref, generation, instanceID, func(current *Sandbox) error {
		if current.MainProcessExitCode != nil {
			return nil
		}
		if current.State != "running" {
			return domain.New(domain.CodeConflict, "sandbox.process_exit", "sandbox is not running")
		}
		code := exitCode
		current.MainProcessInstanceID = instanceID
		current.MainProcessExitCode = &code
		if exitCode == 0 {
			current.State = "completed"
		} else {
			current.State = "error"
		}
		return nil
	})
}

// FinalizeMainProcessExit marks terminal delivery complete after the exit
// result has been durably recorded by the current runtime instance.
func (s *Service) FinalizeMainProcessExit(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, instanceID string) error {
	if !ref.Valid() || generation == 0 || strings.TrimSpace(instanceID) == "" {
		return domain.Invalidf("sandbox.process_exit_finalize", "sandbox, runtime generation and instance ID are required")
	}
	if err := s.updateProcessExit(ctx, ref, generation, instanceID, func(current *Sandbox) error {
		if current.MainProcessExitCode == nil {
			return domain.New(domain.CodeConflict, "sandbox.process_exit_finalize", "main-process exit has not been reported")
		}
		if current.MainProcessInstanceID != instanceID {
			return domain.New(domain.CodeConflict, "sandbox.process_exit_finalize", "main-process instance does not match the terminal result")
		}
		current.MainProcessFinalized = true
		return nil
	}); err != nil {
		return err
	}
	if s.SupervisorSessions != nil {
		s.SupervisorSessions.ReleaseSupervisor(string(ref.Sandbox))
	}
	return nil
}

func (s *Service) updateProcessExit(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, instanceID string, mutate func(*Sandbox) error) error {
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "sandbox.process_exit", "sandbox not found")
		}
		var current Sandbox
		if err := json.Unmarshal(record.Payload, &current); err != nil {
			return err
		}
		before, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if current.RuntimeGenerationOrInitial() != generation {
			return domain.New(domain.CodeConflict, "sandbox.process_exit", "runtime generation is stale")
		}
		if err := mutate(&current); err != nil {
			return err
		}
		// Keep the durable supervisor lease until the owner acknowledges that
		// its terminal result was finalized. FinalizeMainProcessExit still needs
		// to fence that final RPC against a newer Gateway owner.
		if current.State != "running" && (current.MainProcessExitCode == nil || current.MainProcessFinalized) {
			if err := deleteSupervisorLease(tx, ref); err != nil {
				return err
			}
		}
		updated, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if bytes.Equal(before, updated) {
			return nil
		}
		current.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if _, err := tx.Put(recordKind, refKey(ref), record.Version, payload); err != nil {
			return err
		}
		phase := "result"
		if current.MainProcessFinalized {
			phase = "finalized"
		}
		return tx.Enqueue(lifecycle.OutboxMessage{ID: "sandbox.process-exit:" + refKey(ref) + ":" + strconv.FormatUint(uint64(generation), 10) + ":" + phase, Topic: "sandbox.process_exit." + phase, Payload: payload})
	})
}

func newSandboxSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

// Delete is idempotent per key and emits sandbox.deleted once.
func (s *Service) Delete(ctx context.Context, ref domain.SandboxRef, key domain.OperationID) error {
	if !ref.Valid() {
		return domain.Invalidf("sandbox.delete", "sandbox reference is invalid")
	}
	operationKey, hash, err := deleteIdentity(ref, key)
	if err != nil {
		return err
	}
	if s.Runtime != nil {
		input := Sandbox{Workspace: ref.Workspace, Sandbox: ref.Sandbox}
		_ = s.store.View(ctx, func(tx lifecycle.ReadTx) error {
			record, exists, err := tx.Get(recordKind, refKey(ref))
			if err != nil || !exists {
				return nil
			}
			_ = json.Unmarshal(record.Payload, &input)
			return nil
		})
		if err := s.Runtime.Delete(ctx, runtimeInput(input)); err != nil && domain.CodeOf(err) != domain.CodeNotFound {
			return domain.Wrap(err, "sandbox.delete", "delete runtime")
		}
	}
	_, _, err = s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := deleteSupervisorLease(tx, ref); err != nil {
			return nil, err
		}
		if err := tx.Delete(recordKind, refKey(ref), record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{
			ID: operationKey + ":deleted", Topic: "sandbox.deleted", Payload: record.Payload,
		}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

func cloneNetwork(network Network) Network {
	return Network{GatewayURL: network.GatewayURL, ExtraHosts: append([]string(nil), network.ExtraHosts...), PortPublish: append([]PortPublish(nil), network.PortPublish...)}
}

func portPublishes(values []PortPublish) []sandboxruntime.PortPublish {
	out := make([]sandboxruntime.PortPublish, 0, len(values))
	for _, value := range values {
		out = append(out, sandboxruntime.PortPublish{Host: value.Host, Guest: value.Guest})
	}
	return out
}

func (s *Service) setRuntimeID(ctx context.Context, ref domain.SandboxRef, runtimeID string) error {
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		record, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "sandbox.create", "sandbox not found")
		}
		var item Sandbox
		if err := json.Unmarshal(record.Payload, &item); err != nil {
			return err
		}
		item.RuntimeID = runtimeID
		item.UpdatedAt = s.now().UTC()
		payload, err := json.Marshal(item)
		if err != nil {
			return err
		}
		_, err = tx.Put(recordKind, refKey(ref), record.Version, payload)
		return err
	})
}

func runtimeInput(item Sandbox) sandboxruntime.Sandbox {
	return sandboxruntime.Sandbox{
		Workspace: item.Workspace, Sandbox: item.Sandbox, RuntimeID: item.RuntimeID, Image: item.Image, Command: item.Command, TTY: item.TTY,
		AwaitMainProcessAttachment: item.AwaitMainProcessAttachment,
		DriverConfigJSON:           item.DriverConfigJSON,
		Resources:                  sandboxruntime.Resources{CPUCores: item.Resources.CPUCores, MemoryBytes: item.Resources.MemoryBytes, PIDs: item.Resources.PIDs, GPU: item.Resources.GPU, GPUCount: item.Resources.GPUCount},
		Network: sandboxruntime.Network{
			GatewayURL: item.Network.GatewayURL, ExtraHosts: append([]string(nil), item.Network.ExtraHosts...),
			PortPublish: portPublishes(item.Network.PortPublish),
		},
		Labels: cloneLabels(item.Labels),
	}
}

func validateRequest(request Request) error {
	ref := domain.SandboxRef{Workspace: request.Workspace, Sandbox: request.Sandbox}
	if !ref.Valid() {
		return domain.Invalidf("sandbox.create", "sandbox reference is invalid")
	}
	if request.Generation == 0 {
		return domain.Invalidf("sandbox.create", "generation must be positive")
	}
	if strings.TrimSpace(request.Image) == "" && !strings.Contains(request.DriverConfigJSON, `"rootfs_tar_path"`) {
		return domain.Invalidf("sandbox.create", "image is required")
	}
	for _, argument := range request.Command {
		if strings.ContainsRune(argument, 0) {
			return domain.Invalidf("sandbox.create", "command contains NUL")
		}
	}
	return nil
}

func operationIdentity(action string, request Request) (string, string, error) {
	hashInput := struct {
		Workspace  domain.WorkspaceID `json:"workspace"`
		Sandbox    domain.SandboxID   `json:"sandbox"`
		Generation domain.Generation  `json:"generation"`
		Image      string             `json:"image"`
		Command    []string           `json:"command"`
		Labels     map[string]string  `json:"labels"`
	}{request.Workspace, request.Sandbox, request.Generation, request.Image, request.Command, request.Labels}
	encoded, err := json.Marshal(hashInput)
	if err != nil {
		return "", "", domain.Wrap(err, "sandbox.identity", "encode request")
	}
	sum := sha256.Sum256(encoded)
	hash := hex.EncodeToString(sum[:])
	key := strings.TrimSpace(string(request.IdempotencyKey))
	if key == "" {
		key = string(request.Workspace) + "/" + string(request.Sandbox) + "/" + action + "/" + hash[:16]
	} else {
		key = action + ":" + key
	}
	return key, hash, nil
}

func deleteIdentity(ref domain.SandboxRef, key domain.OperationID) (string, string, error) {
	hash := sha256.Sum256([]byte(string(ref.Workspace) + "/" + string(ref.Sandbox)))
	operationKey := strings.TrimSpace(string(key))
	if operationKey == "" {
		operationKey = "delete/" + hex.EncodeToString(hash[:16])
	} else {
		operationKey = "delete:" + operationKey
	}
	return operationKey, hex.EncodeToString(hash[:]), nil
}

func refKey(ref domain.SandboxRef) string {
	return string(ref.Workspace) + "/" + string(ref.Sandbox)
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
