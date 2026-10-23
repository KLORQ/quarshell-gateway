package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const supervisorLeaseKind = "sandbox-supervisor-lease"

// SupervisorLeaseTTL preserves ownership for transient control-stream loss.
const SupervisorLeaseTTL = 45 * time.Second

type supervisorLease struct {
	Generation      domain.Generation `json:"generation"`
	CredentialEpoch uint64            `json:"credential_epoch"`
	SessionID       string            `json:"session_id"`
	InstanceID      string            `json:"instance_id"`
	ConnectionEpoch uint64            `json:"connection_epoch"`
	ExpiresAt       time.Time         `json:"expires_at"`
}

// ClaimSupervisorSession durably claims one authenticated supervisor session.
// A live owner may only reconnect as the same instance with a higher epoch.
func (s *Service) ClaimSupervisorSession(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, credentialEpoch uint64, sessionID, instanceID string, connectionEpoch uint64) error {
	if !ref.Valid() || generation == 0 || credentialEpoch == 0 || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(instanceID) == "" || connectionEpoch == 0 {
		return domain.Invalidf("sandbox.supervisor.claim", "sandbox, generation, credential epoch, session, instance and connection epoch are required")
	}
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		if err := s.validateSupervisorLeaseSandbox(tx, ref, generation, credentialEpoch); err != nil {
			return err
		}
		key := refKey(ref)
		record, exists, err := tx.Get(supervisorLeaseKind, key)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if exists {
			var current supervisorLease
			if err := json.Unmarshal(record.Payload, &current); err != nil {
				return fmt.Errorf("decode supervisor lease: %w", err)
			}
			if current.Generation == generation && current.CredentialEpoch == credentialEpoch && now.Before(current.ExpiresAt) &&
				(current.InstanceID != instanceID || connectionEpoch <= current.ConnectionEpoch) {
				return domain.New(domain.CodeConflict, "sandbox.supervisor.claim", "supervisor session is owned or connection epoch was replayed")
			}
		}
		lease := supervisorLease{
			Generation: generation, CredentialEpoch: credentialEpoch,
			SessionID: sessionID, InstanceID: instanceID, ConnectionEpoch: connectionEpoch,
			ExpiresAt: now.Add(SupervisorLeaseTTL),
		}
		payload, err := json.Marshal(lease)
		if err != nil {
			return err
		}
		_, err = tx.Put(supervisorLeaseKind, key, record.Version, payload)
		return err
	})
}

// RenewSupervisorSession extends the lease only for its exact current owner.
func (s *Service) RenewSupervisorSession(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, credentialEpoch uint64, instanceID string, connectionEpoch uint64) error {
	if !ref.Valid() || generation == 0 || credentialEpoch == 0 || strings.TrimSpace(instanceID) == "" || connectionEpoch == 0 {
		return domain.Invalidf("sandbox.supervisor.renew", "sandbox, generation, credential epoch, instance and connection epoch are required")
	}
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		if err := s.validateSupervisorLeaseSandbox(tx, ref, generation, credentialEpoch); err != nil {
			return err
		}
		key := refKey(ref)
		record, exists, err := tx.Get(supervisorLeaseKind, key)
		if err != nil {
			return err
		}
		if !exists {
			return domain.New(domain.CodeConflict, "sandbox.supervisor.renew", "supervisor session lease is missing")
		}
		var lease supervisorLease
		if err := json.Unmarshal(record.Payload, &lease); err != nil {
			return fmt.Errorf("decode supervisor lease: %w", err)
		}
		now := s.now().UTC()
		if lease.Generation != generation || lease.CredentialEpoch != credentialEpoch || lease.InstanceID != instanceID || lease.ConnectionEpoch != connectionEpoch || !now.Before(lease.ExpiresAt) {
			return domain.New(domain.CodeConflict, "sandbox.supervisor.renew", "supervisor session ownership expired or changed")
		}
		lease.ExpiresAt = now.Add(SupervisorLeaseTTL)
		payload, err := json.Marshal(lease)
		if err != nil {
			return err
		}
		_, err = tx.Put(supervisorLeaseKind, key, record.Version, payload)
		return err
	})
}

// ValidateSupervisorSession fences data-plane relay work to the durable owner.
// A Gateway replica can still have a locally connected stream after a newer
// owner has claimed the shared lease, so local Hub ownership alone is not enough.
func (s *Service) ValidateSupervisorSession(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, credentialEpoch uint64, instanceID string, connectionEpoch uint64) error {
	if !ref.Valid() || generation == 0 || credentialEpoch == 0 || strings.TrimSpace(instanceID) == "" || connectionEpoch == 0 {
		return domain.Invalidf("sandbox.supervisor.validate", "sandbox, generation, credential epoch, instance and connection epoch are required")
	}
	return s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		sandboxRecord, exists, err := tx.Get(recordKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "sandbox.supervisor.validate", "sandbox not found")
		}
		var current Sandbox
		if err := json.Unmarshal(sandboxRecord.Payload, &current); err != nil {
			return err
		}
		terminalExitPending := current.MainProcessExitCode != nil && !current.MainProcessFinalized
		if (current.State != "running" && !terminalExitPending) || current.RuntimeGenerationOrInitial() != generation || current.CredentialEpochOrInitial() != credentialEpoch {
			return domain.New(domain.CodeConflict, "sandbox.supervisor.validate", "sandbox generation is no longer active for these credentials")
		}
		record, exists, err := tx.Get(supervisorLeaseKind, refKey(ref))
		if err != nil {
			return err
		}
		if !exists {
			return domain.New(domain.CodeConflict, "sandbox.supervisor.validate", "supervisor session lease is missing")
		}
		var lease supervisorLease
		if err := json.Unmarshal(record.Payload, &lease); err != nil {
			return fmt.Errorf("decode supervisor lease: %w", err)
		}
		if lease.Generation != generation || lease.CredentialEpoch != credentialEpoch || lease.InstanceID != instanceID || lease.ConnectionEpoch != connectionEpoch || !s.now().UTC().Before(lease.ExpiresAt) {
			return domain.New(domain.CodeConflict, "sandbox.supervisor.validate", "supervisor session no longer owns the durable lease")
		}
		return nil
	})
}

func (s *Service) validateSupervisorLeaseSandbox(tx lifecycle.ReadTx, ref domain.SandboxRef, generation domain.Generation, credentialEpoch uint64) error {
	record, exists, err := tx.Get(recordKind, refKey(ref))
	if err != nil {
		return err
	}
	if !exists {
		return domain.Wrap(domain.ErrNotFound, "sandbox.supervisor", "sandbox not found")
	}
	var current Sandbox
	if err := json.Unmarshal(record.Payload, &current); err != nil {
		return err
	}
	if current.State != "running" || current.RuntimeGenerationOrInitial() != generation || current.CredentialEpochOrInitial() != credentialEpoch {
		return domain.New(domain.CodeConflict, "sandbox.supervisor", "sandbox generation is not running for these credentials")
	}
	return nil
}

func deleteSupervisorLease(tx lifecycle.WriteTx, ref domain.SandboxRef) error {
	record, exists, err := tx.Get(supervisorLeaseKind, refKey(ref))
	if err != nil || !exists {
		return err
	}
	return tx.Delete(supervisorLeaseKind, refKey(ref), record.Version)
}
