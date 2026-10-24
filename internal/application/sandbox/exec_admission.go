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

const execAdmissionRetention = 24 * time.Hour

type execAdmissionState struct {
	Completed bool   `json:"completed"`
	SessionID string `json:"session_id,omitempty"`
	Cursor    uint64 `json:"cursor,omitempty"`
}

// AdmitExecRequest durably fences a launch before it reaches a runtime. An
// unfinished record is retained indefinitely because a disconnected caller
// cannot know whether the guest started the command. A completed request ID
// may be reused after the upstream 24-hour retention window.
func (s *Service) AdmitExecRequest(ctx context.Context, ref domain.SandboxRef, requestID, requestHash string) error {
	if ctx == nil || s == nil || s.store == nil {
		return domain.Invalidf("sandbox.exec_admission", "context and lifecycle store are required")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" || requestHash == "" || ref.Workspace == "" || ref.Sandbox == "" {
		return domain.Invalidf("sandbox.exec_admission", "workspace, sandbox, request ID, and request hash are required")
	}
	key := execAdmissionKey(ref, requestID)
	now := s.now().UTC()
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		previous, exists, err := tx.GetOperation(key)
		if err != nil {
			return err
		}
		if exists {
			var state execAdmissionState
			_ = json.Unmarshal(previous.Result, &state)
			if !state.Completed || now.Sub(previous.CreatedAt) < execAdmissionRetention {
				return domain.New(domain.CodeConflict, "sandbox.exec_admission", "request_id has already been admitted")
			}
			if err := tx.DeleteOperation(key); err != nil {
				return err
			}
		}
		result, err := json.Marshal(execAdmissionState{})
		if err != nil {
			return fmt.Errorf("encode exec admission: %w", err)
		}
		return tx.PutOperation(lifecycle.Operation{Key: key, RequestHash: requestHash, Result: result, CreatedAt: now})
	})
}

// ExecSessionID returns the retained runtime handle for an admitted,
// unfinished exec request when its payload hash matches the original request.
func (s *Service) ExecSessionID(ctx context.Context, ref domain.SandboxRef, requestID, requestHash string) (string, bool, error) {
	sessionID, _, found, err := s.ExecSessionCheckpoint(ctx, ref, requestID, requestHash)
	return sessionID, found, err
}

// ExecSessionCheckpoint returns the retained process identity and the last
// output frame acknowledged by the durable request owner.
func (s *Service) ExecSessionCheckpoint(ctx context.Context, ref domain.SandboxRef, requestID, requestHash string) (string, uint64, bool, error) {
	if ctx == nil || s == nil || s.store == nil {
		return "", 0, false, domain.Invalidf("sandbox.exec_admission", "context and lifecycle store are required")
	}
	key := execAdmissionKey(ref, strings.TrimSpace(requestID))
	var state execAdmissionState
	var found bool
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		operation, exists, err := tx.GetOperation(key)
		if err != nil || !exists {
			return err
		}
		if operation.RequestHash != requestHash {
			return domain.New(domain.CodeConflict, "sandbox.exec_admission", "request_id payload does not match the admitted request")
		}
		if err := json.Unmarshal(operation.Result, &state); err != nil {
			return fmt.Errorf("decode exec admission: %w", err)
		}
		found = !state.Completed && state.SessionID != ""
		return nil
	})
	return state.SessionID, state.Cursor, found, err
}

// SetExecSessionCursor advances the durable replay position monotonically.
func (s *Service) SetExecSessionCursor(ctx context.Context, ref domain.SandboxRef, requestID, requestHash string, cursor uint64) error {
	if ctx == nil || s == nil || s.store == nil {
		return domain.Invalidf("sandbox.exec_admission", "context and lifecycle store are required")
	}
	key := execAdmissionKey(ref, strings.TrimSpace(requestID))
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		op, exists, err := tx.GetOperation(key)
		if err != nil {
			return err
		}
		if !exists || op.RequestHash != requestHash {
			return domain.New(domain.CodeConflict, "sandbox.exec_admission", "request_id was not admitted for this payload")
		}
		var state execAdmissionState
		if err := json.Unmarshal(op.Result, &state); err != nil {
			return fmt.Errorf("decode exec admission: %w", err)
		}
		if state.Completed || state.SessionID == "" {
			return domain.New(domain.CodeConflict, "sandbox.exec_admission", "exec session is not active")
		}
		if cursor <= state.Cursor {
			return nil
		}
		state.Cursor = cursor
		result, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("encode exec admission: %w", err)
		}
		if err := tx.DeleteOperation(key); err != nil {
			return err
		}
		op.Result = result
		return tx.PutOperation(op)
	})
}

// PrepareOutputReader atomically creates or resumes a durable cursor record for
// a canonical main-process output reader.
func (s *Service) PrepareOutputReader(ctx context.Context, ref domain.SandboxRef, readerID, readerHash string) (uint64, error) {
	if ctx == nil || s == nil || s.store == nil || readerID == "" || readerHash == "" {
		return 0, domain.Invalidf("sandbox.output_reader", "context, store, reader ID, and reader hash are required")
	}
	key := execAdmissionKey(ref, "reader:"+readerID)
	var cursor uint64
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		op, exists, err := tx.GetOperation(key)
		if err != nil {
			return err
		}
		if exists {
			if op.RequestHash != readerHash {
				return domain.New(domain.CodeConflict, "sandbox.output_reader", "reader ID was already used for another sandbox")
			}
			var state execAdmissionState
			if err := json.Unmarshal(op.Result, &state); err != nil {
				return fmt.Errorf("decode output reader cursor: %w", err)
			}
			if state.Completed {
				return domain.New(domain.CodeConflict, "sandbox.output_reader", "reader is already complete")
			}
			cursor = state.Cursor
			if state.SessionID != "" {
				return nil
			}
			state.SessionID = "canonical-main-process"
			result, err := json.Marshal(state)
			if err != nil {
				return fmt.Errorf("encode output reader cursor: %w", err)
			}
			if err := tx.DeleteOperation(key); err != nil {
				return err
			}
			op.Result = result
			return tx.PutOperation(op)
		}
		result, err := json.Marshal(execAdmissionState{SessionID: "canonical-main-process"})
		if err != nil {
			return fmt.Errorf("encode output reader cursor: %w", err)
		}
		return tx.PutOperation(lifecycle.Operation{Key: key, RequestHash: readerHash, Result: result, CreatedAt: s.now().UTC()})
	})
	return cursor, err
}

// SetOutputReaderCursor advances a canonical reader's replay position.
func (s *Service) SetOutputReaderCursor(ctx context.Context, ref domain.SandboxRef, readerID, readerHash string, cursor uint64) error {
	if readerID == "" {
		return domain.Invalidf("sandbox.output_reader", "reader ID is required")
	}
	return s.SetExecSessionCursor(ctx, ref, "reader:"+readerID, readerHash, cursor)
}

// SetExecSessionID records the runtime process handle so the same
// request_id can attach to that process after a transport disconnect.
func (s *Service) SetExecSessionID(ctx context.Context, ref domain.SandboxRef, requestID, requestHash, sessionID string) error {
	if ctx == nil || s == nil || s.store == nil {
		return domain.Invalidf("sandbox.exec_admission", "context and lifecycle store are required")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" || requestHash == "" || sessionID == "" {
		return domain.Invalidf("sandbox.exec_admission", "request ID, request hash, and exec session ID are required")
	}
	key := execAdmissionKey(ref, requestID)
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		operation, exists, err := tx.GetOperation(key)
		if err != nil {
			return err
		}
		if !exists || operation.RequestHash != requestHash {
			return domain.New(domain.CodeConflict, "sandbox.exec_admission", "request_id was not admitted for this payload")
		}
		var state execAdmissionState
		if err := json.Unmarshal(operation.Result, &state); err != nil {
			return fmt.Errorf("decode exec admission: %w", err)
		}
		if state.Completed || state.SessionID != "" {
			return domain.New(domain.CodeConflict, "sandbox.exec_admission", "exec session is already finalized")
		}
		state.SessionID = sessionID
		result, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("encode exec admission: %w", err)
		}
		if err := tx.DeleteOperation(key); err != nil {
			return err
		}
		operation.Result = result
		return tx.PutOperation(operation)
	})
}

// CompleteExecRequest starts the 24-hour duplicate-retention window after the
// command reaches a known terminal result.
func (s *Service) CompleteExecRequest(ctx context.Context, ref domain.SandboxRef, requestID string) error {
	if ctx == nil || s == nil || s.store == nil {
		return domain.Invalidf("sandbox.exec_admission", "context and lifecycle store are required")
	}
	key := execAdmissionKey(ref, strings.TrimSpace(requestID))
	now := s.now().UTC()
	return s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		operation, exists, err := tx.GetOperation(key)
		if err != nil {
			return err
		}
		if !exists {
			return domain.New(domain.CodeConflict, "sandbox.exec_admission", "request_id was not admitted")
		}
		result, err := json.Marshal(execAdmissionState{Completed: true})
		if err != nil {
			return fmt.Errorf("encode completed exec admission: %w", err)
		}
		if err := tx.DeleteOperation(key); err != nil {
			return err
		}
		operation.Result = result
		operation.CreatedAt = now
		return tx.PutOperation(operation)
	})
}

func execAdmissionKey(ref domain.SandboxRef, requestID string) string {
	return "sandbox.exec_admission:" + string(ref.Workspace) + "/" + string(ref.Sandbox) + ":" + requestID
}
