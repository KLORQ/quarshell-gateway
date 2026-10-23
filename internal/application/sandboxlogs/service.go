// Package sandboxlogs persists bounded supervisor log windows per sandbox.
package sandboxlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const (
	recordKind = "sandbox_log_window"
	maxLines   = 2000
	maxBytes   = 8 << 20
)

// Line is one sandbox-correlated Gateway or supervisor log observation.
type Line struct {
	SandboxID string    `json:"sandbox_id"`
	Sequence  uint64    `json:"sequence,omitempty"`
	EventTime time.Time `json:"event_time,omitempty"`
	Level     string    `json:"level,omitempty"`
	Target    string    `json:"target,omitempty"`
	Message   string    `json:"message"`
	Source    string    `json:"source,omitempty"`
}

// PlatformEvent is one resumable backend lifecycle observation.
type PlatformEvent struct {
	SandboxID string            `json:"sandbox_id"`
	Sequence  uint64            `json:"sequence,omitempty"`
	EventTime time.Time         `json:"event_time"`
	Source    string            `json:"source"`
	Type      string            `json:"type"`
	Reason    string            `json:"reason,omitempty"`
	Message   string            `json:"message,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Terminal  bool              `json:"terminal,omitempty"`
	DedupKey  string            `json:"dedup_key,omitempty"`
}

// Service owns each sandbox's durable bounded log window.
type Service struct{ store lifecycle.Store }

type window struct {
	NextSequence        uint64          `json:"next_sequence"`
	LogTrimmedThrough   uint64          `json:"log_trimmed_through,omitempty"`
	EventTrimmedThrough uint64          `json:"event_trimmed_through,omitempty"`
	Lines               []Line          `json:"lines"`
	Events              []PlatformEvent `json:"events,omitempty"`
}

// WatchSnapshot is an atomic snapshot of both sources and their shared cursor
// bounds for one sandbox.
type WatchSnapshot struct {
	Lines                []Line
	Events               []PlatformEvent
	LatestSequence       uint64
	LogsTrimmedThrough   uint64
	EventsTrimmedThrough uint64
}

// New returns a log service backed by the shared lifecycle store.
func New(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("sandbox logs: lifecycle store is required")
	}
	return &Service{store: store}, nil
}

// Append adds one batch atomically, retaining at most 2000 lines and 8 MiB.
func (s *Service) Append(ctx context.Context, sandboxID string, batch []Line) ([]Line, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" || len(sandboxID) > 256 {
		return nil, fmt.Errorf("sandbox logs: invalid sandbox ID")
	}
	for _, line := range batch {
		if line.SandboxID != sandboxID || strings.TrimSpace(line.Message) == "" || len(line.Message) > 64*1024 {
			return nil, fmt.Errorf("sandbox logs: invalid line identity or message")
		}
	}
	if len(batch) == 0 {
		return nil, nil
	}
	var appended []Line
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		state, exists, version, err := loadWindow(tx, sandboxID)
		if err != nil {
			return err
		}
		for _, line := range batch {
			if state.NextSequence == ^uint64(0) {
				return fmt.Errorf("sandbox logs: sequence exhausted")
			}
			state.NextSequence++
			line.Sequence = state.NextSequence
			state.Lines = append(state.Lines, line)
			appended = append(appended, line)
		}
		if len(state.Lines) > maxLines {
			removed := state.Lines[:len(state.Lines)-maxLines]
			state.LogTrimmedThrough = max(state.LogTrimmedThrough, lastLineSequence(removed))
			state.Lines = state.Lines[len(state.Lines)-maxLines:]
		}
		if encodedSize(state.Lines) > maxBytes {
			low, high := 1, len(state.Lines)
			for low < high {
				mid := low + (high-low)/2
				if encodedSize(state.Lines[mid:]) <= maxBytes {
					high = mid
				} else {
					low = mid + 1
				}
			}
			state.LogTrimmedThrough = max(state.LogTrimmedThrough, lastLineSequence(state.Lines[:low]))
			state.Lines = state.Lines[low:]
		}
		return saveWindow(tx, sandboxID, version, exists, state)
	})
	return appended, err
}

// AppendPlatformEvent appends one deduplicated event in the same per-sandbox
// cursor space as log lines. A non-empty DedupKey makes repeated backend
// snapshots idempotent while they remain in the retained event window.
func (s *Service) AppendPlatformEvent(ctx context.Context, event PlatformEvent) (PlatformEvent, bool, error) {
	event.SandboxID = strings.TrimSpace(event.SandboxID)
	if event.SandboxID == "" || len(event.SandboxID) > 256 || event.Source == "" || event.Type == "" || event.EventTime.IsZero() {
		return PlatformEvent{}, false, fmt.Errorf("sandbox logs: invalid platform event")
	}
	if len(event.Source) > 128 || len(event.Type) > 128 || len(event.Reason) > 256 || len(event.Message) > 64*1024 || len(event.DedupKey) > 1024 {
		return PlatformEvent{}, false, fmt.Errorf("sandbox logs: platform event exceeds field limits")
	}
	if len(event.Metadata) > 64 {
		return PlatformEvent{}, false, fmt.Errorf("sandbox logs: platform event has too many metadata fields")
	}
	metadataBytes := 0
	for key, value := range event.Metadata {
		if key == "" || len(key) > 256 || len(value) > 4096 {
			return PlatformEvent{}, false, fmt.Errorf("sandbox logs: invalid platform event metadata")
		}
		metadataBytes += len(key) + len(value)
	}
	if metadataBytes > 16*1024 {
		return PlatformEvent{}, false, fmt.Errorf("sandbox logs: platform event metadata exceeds size limit")
	}
	var appended PlatformEvent
	created := false
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		state, exists, version, err := loadWindow(tx, event.SandboxID)
		if err != nil {
			return err
		}
		if event.DedupKey != "" {
			for _, retained := range state.Events {
				if retained.DedupKey == event.DedupKey {
					appended = retained
					return nil
				}
			}
		}
		if state.NextSequence == ^uint64(0) {
			return fmt.Errorf("sandbox logs: sequence exhausted")
		}
		state.NextSequence++
		event.Sequence = state.NextSequence
		event.EventTime = event.EventTime.UTC()
		event.Metadata = cloneMetadata(event.Metadata)
		state.Events = append(state.Events, event)
		if len(state.Events) > maxLines {
			removed := state.Events[:len(state.Events)-maxLines]
			state.EventTrimmedThrough = max(state.EventTrimmedThrough, lastEventSequence(removed))
			state.Events = state.Events[len(state.Events)-maxLines:]
		}
		if encodedSize(state.Events) > maxBytes {
			low, high := 1, len(state.Events)
			for low < high {
				mid := low + (high-low)/2
				if encodedSize(state.Events[mid:]) <= maxBytes {
					high = mid
				} else {
					low = mid + 1
				}
			}
			state.EventTrimmedThrough = max(state.EventTrimmedThrough, lastEventSequence(state.Events[:low]))
			state.Events = state.Events[low:]
		}
		if err := saveWindow(tx, event.SandboxID, version, exists, state); err != nil {
			return err
		}
		appended = event
		created = true
		return nil
	})
	return appended, created, err
}

// ListPlatformEvents returns retained platform events in cursor order.
func (s *Service) ListPlatformEvents(ctx context.Context, sandboxID string) ([]PlatformEvent, error) {
	snapshot, err := s.Snapshot(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	return snapshot.Events, nil
}

// CursorState returns the high-water mark and per-source trim marks for a
// sandbox's merged log/event cursor space.
func (s *Service) CursorState(ctx context.Context, sandboxID string) (latest, logsTrimmed, eventsTrimmed uint64, err error) {
	snapshot, err := s.Snapshot(ctx, sandboxID)
	if err != nil {
		return 0, 0, 0, err
	}
	return snapshot.LatestSequence, snapshot.LogsTrimmedThrough, snapshot.EventsTrimmedThrough, nil
}

// List returns a copy of the retained window for one sandbox.
func (s *Service) List(ctx context.Context, sandboxID string) ([]Line, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" || len(sandboxID) > 256 {
		return nil, fmt.Errorf("sandbox logs: invalid sandbox ID")
	}
	state, err := s.readWindow(ctx, sandboxID)
	return append([]Line(nil), state.Lines...), err
}

func (s *Service) readWindow(ctx context.Context, sandboxID string) (state window, err error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" || len(sandboxID) > 256 {
		return state, fmt.Errorf("sandbox logs: invalid sandbox ID")
	}
	err = s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		var exists bool
		state, exists, _, err = loadWindow(tx, sandboxID)
		if err != nil || !exists {
			return err
		}
		return nil
	})
	return state, err
}

// Snapshot reads retained logs/events and cursor bounds in one lifecycle-store
// view so a merged WatchSandbox replay cannot observe mixed generations.
func (s *Service) Snapshot(ctx context.Context, sandboxID string) (snapshot WatchSnapshot, err error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" || len(sandboxID) > 256 {
		return snapshot, fmt.Errorf("sandbox logs: invalid sandbox ID")
	}
	err = s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		state, exists, _, err := loadWindow(tx, sandboxID)
		if err != nil || !exists {
			return err
		}
		snapshot = WatchSnapshot{
			Lines:                append([]Line(nil), state.Lines...),
			Events:               append([]PlatformEvent(nil), state.Events...),
			LatestSequence:       state.NextSequence,
			LogsTrimmedThrough:   state.LogTrimmedThrough,
			EventsTrimmedThrough: state.EventTrimmedThrough,
		}
		for index := range snapshot.Events {
			snapshot.Events[index].Metadata = cloneMetadata(snapshot.Events[index].Metadata)
		}
		return nil
	})
	return snapshot, err
}

func loadWindow(tx lifecycle.ReadTx, sandboxID string) (window, bool, uint64, error) {
	record, exists, err := tx.Get(recordKind, sandboxID)
	if err != nil || !exists {
		return window{}, exists, 0, err
	}
	var state window
	if len(record.Payload) > 0 && record.Payload[0] == '{' {
		if err := json.Unmarshal(record.Payload, &state); err != nil {
			return window{}, true, 0, fmt.Errorf("sandbox logs: decode persisted window: %w", err)
		}
		return state, true, record.Version, nil
	}
	if err := json.Unmarshal(record.Payload, &state.Lines); err != nil {
		return window{}, true, 0, fmt.Errorf("sandbox logs: decode persisted window: %w", err)
	}
	for index := range state.Lines {
		state.Lines[index].Sequence = uint64(index + 1)
		state.NextSequence = uint64(index + 1)
	}
	return state, true, record.Version, nil
}

func saveWindow(tx lifecycle.WriteTx, sandboxID string, version uint64, exists bool, state window) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("sandbox logs: encode window: %w", err)
	}
	_, err = tx.Put(recordKind, sandboxID, version, payload)
	return err
}

func lastLineSequence(lines []Line) uint64 {
	if len(lines) == 0 {
		return 0
	}
	return lines[len(lines)-1].Sequence
}

func lastEventSequence(events []PlatformEvent) uint64 {
	if len(events) == 0 {
		return 0
	}
	return events[len(events)-1].Sequence
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}
	clone := make(map[string]string, len(metadata))
	for key, value := range metadata {
		clone[key] = value
	}
	return clone
}

func encodedSize[T any](items []T) int {
	payload, _ := json.Marshal(items)
	return len(payload)
}
