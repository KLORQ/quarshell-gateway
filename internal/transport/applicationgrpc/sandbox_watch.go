package applicationgrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sandboxWatchBuffer = 128

// WatchSandbox streams an initial sandbox snapshot, bounded log replay and live
// status/log/platform-event updates.
func (s *Server) WatchSandbox(request *gatewayv1.WatchSandboxRequest, stream gatewayv1.OpenShell_WatchSandboxServer) error {
	if request == nil || strings.TrimSpace(request.GetSandbox()) == "" {
		return status.Error(codes.InvalidArgument, "sandbox is required")
	}
	if !request.GetFollowLogs() && !request.GetFollowStatus() && !request.GetFollowEvents() {
		return status.Error(codes.InvalidArgument, "follow_logs, follow_status, or follow_events is required")
	}
	if s.Sandboxes == nil {
		return status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	if since := request.GetSinceTime(); since != nil && !since.IsValid() {
		return status.Error(codes.InvalidArgument, "since_time is invalid")
	}
	ref := domain.SandboxRef{Workspace: workspaceID(request.GetWorkspaceScope()), Sandbox: domain.SandboxID(request.GetSandbox())}
	current, err := s.Sandboxes.Get(stream.Context(), ref)
	if err != nil {
		return grpcError(err)
	}
	if s.SandboxLogs != nil {
		epoch, err := s.SandboxLogs.CursorEpoch(stream.Context())
		if err != nil {
			return status.Error(codes.Unavailable, "sandbox watch cursor storage is unavailable")
		}
		s.setSandboxLogCursorEpoch(epoch)
	}
	var platformEvents <-chan driver.PlatformEventResult
	if request.GetFollowEvents() {
		watcher, ok := s.Sandboxes.Runtime.(interface {
			WatchPlatformEvents(context.Context, sandboxruntime.Sandbox) (<-chan driver.PlatformEventResult, error)
		})
		if !ok {
			return status.Error(codes.Unimplemented, "platform event watch is not configured for this backend")
		}
		eventCtx, cancelEvents := context.WithCancel(stream.Context())
		defer cancelEvents()
		platformEvents, err = watcher.WatchPlatformEvents(eventCtx, sandboxruntime.Sandbox{Sandbox: current.Sandbox, RuntimeID: current.RuntimeID})
		if err != nil {
			return grpcError(err)
		}
	}

	resumeCursor := strings.TrimSpace(request.GetResumeAfterCursor())
	resumeSequence := uint64(0)
	if resumeCursor != "" {
		if s.SandboxLogs == nil {
			return status.Error(codes.OutOfRange, "watch cursor is not available in this Gateway instance")
		}
		var sameEpoch, valid bool
		resumeSequence, sameEpoch, valid = s.parseSandboxLogCursor(request.GetSandbox(), resumeCursor)
		if !sameEpoch {
			return status.Error(codes.OutOfRange, "watch cursor belongs to a previous Gateway cursor space")
		}
		if !valid {
			return status.Error(codes.InvalidArgument, "resume_after_cursor was not issued for this sandbox and Gateway instance")
		}
	}
	var live chan *gatewayv1.SandboxStreamEvent
	var logReplay, platformReplay []*gatewayv1.SandboxStreamEvent
	logCutoff := resumeSequence
	platformCutoff := resumeSequence
	if request.GetFollowEvents() && request.GetEventTail() > 0 && s.SandboxLogs == nil {
		return status.Error(codes.Unavailable, "platform event replay storage is not configured")
	}
	var watchSnapshot sandboxlogs.WatchSnapshot
	snapshotLoaded := false
	if request.GetFollowLogs() {
		live = make(chan *gatewayv1.SandboxStreamEvent, sandboxWatchBuffer)
		s.logMu.Lock()
		if s.logWatchers == nil {
			s.logWatchers = make(map[string]map[chan *gatewayv1.SandboxStreamEvent]struct{})
		}
		if s.logWatchers[request.GetSandbox()] == nil {
			s.logWatchers[request.GetSandbox()] = make(map[chan *gatewayv1.SandboxStreamEvent]struct{})
		}
		s.logWatchers[request.GetSandbox()][live] = struct{}{}
		var stored []*gatewayv1.SandboxStreamEvent
		var readErr error
		if s.SandboxLogs != nil {
			watchSnapshot, readErr = s.SandboxLogs.Snapshot(stream.Context(), request.GetSandbox())
			snapshotLoaded = readErr == nil
			if readErr == nil {
				stored = sandboxLogStreamEvents(s, request.GetSandbox(), watchSnapshot.Lines)
			}
		} else {
			stored, readErr = s.sandboxLogSnapshotLocked(stream.Context(), request.GetSandbox())
		}
		s.logMu.Unlock()
		if readErr != nil {
			s.removeSandboxLogWatcher(request.GetSandbox(), live)
			return status.Error(codes.Internal, "read sandbox log replay")
		}
		defer s.removeSandboxLogWatcher(request.GetSandbox(), live)
		if resumeCursor == "" {
			tail := boundedWatchTail(request.GetLogTailLines(), 200)
			if tail > 0 && len(stored) > tail {
				stored = stored[len(stored)-tail:]
			}
		}
		for _, event := range stored {
			line := event.GetLog()
			sequence := cursorSequence(event.GetCursor())
			if sequence > logCutoff {
				logCutoff = sequence
			}
			if line == nil || (resumeCursor != "" && sequence <= resumeSequence) {
				continue
			}
			if watchLogMatches(line, request) {
				logReplay = append(logReplay, event)
			}
		}
	}
	if (request.GetFollowEvents() || resumeCursor != "") && s.SandboxLogs != nil {
		if !snapshotLoaded {
			watchSnapshot, err = s.SandboxLogs.Snapshot(stream.Context(), request.GetSandbox())
			if err != nil {
				return status.Error(codes.Internal, "read sandbox watch replay")
			}
			snapshotLoaded = true
		}
	}
	if request.GetFollowEvents() && s.SandboxLogs != nil {
		if resumeCursor != "" {
			if resumeSequence > watchSnapshot.LatestSequence {
				return status.Error(codes.InvalidArgument, "resume_after_cursor is ahead of the latest sandbox event")
			}
			if resumeSequence < watchSnapshot.EventsTrimmedThrough {
				return status.Error(codes.OutOfRange, "watch cursor has been trimmed from the platform event window")
			}
		}
		stored := watchSnapshot.Events
		if resumeCursor == "" {
			tail := boundedWatchTail(request.GetEventTail(), 0)
			if tail > 0 && len(stored) > tail {
				stored = stored[len(stored)-tail:]
			}
		}
		for _, event := range stored {
			if event.Sequence > platformCutoff {
				platformCutoff = event.Sequence
			}
			if resumeCursor != "" && event.Sequence <= resumeSequence {
				continue
			}
			platformReplay = append(platformReplay, platformStreamEvent(event, s.sandboxLogCursor(request.GetSandbox(), event.Sequence)))
		}
	}
	if request.GetFollowLogs() && resumeCursor != "" && s.SandboxLogs != nil {
		if resumeSequence > watchSnapshot.LatestSequence {
			return status.Error(codes.InvalidArgument, "resume_after_cursor is ahead of the latest sandbox event")
		}
		if resumeSequence < watchSnapshot.LogsTrimmedThrough {
			return status.Error(codes.OutOfRange, "watch cursor has been trimmed from the sandbox log window")
		}
	}

	lastSnapshot := sandboxProto(current, nil)
	if err := stream.Send(&gatewayv1.SandboxStreamEvent{Payload: &gatewayv1.SandboxStreamEvent_Sandbox{Sandbox: lastSnapshot}}); err != nil {
		return err
	}
	replay := append(logReplay, platformReplay...)
	sort.Slice(replay, func(i, j int) bool {
		return cursorSequence(replay[i].GetCursor()) < cursorSequence(replay[j].GetCursor())
	})
	for _, event := range replay {
		if err := stream.Send(event); err != nil {
			return err
		}
	}
	lastLogSequence := logCutoff
	lastPlatformSequence := platformCutoff
	if request.GetFollowEvents() && resumeCursor == "" && request.GetEventTail() == 0 && snapshotLoaded {
		lastPlatformSequence = watchSnapshot.LatestSequence
	}
	if resumeCursor != "" && resumeSequence > watchSnapshot.LatestSequence && snapshotLoaded {
		return status.Error(codes.InvalidArgument, "resume_after_cursor is ahead of the latest sandbox event")
	}
	if request.GetFollowLogs() && resumeCursor != "" && snapshotLoaded && resumeSequence < watchSnapshot.LogsTrimmedThrough {
		return status.Error(codes.OutOfRange, "watch cursor has been trimmed from the sandbox log window")
	}
	if request.GetFollowEvents() && resumeCursor != "" && snapshotLoaded && resumeSequence < watchSnapshot.EventsTrimmedThrough {
		return status.Error(codes.OutOfRange, "watch cursor has been trimmed from the platform event window")
	}
	if request.GetStopOnTerminal() && terminalWatchPhase(phaseFromState(current.State)) {
		return nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case event := <-live:
			if s.SandboxLogs != nil {
				terminal, err := s.sendSandboxWatchCatchup(stream.Context(), stream, request, &lastLogSequence, &lastPlatformSequence)
				if err != nil {
					return err
				}
				if request.GetStopOnTerminal() && terminal {
					return nil
				}
			} else {
				if line := event.GetLog(); line != nil {
					sequence := cursorSequence(event.GetCursor())
					if sequence <= lastLogSequence || !watchLogMatches(line, request) {
						continue
					}
					lastLogSequence = sequence
				}
				if err := stream.Send(proto.Clone(event).(*gatewayv1.SandboxStreamEvent)); err != nil {
					return err
				}
			}
		case result, open := <-platformEvents:
			if !open {
				platformEvents = nil
				continue
			}
			if result.Err != nil {
				return status.Error(codes.Unavailable, "platform event stream failed")
			}
			// Backends often identify platform events by their own runtime ID
			// (for example a VM UUID or container ID), while WatchSandbox is
			// addressed by the Gateway's logical Sandbox ID. Accept either ID
			// only for the runtime bound to the record loaded above.
			eventSandboxID := string(result.Event.SandboxID)
			runtimeSandboxID := strings.TrimSpace(current.RuntimeID)
			if eventSandboxID != request.GetSandbox() && (runtimeSandboxID == "" || eventSandboxID != runtimeSandboxID) {
				continue
			}
			eventTime := result.Event.Time
			if eventTime.IsZero() {
				eventTime = time.Now()
			}
			if s.SandboxLogs != nil {
				_, _, appendErr := s.SandboxLogs.AppendPlatformEvent(stream.Context(), sandboxlogs.PlatformEvent{
					SandboxID: request.GetSandbox(), EventTime: eventTime, Source: result.Event.Source, Type: result.Event.Type,
					Reason: result.Event.Reason, Message: result.Event.Message, Metadata: result.Event.Metadata,
					Terminal: result.Event.Terminal, DedupKey: sandboxPlatformEventDedupKey(result.Event, eventTime),
				})
				if appendErr != nil {
					return status.Error(codes.Internal, "persist sandbox platform event")
				}
				terminal, err := s.sendSandboxWatchCatchup(stream.Context(), stream, request, &lastLogSequence, &lastPlatformSequence)
				if err != nil {
					return err
				}
				if request.GetStopOnTerminal() && terminal {
					return nil
				}
			} else {
				wireEvent := platformStreamEvent(sandboxlogs.PlatformEvent{
					SandboxID: request.GetSandbox(), EventTime: eventTime, Source: result.Event.Source, Type: result.Event.Type,
					Reason: result.Event.Reason, Message: result.Event.Message, Metadata: result.Event.Metadata,
					Terminal: result.Event.Terminal,
				}, "")
				if err := stream.Send(wireEvent); err != nil {
					return err
				}
			}
			if request.GetStopOnTerminal() && result.Event.Terminal {
				return nil
			}
		case <-ticker.C:
			if request.GetFollowLogs() || request.GetFollowEvents() {
				terminal, err := s.sendSandboxWatchCatchup(stream.Context(), stream, request, &lastLogSequence, &lastPlatformSequence)
				if err != nil {
					return err
				}
				if request.GetStopOnTerminal() && terminal {
					return nil
				}
			}
			if !request.GetFollowStatus() && !request.GetStopOnTerminal() {
				continue
			}
			latest, err := s.Sandboxes.Get(stream.Context(), ref)
			if err != nil {
				return grpcError(err)
			}
			phase := phaseFromState(latest.State)
			if request.GetFollowStatus() {
				snapshot := sandboxProto(latest, nil)
				if !proto.Equal(lastSnapshot, snapshot) {
					if err := stream.Send(&gatewayv1.SandboxStreamEvent{Payload: &gatewayv1.SandboxStreamEvent_Sandbox{Sandbox: snapshot}}); err != nil {
						return err
					}
					lastSnapshot = snapshot
				}
			}
			if request.GetStopOnTerminal() && terminalWatchPhase(phase) {
				return nil
			}
		}
	}
}

func (s *Server) sandboxLogSnapshotLocked(ctx context.Context, sandboxID string) ([]*gatewayv1.SandboxStreamEvent, error) {
	if s.SandboxLogs != nil {
		lines, err := s.SandboxLogs.List(ctx, sandboxID)
		if err != nil {
			return nil, err
		}
		return sandboxLogStreamEvents(s, sandboxID, lines), nil
	}
	lines := s.sandboxLogs[sandboxID]
	out := make([]*gatewayv1.SandboxStreamEvent, 0, len(lines))
	for _, line := range lines {
		out = append(out, logStreamEvent(proto.Clone(line).(*gatewayv1.SandboxLogLine), ""))
	}
	return out, nil
}

func sandboxLogStreamEvents(s *Server, sandboxID string, lines []sandboxlogs.Line) []*gatewayv1.SandboxStreamEvent {
	out := make([]*gatewayv1.SandboxStreamEvent, 0, len(lines))
	for _, line := range lines {
		item := &gatewayv1.SandboxLogLine{SandboxId: line.SandboxID, Level: line.Level, Target: line.Target, Message: line.Message, Source: line.Source}
		if !line.EventTime.IsZero() {
			item.EventTime = timestamppb.New(line.EventTime)
		}
		out = append(out, &gatewayv1.SandboxStreamEvent{Payload: &gatewayv1.SandboxStreamEvent_Log{Log: item}, Cursor: s.sandboxLogCursor(sandboxID, line.Sequence)})
	}
	return out
}

func (s *Server) sendSandboxWatchCatchup(
	ctx context.Context,
	stream gatewayv1.OpenShell_WatchSandboxServer,
	request *gatewayv1.WatchSandboxRequest,
	lastLogSequence, lastPlatformSequence *uint64,
) (bool, error) {
	snapshot, err := s.SandboxLogs.Snapshot(ctx, request.GetSandbox())
	if err != nil {
		return false, status.Error(codes.Internal, "read sandbox watch live window")
	}
	if request.GetFollowLogs() && *lastLogSequence < snapshot.LogsTrimmedThrough {
		return false, status.Error(codes.OutOfRange, "sandbox log events were trimmed while the watch was live")
	}
	if request.GetFollowEvents() && *lastPlatformSequence < snapshot.EventsTrimmedThrough {
		return false, status.Error(codes.OutOfRange, "platform events were trimmed while the watch was live")
	}
	type pendingEvent struct {
		sequence uint64
		payload  *gatewayv1.SandboxStreamEvent
		terminal bool
	}
	pending := make([]pendingEvent, 0, len(snapshot.Lines)+len(snapshot.Events))
	if request.GetFollowLogs() {
		for _, line := range snapshot.Lines {
			if line.Sequence <= *lastLogSequence {
				continue
			}
			*lastLogSequence = line.Sequence
			event := sandboxLogStreamEvents(s, request.GetSandbox(), []sandboxlogs.Line{line})[0]
			if watchLogMatches(event.GetLog(), request) {
				pending = append(pending, pendingEvent{sequence: line.Sequence, payload: event})
			}
		}
	}
	if request.GetFollowEvents() {
		for _, event := range snapshot.Events {
			if event.Sequence <= *lastPlatformSequence {
				continue
			}
			*lastPlatformSequence = event.Sequence
			pending = append(pending, pendingEvent{
				sequence: event.Sequence,
				payload:  platformStreamEvent(event, s.sandboxLogCursor(request.GetSandbox(), event.Sequence)),
				terminal: event.Terminal,
			})
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].sequence < pending[j].sequence })
	terminal := false
	for _, event := range pending {
		if err := stream.Send(event.payload); err != nil {
			return false, err
		}
		terminal = terminal || event.terminal
	}
	return terminal, nil
}

func platformStreamEvent(event sandboxlogs.PlatformEvent, cursor string) *gatewayv1.SandboxStreamEvent {
	return &gatewayv1.SandboxStreamEvent{
		Payload: &gatewayv1.SandboxStreamEvent_Event{Event: &gatewayv1.PlatformEvent{
			EventTime: timestamppb.New(event.EventTime), Source: event.Source, Type: event.Type,
			Reason: event.Reason, Message: event.Message, Metadata: event.Metadata,
		}}, Cursor: cursor,
	}
}

func boundedWatchTail(requested uint32, defaultValue int) int {
	if requested == 0 {
		return defaultValue
	}
	if requested > sandboxLogRetention {
		return sandboxLogRetention
	}
	return int(requested)
}

func sandboxPlatformEventDedupKey(event driver.PlatformEvent, eventTime time.Time) string {
	encoded, _ := json.Marshal(struct {
		Time     string            `json:"time"`
		Source   string            `json:"source"`
		Type     string            `json:"type"`
		Reason   string            `json:"reason"`
		Message  string            `json:"message"`
		Metadata map[string]string `json:"metadata"`
	}{
		Time: eventTime.UTC().Format(time.RFC3339Nano), Source: event.Source, Type: event.Type,
		Reason: event.Reason, Message: event.Message, Metadata: event.Metadata,
	})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (s *Server) removeSandboxLogWatcher(sandboxID string, watcher chan *gatewayv1.SandboxStreamEvent) {
	s.logMu.Lock()
	delete(s.logWatchers[sandboxID], watcher)
	if len(s.logWatchers[sandboxID]) == 0 {
		delete(s.logWatchers, sandboxID)
	}
	s.logMu.Unlock()
}

func (s *Server) publishSandboxLogLocked(sandboxID string, line *gatewayv1.SandboxLogLine, cursor string) {
	if len(s.logWatchers[sandboxID]) == 0 {
		return
	}
	event := logStreamEvent(line, cursor)
	for watcher := range s.logWatchers[sandboxID] {
		select {
		case watcher <- event:
		default:
			select {
			case <-watcher:
			default:
			}
			warning := &gatewayv1.SandboxStreamEvent{Payload: &gatewayv1.SandboxStreamEvent_Warning{Warning: &gatewayv1.SandboxStreamWarning{Message: "sandbox log watch dropped events because its buffer was full"}}}
			select {
			case watcher <- warning:
			default:
			}
		}
	}
}

func logStreamEvent(line *gatewayv1.SandboxLogLine, cursor string) *gatewayv1.SandboxStreamEvent {
	return &gatewayv1.SandboxStreamEvent{Payload: &gatewayv1.SandboxStreamEvent_Log{Log: proto.Clone(line).(*gatewayv1.SandboxLogLine)}, Cursor: cursor}
}

func (s *Server) sandboxLogCursor(sandboxID string, sequence uint64) string {
	s.logCursorMu.Lock()
	if s.logCursorEpoch == "" {
		s.logCursorEpoch = randomSessionID()
	}
	epoch := s.logCursorEpoch
	s.logCursorMu.Unlock()
	digest := sha256.Sum256([]byte(sandboxID))
	return fmt.Sprintf("%s-%s-%020d", epoch, hex.EncodeToString(digest[:6]), sequence)
}

func (s *Server) parseSandboxLogCursor(sandboxID, cursor string) (uint64, bool, bool) {
	s.logCursorMu.Lock()
	if s.logCursorEpoch == "" {
		s.logCursorEpoch = randomSessionID()
	}
	epochPrefix := s.logCursorEpoch + "-"
	s.logCursorMu.Unlock()
	if !strings.HasPrefix(cursor, epochPrefix) {
		return 0, false, false
	}
	digest := sha256.Sum256([]byte(sandboxID))
	prefix := epochPrefix + hex.EncodeToString(digest[:6]) + "-"
	if !strings.HasPrefix(cursor, prefix) {
		return 0, true, false
	}
	sequence, err := strconv.ParseUint(strings.TrimPrefix(cursor, prefix), 10, 64)
	return sequence, true, err == nil && sequence > 0
}

func (s *Server) setSandboxLogCursorEpoch(epoch string) {
	s.logCursorMu.Lock()
	s.logCursorEpoch = epoch
	s.logCursorMu.Unlock()
}

func cursorSequence(cursor string) uint64 {
	parts := strings.Split(cursor, "-")
	if len(parts) == 0 {
		return 0
	}
	sequence, _ := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	return sequence
}

func watchLogMatches(line *gatewayv1.SandboxLogLine, request *gatewayv1.WatchSandboxRequest) bool {
	if sources := request.GetLogSources(); len(sources) > 0 {
		source := line.GetSource()
		if source == "" {
			source = "gateway"
		}
		matched := false
		for _, allowed := range sources {
			if allowed == source {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if since := request.GetSinceTime(); since != nil {
		if line.GetEventTime() == nil || line.GetEventTime().AsTime().Before(since.AsTime()) {
			return false
		}
	}
	minimum := logLevelRank(request.GetLogMinLevel())
	return minimum == 0 || logLevelRank(line.GetLevel()) >= minimum
}

func terminalWatchPhase(phase gatewayv1.SandboxPhase) bool {
	switch phase {
	case gatewayv1.SandboxPhase_SANDBOX_PHASE_READY,
		gatewayv1.SandboxPhase_SANDBOX_PHASE_COMPLETED,
		gatewayv1.SandboxPhase_SANDBOX_PHASE_STOPPED,
		gatewayv1.SandboxPhase_SANDBOX_PHASE_ERROR:
		return true
	default:
		return false
	}
}
