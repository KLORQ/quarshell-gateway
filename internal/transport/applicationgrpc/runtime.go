package applicationgrpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func unavailable(feature string) error {
	return status.Error(codes.Unimplemented, feature+" is not configured")
}

func credentialEpoch(epoch uint64) uint64 {
	if epoch == 0 {
		return 1
	}
	return epoch
}

func (s *Server) validateSupervisorRelayOwner(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, epoch uint64) error {
	instanceID, connectionEpoch, ok := s.SupervisorHub.SupervisorSession(string(ref.Sandbox))
	if !ok {
		return status.Error(codes.FailedPrecondition, "sandbox supervisor relay is not connected")
	}
	if err := s.Sandboxes.ValidateSupervisorSession(ctx, ref, generation, epoch, instanceID, connectionEpoch); err != nil {
		return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
	}
	return nil
}

func (s *Server) validatePendingSupervisorRelayOwner(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, epoch uint64, channel string) error {
	instanceID, connectionEpoch, ok := s.SupervisorHub.PendingSupervisorSession(string(ref.Sandbox), channel)
	if !ok {
		return status.Error(codes.NotFound, "relay channel is not pending for this sandbox")
	}
	if err := s.Sandboxes.ValidateSupervisorSession(ctx, ref, generation, epoch, instanceID, connectionEpoch); err != nil {
		return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
	}
	return nil
}

// monitorSupervisorRelayOwner closes an established data-plane connection if
// another Gateway claims the shared lease. A one-time open check would leave
// an already-active SSH/TCP stream usable until its transport or lease TTL ends.
func (s *Server) monitorSupervisorRelayOwner(ctx context.Context, ref domain.SandboxRef, generation domain.Generation, epoch uint64, closeConnection func()) (func(), <-chan struct{}) {
	stop := make(chan struct{})
	done := make(chan struct{})
	lost := make(chan struct{}, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.validateSupervisorRelayOwner(ctx, ref, generation, epoch); err != nil {
					closeConnection()
					lost <- struct{}{}
					return
				}
			}
		}
	}()
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() { close(stop) })
		<-done
	}, lost
}

// ReportMainProcessExit persists the terminal result from the active sandbox
// supervisor. The token, running generation, epoch and connected instance must
// all agree before the durable sandbox state is changed.
func (s *Server) ReportMainProcessExit(ctx context.Context, request *gatewayv1.ReportMainProcessExitRequest) (*gatewayv1.ReportMainProcessExitResponse, error) {
	principal, ok := sandboxPrincipalFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "sandbox principal required")
	}
	if request == nil || strings.TrimSpace(request.GetSandboxId()) == "" || strings.TrimSpace(request.GetInstanceId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and instance_id are required")
	}
	if request.GetSandboxId() != string(principal.sandbox) {
		return nil, status.Error(codes.PermissionDenied, "process exit sandbox does not match authenticated sandbox")
	}
	if s.Sandboxes == nil || s.SupervisorHub == nil {
		return nil, status.Error(codes.Unavailable, "sandbox runtime is not configured")
	}
	current, err := s.Sandboxes.GetBySandboxID(ctx, principal.sandbox)
	if err != nil {
		return nil, grpcError(err)
	}
	if current.State != "running" || current.RuntimeGenerationOrInitial() != principal.generation || current.CredentialEpochOrInitial() != principal.credentialEpoch {
		return nil, status.Error(codes.Unauthenticated, "sandbox credential is stale")
	}
	instance, connected := s.SupervisorHub.SupervisorInstance(request.GetSandboxId())
	if !connected || instance != request.GetInstanceId() {
		return nil, status.Error(codes.FailedPrecondition, "supervisor instance is not the active sandbox owner")
	}
	if err := s.validateSupervisorRelayOwner(ctx, domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch); err != nil {
		return nil, err
	}
	if err := s.Sandboxes.RecordMainProcessExit(ctx, domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, instance, request.GetExitCode()); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ReportMainProcessExitResponse{}, nil
}

// FinalizeMainProcessExit completes terminal delivery for the active
// supervisor instance after its process result has been recorded.
func (s *Server) FinalizeMainProcessExit(ctx context.Context, request *gatewayv1.FinalizeMainProcessExitRequest) (*gatewayv1.FinalizeMainProcessExitResponse, error) {
	principal, ok := sandboxPrincipalFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "sandbox principal required")
	}
	if request == nil || strings.TrimSpace(request.GetSandboxId()) == "" || strings.TrimSpace(request.GetInstanceId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and instance_id are required")
	}
	if request.GetSandboxId() != string(principal.sandbox) {
		return nil, status.Error(codes.PermissionDenied, "process exit sandbox does not match authenticated sandbox")
	}
	if s.Sandboxes == nil || s.SupervisorHub == nil {
		return nil, status.Error(codes.Unavailable, "sandbox runtime is not configured")
	}
	current, err := s.Sandboxes.GetBySandboxID(ctx, principal.sandbox)
	if err != nil {
		return nil, grpcError(err)
	}
	if current.RuntimeGenerationOrInitial() != principal.generation || current.CredentialEpochOrInitial() != principal.credentialEpoch {
		return nil, status.Error(codes.Unauthenticated, "sandbox credential is stale")
	}
	instance, connected := s.SupervisorHub.SupervisorInstance(request.GetSandboxId())
	if !connected || instance != request.GetInstanceId() {
		return nil, status.Error(codes.FailedPrecondition, "supervisor instance is not the active sandbox owner")
	}
	if err := s.validateSupervisorRelayOwner(ctx, domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch); err != nil {
		return nil, err
	}
	if err := s.Sandboxes.FinalizeMainProcessExit(ctx, domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, instance); err != nil {
		return nil, grpcError(err)
	}
	s.SupervisorHub.ReleaseSupervisor(request.GetSandboxId())
	return &gatewayv1.FinalizeMainProcessExitResponse{}, nil
}

// IssueSandboxToken requires the auth-bound sandbox principal.
func (s *Server) IssueSandboxToken(context.Context, *gatewayv1.IssueSandboxTokenRequest) (*gatewayv1.IssueSandboxTokenResponse, error) {
	return nil, unavailable("sandbox token issuance")
}

// RefreshSandboxToken requires the auth-bound sandbox principal.
func (s *Server) RefreshSandboxToken(ctx context.Context, _ *gatewayv1.RefreshSandboxTokenRequest) (*gatewayv1.RefreshSandboxTokenResponse, error) {
	principal, ok := sandboxPrincipalFromContext(ctx)
	if !ok || s.Tokens == nil || s.Sandboxes == nil {
		return nil, status.Error(codes.Unauthenticated, "sandbox authentication required")
	}
	current, err := s.Sandboxes.GetBySandboxID(ctx, principal.sandbox)
	if err != nil || current.RuntimeGenerationOrInitial() != principal.generation || credentialEpoch(current.CredentialEpoch) != principal.credentialEpoch || current.State != "running" {
		return nil, status.Error(codes.Unauthenticated, "sandbox credential is stale")
	}
	// The inbound bearer was verified by the auth interceptor. Mint a fresh
	// generation-bound bearer with the token service's configured lifetime.
	ref := domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}
	epoch := credentialEpoch(current.CredentialEpoch)
	raw, claims, err := s.Tokens.IssueForAudienceEpoch(ref, principal.generation, epoch, "gateway", principal.subject, 0)
	if err != nil {
		return nil, status.Error(codes.Internal, "sandbox token refresh failed")
	}
	sandboxToken, sandboxClaims, err := s.Tokens.IssueForAudienceEpoch(ref, principal.generation, epoch, "sandbox", principal.subject, 0)
	if err != nil {
		return nil, status.Error(codes.Internal, "sandbox protocol credential refresh failed")
	}
	exp := timestamppb.New(claims.ExpiresAt)
	return &gatewayv1.RefreshSandboxTokenResponse{
		Token: raw, ExpirationTime: exp, SandboxToken: sandboxToken,
		SandboxExpirationTime: timestamppb.New(sandboxClaims.ExpiresAt),
		SessionId:             fmt.Sprintf("g%016x", uint64(principal.generation)),
		CredentialEpoch:       epoch,
	}, nil
}

func (s *Server) ConnectSupervisor(stream gatewayv1.OpenShell_ConnectSupervisorServer) error {
	principal, ok := sandboxPrincipalFromContext(stream.Context())
	if !ok || s.Sandboxes == nil || s.SupervisorHub == nil {
		return status.Error(codes.Unauthenticated, "sandbox authentication required")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.GetSandboxId() != string(principal.sandbox) || strings.TrimSpace(hello.GetInstanceId()) == "" || hello.GetConnectionEpoch() == 0 {
		return status.Error(codes.PermissionDenied, "supervisor hello does not match credential")
	}
	current, err := s.Sandboxes.GetBySandboxID(stream.Context(), principal.sandbox)
	if err != nil || current.RuntimeGenerationOrInitial() != principal.generation || credentialEpoch(current.CredentialEpoch) != principal.credentialEpoch || current.State != "running" {
		return status.Error(codes.PermissionDenied, "sandbox generation is not running")
	}
	if hello.GetSupportsSessionRedirect() && s.ReplicaRouting != nil {
		if replica, redirect := s.ReplicaRouting.Redirect(hello.GetSandboxId(), hello.GetRedirected(), s.draining.Load()); redirect {
			_ = stream.Send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_SessionRedirect{SessionRedirect: &gatewayv1.SessionRedirect{PeerEndpoint: replica.Endpoint, OwnerReplicaId: replica.ID}}})
			return nil
		}
	}
	sessionID := randomSessionID()
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	done := make(chan struct{})
	var sendMu sync.Mutex
	send := func(msg *gatewayv1.GatewayMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(msg)
	}
	unregister, err := s.SupervisorHub.RegisterSupervisor(string(principal.sandbox), hello.GetInstanceId(), hello.GetConnectionEpoch(), func(channel, target string) error {
		relay, err := relayOpenMessage(channel, target)
		if err != nil {
			return err
		}
		return send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_RelayOpen{RelayOpen: relay}})
	}, done, cancel)
	if err != nil {
		_ = stream.Send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_SessionRejected{SessionRejected: &gatewayv1.SessionRejected{Reason: err.Error()}}})
		return nil
	}
	if err := s.Sandboxes.ClaimSupervisorSession(stream.Context(), domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch, sessionID, hello.GetInstanceId(), hello.GetConnectionEpoch()); err != nil {
		_ = stream.Send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_SessionRejected{SessionRejected: &gatewayv1.SessionRejected{Reason: err.Error()}}})
		s.SupervisorHub.ReleaseSupervisorClaim(string(principal.sandbox), hello.GetInstanceId(), hello.GetConnectionEpoch())
		unregister()
		return nil
	}
	defer unregister()
	if err := stream.Send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_SessionAccepted{SessionAccepted: &gatewayv1.SessionAccepted{SessionId: sessionID, HeartbeatInterval: durationpb.New(15 * time.Second)}}}); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_Heartbeat{Heartbeat: &gatewayv1.GatewayHeartbeat{}}}) != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		msg, err := stream.Recv()
		if err != nil {
			close(done)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch payload := msg.GetPayload().(type) {
		case *gatewayv1.SupervisorMessage_Heartbeat:
			if err := s.Sandboxes.RenewSupervisorSession(stream.Context(), domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch, hello.GetInstanceId(), hello.GetConnectionEpoch()); err != nil || !s.SupervisorHub.RenewSupervisorOwner(string(principal.sandbox), hello.GetInstanceId(), hello.GetConnectionEpoch()) {
				return status.Error(codes.Aborted, "supervisor session ownership expired")
			}
			if err := send(&gatewayv1.GatewayMessage{Payload: &gatewayv1.GatewayMessage_Heartbeat{Heartbeat: &gatewayv1.GatewayHeartbeat{}}}); err != nil {
				return err
			}
		case *gatewayv1.SupervisorMessage_RelayOpenResult:
			if payload.RelayOpenResult != nil && !payload.RelayOpenResult.GetSuccess() {
				s.SupervisorHub.CloseRelay(string(principal.sandbox), payload.RelayOpenResult.GetChannelId(), errors.New(payload.RelayOpenResult.GetError()))
			}
		case *gatewayv1.SupervisorMessage_RelayClose:
			if payload.RelayClose != nil {
				s.SupervisorHub.CloseRelay(string(principal.sandbox), payload.RelayClose.GetChannelId(), errors.New(payload.RelayClose.GetReason()))
			}
		default:
			return status.Error(codes.InvalidArgument, "unexpected supervisor message")
		}
	}
}

func relayOpenMessage(channel, target string) (*gatewayv1.RelayOpen, error) {
	out := &gatewayv1.RelayOpen{ChannelId: channel}
	if target == "ssh" {
		out.Target = &gatewayv1.RelayOpen_Ssh{Ssh: &gatewayv1.SshRelayTarget{}}
		return out, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "tcp" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid relay target")
	}
	host := strings.Trim(u.Hostname(), "[]")
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 || (host != "localhost" && net.ParseIP(host) == nil) || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		return nil, errors.New("relay target must be loopback TCP")
	}
	out.Target = &gatewayv1.RelayOpen_Tcp{Tcp: &gatewayv1.TcpRelayTarget{Host: host, Port: uint32(port)}}
	return out, nil
}

func (s *Server) RelayStream(stream gatewayv1.OpenShell_RelayStreamServer) error {
	principal, ok := sandboxPrincipalFromContext(stream.Context())
	if !ok || s.Sandboxes == nil || s.SupervisorHub == nil {
		return status.Error(codes.Unauthenticated, "sandbox authentication required")
	}
	current, err := s.Sandboxes.GetBySandboxID(stream.Context(), principal.sandbox)
	if err != nil || current.RuntimeGenerationOrInitial() != principal.generation || credentialEpoch(current.CredentialEpoch) != principal.credentialEpoch || current.State != "running" {
		return status.Error(codes.PermissionDenied, "sandbox generation is not running")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	init := first.GetInit()
	if init == nil || init.GetChannelId() == "" {
		return status.Error(codes.InvalidArgument, "first relay frame must initialize a channel")
	}
	if err := s.validatePendingSupervisorRelayOwner(stream.Context(), domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch, init.GetChannelId()); err != nil {
		return err
	}
	conn, err := s.SupervisorHub.AcceptRelay(string(principal.sandbox), init.GetChannelId())
	if err != nil {
		return status.Error(codes.NotFound, "relay channel is not pending for this sandbox")
	}
	var closeOnce sync.Once
	closeConnection := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	stopOwnerMonitor, ownerLost := s.monitorSupervisorRelayOwner(stream.Context(), domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch, closeConnection)
	defer func() { stopOwnerMonitor(); closeConnection() }()
	if err := s.validateSupervisorRelayOwner(stream.Context(), domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}, principal.generation, principal.credentialEpoch); err != nil {
		return err
	}
	copyDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&gatewayv1.RelayFrame{Payload: &gatewayv1.RelayFrame_Data{Data: append([]byte(nil), buf[:n]...)}}); sendErr != nil {
					copyDone <- sendErr
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
					copyDone <- nil
				} else {
					copyDone <- readErr
				}
				return
			}
		}
	}()
	recvDone := make(chan error, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) {
					if cw, ok := conn.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
					recvDone <- nil
				} else {
					recvDone <- recvErr
				}
				return
			}
			data := frame.GetData()
			if data == nil {
				recvDone <- status.Error(codes.InvalidArgument, "relay frames after init must contain data")
				return
			}
			if _, err := conn.Write(data); err != nil {
				recvDone <- err
				return
			}
		}
	}()
	for {
		select {
		case err := <-recvDone:
			if err != nil {
				return err
			}
			select {
			case <-ownerLost:
				return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
			case err := <-copyDone:
				return err
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		case err := <-copyDone:
			return err
		case <-ownerLost:
			return status.Error(codes.Aborted, "sandbox supervisor relay ownership changed")
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func randomSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

const sandboxLogRetention = 2000

// PushSandboxLogs accepts bounded supervisor logs and binds every batch to the
// sandbox identity authenticated by the Sandbox Protocol bearer.
func (s *Server) PushSandboxLogs(stream gatewayv1.OpenShell_PushSandboxLogsServer) error {
	principal, ok := sandboxPrincipalFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "sandbox principal required")
	}
	var total int
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&gatewayv1.PushSandboxLogsResponse{})
		}
		if err != nil {
			return err
		}
		if request.GetSandboxId() == "" || string(principal.sandbox) != request.GetSandboxId() {
			return status.Error(codes.PermissionDenied, "log batch sandbox does not match authenticated sandbox")
		}
		total += len(request.GetLogs())
		if total > 1000 {
			return status.Error(codes.ResourceExhausted, "log batch exceeds 1000 lines")
		}
		for _, line := range request.GetLogs() {
			if line == nil || line.GetSandboxId() != request.GetSandboxId() || line.GetMessage() == "" || len(line.GetMessage()) > 64*1024 {
				return status.Error(codes.InvalidArgument, "log line identity or message is invalid")
			}
			if ts := line.GetEventTime(); ts != nil && !ts.IsValid() {
				return status.Error(codes.InvalidArgument, "log line event_time is invalid")
			}
		}
		if len(request.GetLogs()) == 0 {
			continue
		}
		s.logMu.Lock()
		var persisted []sandboxlogs.Line
		if s.SandboxLogs != nil {
			batch := make([]sandboxlogs.Line, 0, len(request.GetLogs()))
			for _, line := range request.GetLogs() {
				item := sandboxlogs.Line{
					SandboxID: line.GetSandboxId(), Level: line.GetLevel(), Target: line.GetTarget(),
					Message: line.GetMessage(), Source: line.GetSource(),
				}
				if eventTime := line.GetEventTime(); eventTime != nil {
					item.EventTime = eventTime.AsTime()
				}
				batch = append(batch, item)
			}
			var err error
			persisted, err = s.SandboxLogs.Append(stream.Context(), request.GetSandboxId(), batch)
			if err != nil {
				s.logMu.Unlock()
				return status.Error(codes.Internal, "persist sandbox logs")
			}
		}
		if s.sandboxLogs == nil {
			s.sandboxLogs = make(map[string][]*gatewayv1.SandboxLogLine)
		}
		lines := s.sandboxLogs[request.GetSandboxId()]
		for _, line := range request.GetLogs() {
			lines = append(lines, proto.Clone(line).(*gatewayv1.SandboxLogLine))
		}
		if len(lines) > sandboxLogRetention {
			lines = append([]*gatewayv1.SandboxLogLine(nil), lines[len(lines)-sandboxLogRetention:]...)
		}
		s.sandboxLogs[request.GetSandboxId()] = lines
		for index, line := range request.GetLogs() {
			sequence := uint64(0)
			if index < len(persisted) {
				sequence = persisted[index].Sequence
			} else {
				s.logCursorSeq[request.GetSandboxId()]++
				sequence = s.logCursorSeq[request.GetSandboxId()]
			}
			cursor := ""
			if sequence > 0 {
				cursor = s.sandboxLogCursor(request.GetSandboxId(), sequence)
			}
			s.publishSandboxLogLocked(request.GetSandboxId(), line, cursor)
		}
		s.logMu.Unlock()
	}
}

// GetSandboxLogs returns the retained log window for a sandbox.
func (s *Server) GetSandboxLogs(ctx context.Context, request *gatewayv1.GetSandboxLogsRequest) (*gatewayv1.GetSandboxLogsResponse, error) {
	if request == nil || strings.TrimSpace(request.GetSandbox()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox is required")
	}
	limit := int(request.GetLines())
	if limit <= 0 || limit > sandboxLogRetention {
		limit = sandboxLogRetention
	}
	allowedSources := make(map[string]struct{}, len(request.GetSources()))
	for _, source := range request.GetSources() {
		allowedSources[source] = struct{}{}
	}
	minimum := logLevelRank(request.GetMinLevel())
	var stored []*gatewayv1.SandboxLogLine
	if s.SandboxLogs != nil {
		lines, err := s.SandboxLogs.List(ctx, request.GetSandbox())
		if err != nil {
			return nil, status.Error(codes.Internal, "read sandbox logs")
		}
		stored = make([]*gatewayv1.SandboxLogLine, 0, len(lines))
		for _, line := range lines {
			item := &gatewayv1.SandboxLogLine{SandboxId: line.SandboxID, Level: line.Level, Target: line.Target, Message: line.Message, Source: line.Source}
			if !line.EventTime.IsZero() {
				item.EventTime = timestamppb.New(line.EventTime)
			}
			stored = append(stored, item)
		}
	} else {
		s.logMu.RLock()
		stored = s.sandboxLogs[request.GetSandbox()]
		s.logMu.RUnlock()
	}
	response := &gatewayv1.GetSandboxLogsResponse{BufferTotal: uint32(len(stored))}
	for _, line := range stored {
		if len(allowedSources) > 0 {
			if _, ok := allowedSources[line.GetSource()]; !ok {
				continue
			}
		}
		if since := request.GetSinceTime(); since != nil && line.GetEventTime() != nil && line.GetEventTime().AsTime().Before(since.AsTime()) {
			continue
		}
		if minimum > 0 && logLevelRank(line.GetLevel()) < minimum {
			continue
		}
		response.Logs = append(response.Logs, proto.Clone(line).(*gatewayv1.SandboxLogLine))
	}
	if len(response.Logs) > limit {
		response.Logs = response.Logs[len(response.Logs)-limit:]
	}
	return response, nil
}

func logLevelRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "TRACE":
		return 1
	case "DEBUG":
		return 2
	case "INFO":
		return 3
	case "WARN", "WARNING":
		return 4
	case "ERROR", "FATAL":
		return 5
	default:
		return 0
	}
}

// PeerReportProviderReadiness requires the peer relay runtime.
func (s *Server) PeerReportProviderReadiness(context.Context, *gatewayv1.ReportProviderReadinessRequest) (*gatewayv1.ReportProviderReadinessResponse, error) {
	return nil, unavailable("peer provider readiness")
}

// PeerReportEndpointStatus requires the peer relay runtime.
func (s *Server) PeerReportEndpointStatus(context.Context, *gatewayv1.ReportEndpointStatusRequest) (*gatewayv1.ReportEndpointStatusResponse, error) {
	return nil, unavailable("peer endpoint status")
}

// PeerGetSandboxProviderStatus requires the peer relay runtime.
func (s *Server) PeerGetSandboxProviderStatus(context.Context, *gatewayv1.GetSandboxProviderStatusRequest) (*gatewayv1.GetSandboxProviderStatusResponse, error) {
	return nil, unavailable("peer sandbox provider status")
}
