package applicationgrpc

import (
	"context"
	"io"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	runtimev1 "github.com/KLORQ/quarshell-proto/gen/go/quarshell/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) AttachTTY(stream grpc.BidiStreamingServer[runtimev1.MainProcessServiceAttachTTYRequest, runtimev1.MainProcessServiceAttachTTYResponse]) error {
	if s.Sandboxes == nil {
		return status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	first, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return status.Error(codes.InvalidArgument, "main-process TTY attachment requires a start message")
		}
		return err
	}
	start := first.GetStart()
	if start == nil || strings.TrimSpace(start.GetSandbox()) == "" || strings.TrimSpace(start.GetWorkspace()) == "" {
		return status.Error(codes.InvalidArgument, "main-process TTY attachment requires workspace and sandbox")
	}
	columns, rows := start.GetCols(), start.GetRows()
	if columns == 0 {
		columns = defaultExecColumns
	}
	if rows == 0 {
		rows = defaultExecRows
	}
	if !start.GetNonTty() && (columns > 65535 || rows > 65535) {
		return status.Error(codes.InvalidArgument, "terminal dimensions must not exceed 65535")
	}
	ref := domain.SandboxRef{Workspace: domain.WorkspaceID(start.GetWorkspace()), Sandbox: domain.SandboxID(start.GetSandbox())}
	readerID := strings.TrimSpace(start.GetReaderId())
	var cursor uint64
	readerHash := ""
	if readerID != "" {
		if !isNonzeroUUID(readerID) {
			return status.Error(codes.InvalidArgument, "reader_id must be a canonical UUID")
		}
		readerHash = canonicalMainProcessReaderHash(ref)
		cursor, err = s.Sandboxes.PrepareOutputReader(stream.Context(), ref, readerID, readerHash)
		if err != nil {
			return grpcError(err)
		}
	}
	adapter := &mainProcessTTYStreamAdapter{stream: stream}
	if start.GetNonTty() {
		return s.attachMainProcessStream(stream.Context(), ref, readerID, readerHash, cursor, adapter)
	}
	return s.attachMainProcessTTY(stream.Context(), ref, columns, rows, readerID, readerHash, cursor, adapter)
}

func (s *Server) Signal(ctx context.Context, request *runtimev1.MainProcessServiceSignalRequest) (*runtimev1.MainProcessServiceSignalResponse, error) {
	if s.Sandboxes == nil {
		return nil, status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	if strings.TrimSpace(request.GetWorkspace()) == "" || strings.TrimSpace(request.GetSandbox()) == "" {
		return nil, status.Error(codes.InvalidArgument, "main-process signal requires workspace and sandbox")
	}
	var signal driver.ExecProcessSignal
	switch request.GetSignal() {
	case runtimev1.MainProcessSignal_MAIN_PROCESS_SIGNAL_TERMINATE:
		signal = driver.ExecSignalTerminate
	case runtimev1.MainProcessSignal_MAIN_PROCESS_SIGNAL_KILL:
		signal = driver.ExecSignalKill
	case runtimev1.MainProcessSignal_MAIN_PROCESS_SIGNAL_INTERRUPT:
		signal = driver.ExecSignalInterrupt
	case runtimev1.MainProcessSignal_MAIN_PROCESS_SIGNAL_HANGUP:
		signal = driver.ExecSignalHangup
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported main-process signal")
	}
	ref := domain.SandboxRef{Workspace: domain.WorkspaceID(request.GetWorkspace()), Sandbox: domain.SandboxID(request.GetSandbox())}
	if err := s.Sandboxes.SignalMainProcess(ctx, ref, signal); err != nil {
		return nil, grpcError(err)
	}
	return &runtimev1.MainProcessServiceSignalResponse{}, nil
}

type mainProcessTTYStreamAdapter struct {
	stream grpc.BidiStreamingServer[runtimev1.MainProcessServiceAttachTTYRequest, runtimev1.MainProcessServiceAttachTTYResponse]
}

func (s *mainProcessTTYStreamAdapter) Context() context.Context { return s.stream.Context() }

func (s *mainProcessTTYStreamAdapter) Recv() (*gatewayv1.ExecSandboxInput, error) {
	input, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	switch payload := input.GetPayload().(type) {
	case *runtimev1.MainProcessServiceAttachTTYRequest_Stdin:
		return &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Stdin{Stdin: payload.Stdin}}, nil
	case *runtimev1.MainProcessServiceAttachTTYRequest_Resize:
		return &gatewayv1.ExecSandboxInput{Payload: &gatewayv1.ExecSandboxInput_Resize{Resize: &gatewayv1.ExecSandboxWindowResize{Cols: payload.Resize.GetCols(), Rows: payload.Resize.GetRows()}}}, nil
	default:
		return &gatewayv1.ExecSandboxInput{}, nil
	}
}

func (s *mainProcessTTYStreamAdapter) Send(event *gatewayv1.ExecSandboxEvent) error {
	switch payload := event.GetPayload().(type) {
	case *gatewayv1.ExecSandboxEvent_Stdout:
		return s.stream.Send(&runtimev1.MainProcessServiceAttachTTYResponse{Payload: &runtimev1.MainProcessServiceAttachTTYResponse_Stdout{Stdout: payload.Stdout.GetData()}})
	case *gatewayv1.ExecSandboxEvent_Stderr:
		return s.stream.Send(&runtimev1.MainProcessServiceAttachTTYResponse{Payload: &runtimev1.MainProcessServiceAttachTTYResponse_Stderr{Stderr: payload.Stderr.GetData()}})
	case *gatewayv1.ExecSandboxEvent_Exit:
		return s.stream.Send(&runtimev1.MainProcessServiceAttachTTYResponse{Payload: &runtimev1.MainProcessServiceAttachTTYResponse_ExitCode{ExitCode: payload.Exit.GetExitCode()}})
	default:
		return status.Error(codes.Internal, "unsupported main-process TTY event")
	}
}
