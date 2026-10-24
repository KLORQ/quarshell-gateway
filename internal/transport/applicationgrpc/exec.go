package applicationgrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-driver/driver"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	execOutputChunkBytes = 32 * 1024
	defaultExecColumns   = 80
	defaultExecRows      = 24
)

// ExecSandbox executes one command and sends bounded stdout/stderr chunks plus
// a final exit event. A supplied request_id is durably fenced before launch.
func (s *Server) ExecSandbox(request *gatewayv1.ExecSandboxRequest, stream gatewayv1.OpenShell_ExecSandboxServer) error {
	if s.Sandboxes == nil {
		return status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	if strings.TrimSpace(request.GetSandbox()) == "" || len(request.GetCommand()) == 0 {
		return status.Error(codes.InvalidArgument, "sandbox and command are required")
	}
	if strings.TrimSpace(request.GetCommand()[0]) == "" || strings.ContainsRune(request.GetWorkdir(), '\x00') {
		return status.Error(codes.InvalidArgument, "command and workdir must be valid")
	}
	for _, argument := range request.GetCommand() {
		if strings.ContainsRune(argument, '\x00') {
			return status.Error(codes.InvalidArgument, "command contains an invalid argument")
		}
	}
	columns, rows := request.GetCols(), request.GetRows()
	if !request.GetTty() && (columns != 0 || rows != 0) {
		return status.Error(codes.InvalidArgument, "terminal dimensions require tty=true")
	}
	if request.GetTty() {
		if columns == 0 {
			columns = defaultExecColumns
		}
		if rows == 0 {
			rows = defaultExecRows
		}
	}
	ctx := stream.Context()
	if timeout := request.GetExecutionTimeout(); timeout != nil {
		if err := timeout.CheckValid(); err != nil || timeout.AsDuration() <= 0 {
			return status.Error(codes.InvalidArgument, "execution_timeout must be a positive duration")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout.AsDuration())
		defer cancel()
	}
	environment := make([]string, 0, len(request.GetEnvironment()))
	keys := make([]string, 0, len(request.GetEnvironment()))
	for key := range request.GetEnvironment() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(request.GetEnvironment()[key], '\x00') {
			return status.Error(codes.InvalidArgument, "environment contains an invalid entry")
		}
		environment = append(environment, key+"="+request.GetEnvironment()[key])
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	if err := s.admitExecRequest(ctx, ref, request.GetRequestId(), request); err != nil {
		return err
	}
	result, err := s.Sandboxes.Exec(ctx, ref, driver.ExecRequest{
		CaptureOutput: true,
		Argv:          append([]string(nil), request.GetCommand()...), TTY: request.GetTty(),
		Columns: columns, Rows: rows,
		Env: environment, WorkDir: request.GetWorkdir(), NoLoginShell: request.GetNoLoginShell(),
		Stdin: append([]byte(nil), request.GetStdin()...),
	})
	if err != nil {
		return grpcError(err)
	}
	if request.GetRequestId() != "" {
		if err := s.Sandboxes.CompleteExecRequest(ctx, ref, request.GetRequestId()); err != nil {
			return grpcError(err)
		}
	}
	if err := sendExecOutput(stream, result.Stdout, true); err != nil {
		return err
	}
	if err := sendExecOutput(stream, result.Stderr, false); err != nil {
		return err
	}
	return stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Exit{Exit: &gatewayv1.ExecSandboxExit{ExitCode: int32(result.ExitCode)}}})
}

// ExecSandboxInteractive relays stdin, terminal resizes, and PTY output for a
// command. A supplied request_id is durably fenced before the guest session
// opens; completed terminal executions retain the fence for 24 hours.
func (s *Server) ExecSandboxInteractive(stream gatewayv1.OpenShell_ExecSandboxInteractiveServer) error {
	if s.Sandboxes == nil {
		return status.Error(codes.Unavailable, "sandbox service is not configured")
	}
	first, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return status.Error(codes.InvalidArgument, "interactive exec requires a start message")
		}
		return err
	}
	request := first.GetStart()
	if request == nil || strings.TrimSpace(request.GetSandbox()) == "" || len(request.GetCommand()) == 0 {
		return status.Error(codes.InvalidArgument, "interactive exec requires a valid start message")
	}
	if strings.TrimSpace(request.GetCommand()[0]) == "" || strings.ContainsRune(request.GetWorkdir(), '\x00') {
		return status.Error(codes.InvalidArgument, "command and workdir must be valid")
	}
	for _, argument := range request.GetCommand() {
		if strings.ContainsRune(argument, '\x00') {
			return status.Error(codes.InvalidArgument, "command contains an invalid argument")
		}
	}
	columns, rows := request.GetCols(), request.GetRows()
	if request.GetTty() {
		if columns == 0 {
			columns = defaultExecColumns
		}
		if rows == 0 {
			rows = defaultExecRows
		}
	}
	if request.GetTty() && (columns > 65535 || rows > 65535) {
		return status.Error(codes.InvalidArgument, "terminal dimensions must not exceed 65535")
	}
	if !request.GetTty() && (columns != 0 || rows != 0) {
		return status.Error(codes.InvalidArgument, "terminal dimensions require tty=true")
	}
	ctx := stream.Context()
	if timeout := request.GetExecutionTimeout(); timeout != nil {
		if err := timeout.CheckValid(); err != nil || timeout.AsDuration() <= 0 {
			return status.Error(codes.InvalidArgument, "execution_timeout must be a positive duration")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout.AsDuration())
		defer cancel()
	}
	environment, err := execEnvironment(request.GetEnvironment())
	if err != nil {
		return err
	}
	ref := sandboxRef(request.GetWorkspaceScope(), request.GetSandbox())
	var attachSessionID string
	var attachCursor uint64
	if err := s.admitExecRequest(ctx, ref, request.GetRequestId(), request); err != nil {
		if request.GetRequestId() == "" || status.Code(err) != codes.Aborted {
			return err
		}
		requestHash, hashErr := execRequestHash(request)
		if hashErr != nil {
			return status.Error(codes.Internal, "encode exec request admission")
		}
		sessionID, cursor, found, lookupErr := s.Sandboxes.ExecSessionCheckpoint(ctx, ref, request.GetRequestId(), requestHash)
		if lookupErr != nil {
			return grpcError(lookupErr)
		}
		if !found {
			return err
		}
		attachSessionID = sessionID
		attachCursor = cursor
	}
	if !request.GetTty() {
		return s.execSandboxInteractiveStream(ctx, ref, request, environment, attachSessionID, attachCursor, stream)
	}
	var session driver.ExecTerminalSession
	if attachSessionID != "" {
		session, err = s.Sandboxes.AttachExecTerminalFromCursor(ctx, ref, attachSessionID, attachCursor)
	} else {
		session, err = s.Sandboxes.OpenExecTerminal(ctx, ref, driver.ExecTerminalRequest{
			Argv: append([]string(nil), request.GetCommand()...), Env: environment,
			WorkDir: request.GetWorkdir(), NoLoginShell: request.GetNoLoginShell(), Columns: columns, Rows: rows,
		})
		if err == nil && request.GetRequestId() != "" {
			if identified, ok := session.(driver.ExecTerminalSessionID); ok && identified.SessionID() != "" {
				requestHash, hashErr := execRequestHash(request)
				if hashErr != nil {
					_ = session.Close()
					return status.Error(codes.Internal, "encode exec request admission")
				}
				if saveErr := s.Sandboxes.SetExecSessionID(ctx, ref, request.GetRequestId(), requestHash, identified.SessionID()); saveErr != nil {
					_ = session.Close()
					return grpcError(saveErr)
				}
			}
		}
	}
	if err != nil {
		return grpcError(err)
	}
	defer session.Close()
	if len(request.GetStdin()) > 0 {
		if _, err := session.Write(request.GetStdin()); err != nil {
			return grpcError(err)
		}
	}
	inputErrors := make(chan error, 1)
	go func() {
		for {
			input, err := stream.Recv()
			if err == io.EOF {
				retained := false
				if identified, ok := session.(driver.ExecTerminalSessionID); ok {
					retained = identified.SessionID() != ""
				}
				if closer, ok := session.(driver.ExecTerminalInputCloser); ok && !retained {
					err = closer.CloseStdin()
				}
				inputErrors <- err
				return
			}
			if err != nil {
				inputErrors <- err
				_ = session.Close()
				return
			}
			switch payload := input.GetPayload().(type) {
			case *gatewayv1.ExecSandboxInput_Stdin:
				if _, err := session.Write(payload.Stdin); err != nil {
					inputErrors <- err
					_ = session.Close()
					return
				}
			case *gatewayv1.ExecSandboxInput_Resize:
				if payload.Resize == nil || payload.Resize.GetCols() == 0 || payload.Resize.GetRows() == 0 || payload.Resize.GetCols() > 65535 || payload.Resize.GetRows() > 65535 {
					inputErrors <- status.Error(codes.InvalidArgument, "terminal resize dimensions must be between 1 and 65535")
					_ = session.Close()
					return
				}
				if err := session.Resize(ctx, payload.Resize.GetCols(), payload.Resize.GetRows()); err != nil {
					inputErrors <- grpcError(err)
					_ = session.Close()
					return
				}
			default:
				inputErrors <- status.Error(codes.InvalidArgument, "interactive exec accepts only stdin and resize after start")
				_ = session.Close()
				return
			}
		}
	}()
	buffer := make([]byte, execOutputChunkBytes)
	for {
		var output []byte
		var cursor uint64
		var readErr error
		if reader, ok := session.(driver.ExecTerminalOutputReader); ok {
			output, cursor, readErr = reader.ReadOutput()
		} else {
			var count int
			count, readErr = session.Read(buffer)
			output = buffer[:count]
		}
		if len(output) > 0 {
			if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stdout{Stdout: &gatewayv1.ExecSandboxStdout{Data: append([]byte(nil), output...)}}}); err != nil {
				return err
			}
			if cursor > 0 && request.GetRequestId() != "" {
				requestHash, hashErr := execRequestHash(request)
				if hashErr != nil {
					return status.Error(codes.Internal, "encode exec request admission")
				}
				if err := s.Sandboxes.SetExecSessionCursor(ctx, ref, request.GetRequestId(), requestHash, cursor); err != nil {
					return grpcError(err)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			select {
			case inputErr := <-inputErrors:
				if inputErr != nil && inputErr != io.EOF {
					return inputErr
				}
			default:
			}
			return grpcError(readErr)
		}
	}
	exitCode, err := session.Wait(ctx)
	if err != nil {
		return grpcError(err)
	}
	if request.GetRequestId() != "" {
		if err := s.Sandboxes.CompleteExecRequest(ctx, ref, request.GetRequestId()); err != nil {
			return grpcError(err)
		}
	}
	return stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Exit{Exit: &gatewayv1.ExecSandboxExit{ExitCode: int32(exitCode)}}})
}

type mainProcessTTYStream interface {
	Context() context.Context
	Send(*gatewayv1.ExecSandboxEvent) error
	Recv() (*gatewayv1.ExecSandboxInput, error)
}

func (s *Server) attachMainProcessTTY(ctx context.Context, ref domain.SandboxRef, columns, rows uint32, readerID, readerHash string, cursor uint64, stream mainProcessTTYStream) error {
	var terminal io.ReadWriteCloser
	var err error
	if readerID != "" {
		terminal, err = s.Sandboxes.OpenMainProcessTTYFromCursor(ctx, ref, columns, rows, cursor)
	} else {
		terminal, err = s.Sandboxes.OpenMainProcessTTY(ctx, ref, columns, rows)
	}
	if err != nil {
		return grpcError(err)
	}
	defer terminal.Close()
	inputErrors := make(chan error, 1)
	go func() {
		failInput := func(inputErr error) {
			inputErrors <- inputErr
			_ = terminal.Close()
		}
		for {
			input, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr != io.EOF {
					failInput(recvErr)
					return
				}
				inputErrors <- recvErr
				return
			}
			switch payload := input.GetPayload().(type) {
			case *gatewayv1.ExecSandboxInput_Stdin:
				if _, writeErr := terminal.Write(payload.Stdin); writeErr != nil {
					failInput(writeErr)
					return
				}
			case *gatewayv1.ExecSandboxInput_Resize:
				if payload.Resize == nil || payload.Resize.GetCols() == 0 || payload.Resize.GetRows() == 0 || payload.Resize.GetCols() > 65535 || payload.Resize.GetRows() > 65535 {
					failInput(status.Error(codes.InvalidArgument, "terminal resize dimensions must be between 1 and 65535"))
					return
				}
				if resizeErr := s.Sandboxes.ResizeMainProcessTTY(ctx, ref, payload.Resize.GetCols(), payload.Resize.GetRows()); resizeErr != nil {
					failInput(grpcError(resizeErr))
					return
				}
			default:
				failInput(status.Error(codes.InvalidArgument, "main-process attachment accepts only stdin and resize after start"))
				return
			}
		}
	}()
	buffer := make([]byte, execOutputChunkBytes)
	for {
		var output []byte
		var outputCursor uint64
		var readErr error
		if reader, ok := terminal.(driver.ExecTerminalOutputReader); ok {
			output, outputCursor, readErr = reader.ReadOutput()
		} else {
			var count int
			count, readErr = terminal.Read(buffer)
			output = buffer[:count]
		}
		if len(output) > 0 {
			if sendErr := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stdout{Stdout: &gatewayv1.ExecSandboxStdout{Data: append([]byte(nil), output...)}}}); sendErr != nil {
				return sendErr
			}
			if outputCursor > 0 && readerID != "" {
				if err := s.Sandboxes.SetOutputReaderCursor(ctx, ref, readerID, readerHash, outputCursor); err != nil {
					return grpcError(err)
				}
			}
		}
		if readErr == io.EOF {
			select {
			case inputErr := <-inputErrors:
				if inputErr != nil && inputErr != io.EOF {
					return grpcError(inputErr)
				}
			default:
			}
			code, waitErr := s.Sandboxes.WaitMainProcess(ctx, ref)
			if waitErr != nil {
				return grpcError(waitErr)
			}
			return stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Exit{Exit: &gatewayv1.ExecSandboxExit{ExitCode: int32(code)}}})
		}
		if readErr != nil {
			select {
			case inputErr := <-inputErrors:
				if inputErr != nil && inputErr != io.EOF {
					return grpcError(inputErr)
				}
			default:
			}
			return grpcError(readErr)
		}
	}
}

func (s *Server) attachMainProcessStream(ctx context.Context, ref domain.SandboxRef, readerID, readerHash string, cursor uint64, stream mainProcessTTYStream) error {
	var session driver.ExecStreamSession
	var err error
	if readerID != "" {
		session, err = s.Sandboxes.OpenMainProcessStreamFromCursor(ctx, ref, cursor)
	} else {
		session, err = s.Sandboxes.OpenMainProcessStream(ctx, ref)
	}
	if err != nil {
		return grpcError(err)
	}
	defer session.Close()
	inputErrors := make(chan error, 1)
	go func() {
		for {
			input, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF {
					inputErrors <- session.CloseStdin()
					return
				}
				inputErrors <- recvErr
				_ = session.Close()
				return
			}
			switch payload := input.GetPayload().(type) {
			case *gatewayv1.ExecSandboxInput_Stdin:
				if _, writeErr := session.Write(payload.Stdin); writeErr != nil {
					inputErrors <- writeErr
					_ = session.Close()
					return
				}
			default:
				inputErrors <- status.Error(codes.InvalidArgument, "non-TTY main-process attachment accepts only stdin")
				_ = session.Close()
				return
			}
		}
	}()
	for {
		output, readErr := session.ReadOutput()
		if readErr != nil {
			select {
			case inputErr := <-inputErrors:
				if inputErr != nil && inputErr != io.EOF {
					return grpcError(inputErr)
				}
			default:
			}
			return grpcError(readErr)
		}
		if len(output.Stdout) != 0 {
			if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stdout{Stdout: &gatewayv1.ExecSandboxStdout{Data: output.Stdout}}}); err != nil {
				return err
			}
		}
		if len(output.Stderr) != 0 {
			if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stderr{Stderr: &gatewayv1.ExecSandboxStderr{Data: output.Stderr}}}); err != nil {
				return err
			}
		}
		if output.Exited {
			return stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Exit{Exit: &gatewayv1.ExecSandboxExit{ExitCode: int32(output.ExitCode)}}})
		}
		if output.Cursor > 0 && readerID != "" {
			if err := s.Sandboxes.SetOutputReaderCursor(ctx, ref, readerID, readerHash, output.Cursor); err != nil {
				return grpcError(err)
			}
		}
	}
}

func (s *Server) execSandboxInteractiveStream(ctx context.Context, ref domain.SandboxRef, request *gatewayv1.ExecSandboxRequest, environment []string, attachSessionID string, attachCursor uint64, stream gatewayv1.OpenShell_ExecSandboxInteractiveServer) error {
	var session driver.ExecStreamSession
	var err error
	if attachSessionID != "" {
		session, err = s.Sandboxes.AttachExecStreamFromCursor(ctx, ref, attachSessionID, attachCursor)
	} else {
		session, err = s.Sandboxes.OpenExecStream(ctx, ref, driver.ExecTerminalRequest{
			Argv: append([]string(nil), request.GetCommand()...), Env: environment,
			WorkDir: request.GetWorkdir(), NoLoginShell: request.GetNoLoginShell(),
		})
		if err == nil && request.GetRequestId() != "" {
			if identified, ok := session.(driver.ExecStreamSessionID); ok && identified.SessionID() != "" {
				requestHash, hashErr := execRequestHash(request)
				if hashErr != nil {
					_ = session.Close()
					return status.Error(codes.Internal, "encode exec request admission")
				}
				if saveErr := s.Sandboxes.SetExecSessionID(ctx, ref, request.GetRequestId(), requestHash, identified.SessionID()); saveErr != nil {
					_ = session.Close()
					return grpcError(saveErr)
				}
			}
		}
	}
	if err != nil {
		return grpcError(err)
	}
	defer session.Close()
	if len(request.GetStdin()) > 0 {
		if _, err := session.Write(request.GetStdin()); err != nil {
			return grpcError(err)
		}
	}
	inputErrors := make(chan error, 1)
	go func() {
		for {
			input, err := stream.Recv()
			if err == io.EOF {
				inputErrors <- session.CloseStdin()
				return
			}
			if err != nil {
				inputErrors <- err
				_ = session.Close()
				return
			}
			switch payload := input.GetPayload().(type) {
			case *gatewayv1.ExecSandboxInput_Stdin:
				if _, err := session.Write(payload.Stdin); err != nil {
					inputErrors <- err
					_ = session.Close()
					return
				}
			case *gatewayv1.ExecSandboxInput_Resize:
				inputErrors <- status.Error(codes.InvalidArgument, "terminal resize requires tty=true")
				_ = session.Close()
				return
			default:
				inputErrors <- status.Error(codes.InvalidArgument, "interactive exec accepts only stdin after start")
				_ = session.Close()
				return
			}
		}
	}()
	for {
		output, err := session.ReadOutput()
		if err != nil {
			select {
			case inputErr := <-inputErrors:
				if inputErr != nil && inputErr != io.EOF {
					return grpcError(inputErr)
				}
			default:
			}
			return grpcError(err)
		}
		if len(output.Stdout) > 0 {
			if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stdout{Stdout: &gatewayv1.ExecSandboxStdout{Data: output.Stdout}}}); err != nil {
				return err
			}
		}
		if len(output.Stderr) > 0 {
			if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stderr{Stderr: &gatewayv1.ExecSandboxStderr{Data: output.Stderr}}}); err != nil {
				return err
			}
		}
		if output.Exited {
			if request.GetRequestId() != "" {
				if err := s.Sandboxes.CompleteExecRequest(ctx, ref, request.GetRequestId()); err != nil {
					return grpcError(err)
				}
			}
			return stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Exit{Exit: &gatewayv1.ExecSandboxExit{ExitCode: int32(output.ExitCode)}}})
		}
		if output.Cursor > 0 && request.GetRequestId() != "" {
			requestHash, hashErr := execRequestHash(request)
			if hashErr != nil {
				return status.Error(codes.Internal, "encode exec request admission")
			}
			if err := s.Sandboxes.SetExecSessionCursor(ctx, ref, request.GetRequestId(), requestHash, output.Cursor); err != nil {
				return grpcError(err)
			}
		}
	}
}

func (s *Server) admitExecRequest(ctx context.Context, ref domain.SandboxRef, requestID string, request proto.Message) error {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil
	}
	if !isNonzeroUUID(requestID) {
		return status.Error(codes.InvalidArgument, "request_id must be a nonzero UUID")
	}
	hash, err := execRequestHash(request)
	if err != nil {
		return status.Error(codes.Internal, "encode exec request admission")
	}
	if err := s.Sandboxes.AdmitExecRequest(ctx, ref, requestID, hash); err != nil {
		return grpcError(err)
	}
	return nil
}

func execRequestHash(request proto.Message) (string, error) {
	clone := proto.Clone(request)
	switch value := clone.(type) {
	case *gatewayv1.ExecSandboxRequest:
		value.RequestId = ""
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(clone)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalMainProcessReaderHash(ref domain.SandboxRef) string {
	digest := sha256.Sum256([]byte("canonical-main-process-reader:" + string(ref.Workspace) + ":" + string(ref.Sandbox)))
	return hex.EncodeToString(digest[:])
}

func isNonzeroUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func execEnvironment(values map[string]string) ([]string, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(values[key], '\x00') {
			return nil, status.Error(codes.InvalidArgument, "environment contains an invalid entry")
		}
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func sendExecOutput(stream gatewayv1.OpenShell_ExecSandboxServer, output []byte, stdout bool) error {
	for len(output) > 0 {
		chunk := output
		if len(chunk) > execOutputChunkBytes {
			chunk = chunk[:execOutputChunkBytes]
		}
		if !stdout {
			if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stderr{Stderr: &gatewayv1.ExecSandboxStderr{Data: append([]byte(nil), chunk...)}}}); err != nil {
				return err
			}
		} else if err := stream.Send(&gatewayv1.ExecSandboxEvent{Payload: &gatewayv1.ExecSandboxEvent_Stdout{Stdout: &gatewayv1.ExecSandboxStdout{Data: append([]byte(nil), chunk...)}}}); err != nil {
			return err
		}
		output = output[len(chunk):]
	}
	return nil
}
