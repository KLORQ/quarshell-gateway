package applicationgrpc

import (
	"context"
	"io"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sandboxLogsStream struct {
	grpc.ServerStream
	ctx      context.Context
	requests []*gatewayv1.PushSandboxLogsRequest
	closed   *gatewayv1.PushSandboxLogsResponse
}

func (s *sandboxLogsStream) Context() context.Context { return s.ctx }
func (s *sandboxLogsStream) Recv() (*gatewayv1.PushSandboxLogsRequest, error) {
	if len(s.requests) == 0 {
		return nil, io.EOF
	}
	request := s.requests[0]
	s.requests = s.requests[1:]
	return request, nil
}
func (s *sandboxLogsStream) SendAndClose(response *gatewayv1.PushSandboxLogsResponse) error {
	s.closed = response
	return nil
}

func TestPushAndGetSandboxLogsAreBoundedAndSandboxScoped(t *testing.T) {
	ctx := context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{identityProvider: "sandbox-token", sandbox: "sandbox-a", generation: 1, credentialEpoch: 1})
	server := New("test", nil, nil, nil, nil, nil, nil, nil)
	server.SandboxLogs, _ = sandboxlogs.New(lifecycle.NewMemoryStore())
	stream := &sandboxLogsStream{ctx: ctx, requests: []*gatewayv1.PushSandboxLogsRequest{{
		SandboxId: "sandbox-a",
		Logs:      []*gatewayv1.SandboxLogLine{{SandboxId: "sandbox-a", Level: "INFO", Source: "sandbox", Message: "PROC:LAUNCH", EventTime: timestamppb.Now()}},
	}}}
	if err := server.PushSandboxLogs(stream); err != nil {
		t.Fatalf("PushSandboxLogs: %v", err)
	}
	if stream.closed == nil {
		t.Fatal("PushSandboxLogs did not close successfully")
	}
	response, err := server.GetSandboxLogs(ctx, &gatewayv1.GetSandboxLogsRequest{Sandbox: "sandbox-a", Sources: []string{"sandbox"}, MinLevel: "INFO"})
	if err != nil || response.GetBufferTotal() != 1 || len(response.GetLogs()) != 1 || response.GetLogs()[0].GetMessage() != "PROC:LAUNCH" {
		t.Fatalf("GetSandboxLogs = %+v, err=%v", response, err)
	}
	wrong := &sandboxLogsStream{ctx: ctx, requests: []*gatewayv1.PushSandboxLogsRequest{{SandboxId: "sandbox-b"}}}
	if err := server.PushSandboxLogs(wrong); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox log push status=%s err=%v", status.Code(err), err)
	}
}
