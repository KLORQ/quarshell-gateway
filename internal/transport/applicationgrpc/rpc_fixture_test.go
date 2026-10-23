package applicationgrpc

import (
	"context"
	"testing"

	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// These fixtures pin the status of each public RPC when application services
// are absent. Implemented methods must report Unavailable; unimplemented
// methods must remain fail-closed. Functional success fixtures live beside the
// individual handlers.
var openShellUnaryRPCFixtures = map[string]codes.Code{
	"Health":                        codes.OK,
	"GetCurrentUser":                codes.Unauthenticated,
	"GetGatewayInfo":                codes.OK,
	"CreateSandbox":                 codes.Unavailable,
	"BeginRootfsTarStaging":         codes.Unavailable,
	"GetSandbox":                    codes.Unavailable,
	"ListSandboxes":                 codes.Unavailable,
	"CreateSandboxTemplate":         codes.Unavailable,
	"GetSandboxTemplate":            codes.Unavailable,
	"ListSandboxTemplates":          codes.Unavailable,
	"DeleteSandboxTemplate":         codes.Unavailable,
	"ListSandboxProviders":          codes.Unavailable,
	"AttachSandboxProvider":         codes.Unavailable,
	"DetachSandboxProvider":         codes.Unavailable,
	"GetSandboxProviderStatus":      codes.Unavailable,
	"DeleteSandbox":                 codes.Unavailable,
	"StopSandbox":                   codes.Unavailable,
	"StartSandbox":                  codes.Unavailable,
	"CreateSshSession":              codes.Unavailable,
	"ExposeService":                 codes.Unavailable,
	"GetService":                    codes.Unavailable,
	"ListServices":                  codes.Unavailable,
	"DeleteService":                 codes.Unavailable,
	"RevokeSshSession":              codes.NotFound,
	"CreateProvider":                codes.Unavailable,
	"GetProvider":                   codes.Unavailable,
	"GetProviderCredentials":        codes.InvalidArgument,
	"ListProviders":                 codes.Unavailable,
	"ListProviderProfiles":          codes.Unavailable,
	"GetProviderProfile":            codes.Unavailable,
	"ImportProviderProfiles":        codes.Unavailable,
	"UpdateProviderProfiles":        codes.Unavailable,
	"LintProviderProfiles":          codes.Unavailable,
	"UpdateProvider":                codes.Unavailable,
	"GetProviderRefreshStatus":      codes.InvalidArgument,
	"ConfigureProviderRefresh":      codes.InvalidArgument,
	"RotateProviderCredential":      codes.InvalidArgument,
	"DeleteProviderRefresh":         codes.NotFound,
	"DeleteProvider":                codes.Unavailable,
	"DeleteProviderProfile":         codes.Unavailable,
	"GetSandboxConfig":              codes.Unavailable,
	"GetGatewayConfig":              codes.Unavailable,
	"UpdateConfig":                  codes.Unavailable,
	"GetSandboxPolicyStatus":        codes.Unavailable,
	"ListSandboxPolicies":           codes.Unavailable,
	"ReportPolicyStatus":            codes.Unauthenticated,
	"ReportEndpointStatus":          codes.Unavailable,
	"ReportProviderReadiness":       codes.Unavailable,
	"ReportSandboxConfiguration":    codes.Unavailable,
	"GetSandboxProviderEnvironment": codes.Unavailable,
	"ExchangeProviderSubjectToken":  codes.Unimplemented,
	"GetSandboxLogs":                codes.InvalidArgument,
	"ReportMainProcessExit":         codes.Unauthenticated,
	"FinalizeMainProcessExit":       codes.Unauthenticated,
	"PeerReportProviderReadiness":   codes.Unimplemented,
	"PeerReportEndpointStatus":      codes.Unimplemented,
	"PeerGetSandboxProviderStatus":  codes.Unimplemented,
	"SubmitPolicyAnalysis":          codes.Unavailable,
	"GetDraftPolicy":                codes.Unavailable,
	"ApproveDraftChunk":             codes.Unavailable,
	"RejectDraftChunk":              codes.Unavailable,
	"ApproveAllDraftChunks":         codes.Unavailable,
	"EditDraftChunk":                codes.Unavailable,
	"UndoDraftChunk":                codes.Unavailable,
	"ClearDraftChunks":              codes.Unavailable,
	"GetDraftHistory":               codes.Unavailable,
	"IssueSandboxToken":             codes.Unimplemented,
	"RefreshSandboxToken":           codes.Unauthenticated,
	"CreateWorkspace":               codes.Unavailable,
	"GetWorkspace":                  codes.Unavailable,
	"ListWorkspaces":                codes.Unavailable,
	"DeleteWorkspace":               codes.Unavailable,
	"AddWorkspaceMember":            codes.Unavailable,
	"RemoveWorkspaceMember":         codes.Unavailable,
	"ListWorkspaceMembers":          codes.Unavailable,
}

var openShellStreamingRPCFixtures = map[string]codes.Code{
	"ExecSandbox":            codes.Unavailable,
	"ForwardTcp":             codes.Unauthenticated,
	"ExecSandboxInteractive": codes.Unavailable,
	"PushSandboxLogs":        codes.Unauthenticated,
	"ConnectSupervisor":      codes.Unauthenticated,
	"RelayStream":            codes.Unauthenticated,
	"PeerRelay":              codes.Unauthenticated,
	"WatchSandbox":           codes.InvalidArgument,
}

type fixtureServerStream struct{ ctx context.Context }

func (s fixtureServerStream) SetHeader(metadata.MD) error  { return nil }
func (s fixtureServerStream) SendHeader(metadata.MD) error { return nil }
func (s fixtureServerStream) SetTrailer(metadata.MD)       {}
func (s fixtureServerStream) Context() context.Context     { return s.ctx }
func (s fixtureServerStream) SendMsg(any) error            { return nil }
func (s fixtureServerStream) RecvMsg(any) error            { return nil }

func TestEveryPublicOpenShellRPCHasFixture(t *testing.T) {
	server := New("fixture", nil, nil, nil, nil, nil, nil, nil)
	seenUnary := make(map[string]bool, len(openShellUnaryRPCFixtures))
	for _, method := range gatewayv1.OpenShell_ServiceDesc.Methods {
		method := method
		t.Run("unary/"+method.MethodName, func(t *testing.T) {
			want, ok := openShellUnaryRPCFixtures[method.MethodName]
			if !ok {
				t.Fatalf("public RPC %q has no fixture", method.MethodName)
			}
			seenUnary[method.MethodName] = true
			response, err := method.Handler(server, context.Background(), func(any) error { return nil }, nil)
			if got := rpcCode(err); got != want {
				t.Fatalf("status = %s, want %s", got, want)
			}
			switch method.MethodName {
			case "Health":
				got := response.(*gatewayv1.HealthResponse)
				if got.GetStatus() != gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY || got.GetVersion() != "fixture" {
					t.Fatalf("Health response = %+v", got)
				}
			case "GetGatewayInfo":
				got := response.(*gatewayv1.GetGatewayInfoResponse)
				if got.GetStatus() != gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY || got.GetGatewayVersion() != "fixture" {
					t.Fatalf("GetGatewayInfo response = %+v", got)
				}
			}
		})
	}
	assertFixtureCoverage(t, "unary", seenUnary, openShellUnaryRPCFixtures)

	seenStreaming := make(map[string]bool, len(openShellStreamingRPCFixtures))
	for _, stream := range gatewayv1.OpenShell_ServiceDesc.Streams {
		stream := stream
		t.Run("stream/"+stream.StreamName, func(t *testing.T) {
			want, ok := openShellStreamingRPCFixtures[stream.StreamName]
			if !ok {
				t.Fatalf("public streaming RPC %q has no fixture", stream.StreamName)
			}
			seenStreaming[stream.StreamName] = true
			err := stream.Handler(server, fixtureServerStream{ctx: context.Background()})
			if got := rpcCode(err); got != want {
				t.Fatalf("status = %s, want %s", got, want)
			}
		})
	}
	assertFixtureCoverage(t, "streaming", seenStreaming, openShellStreamingRPCFixtures)
}

func assertFixtureCoverage(t *testing.T, kind string, seen map[string]bool, fixtures map[string]codes.Code) {
	t.Helper()
	for name := range fixtures {
		if !seen[name] {
			t.Errorf("%s fixture %q is not a public RPC", kind, name)
		}
	}
}

func rpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	return status.Code(err)
}
