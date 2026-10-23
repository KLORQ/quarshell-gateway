// Package applicationgrpc exposes the OpenShell gRPC surface over new use cases.
// Methods that are not migrated yet return codes.Unimplemented explicitly.
package applicationgrpc

import (
	"context"
	"sync"
	"time"

	credentials "github.com/KLORQ/quarshell-gateway/credentialstore"
	"github.com/KLORQ/quarshell-gateway/internal/application/endpoint"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/providercred"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	"github.com/KLORQ/quarshell-gateway/internal/application/settings"
	"github.com/KLORQ/quarshell-gateway/internal/application/template"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
	"github.com/KLORQ/quarshell-gateway/internal/sshrelay"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	runtimev1 "github.com/KLORQ/quarshell-proto/gen/go/quarshell/runtime/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is the greenfield OpenShell gRPC server.
type Server struct {
	gatewayv1.UnimplementedOpenShellServer
	runtimev1.UnimplementedMainProcessServiceServer
	Version          string
	Workspaces       *workspace.Service
	Sandboxes        *sandbox.Service
	Policy           *policyapp.ChunkService
	PolicyRevisions  *policyapp.Service
	Templates        *template.Service
	Settings         *settings.Service
	Providers        *provider.Registry
	Services         *endpoint.ServiceRegistry
	ProviderBindings *provider.Service
	SandboxLogs      *sandboxlogs.Service
	Tokens           *tokenapp.Service
	SupervisorHub    *sshrelay.Hub
	sshMu            sync.RWMutex
	sshSessions      map[string]sshSession
	Credentials      *providercred.Store
	OAuthExchange    *credentials.OAuthExchange
	stagingMu        sync.Mutex
	staging          map[string]stagingUpload
	RootfsStaging    func(context.Context) (string, uint64, error)
	RuntimeBackendID string
	GatewayHost      string
	GatewayPort      int
	GatewayScheme    string
	now              func() time.Time
	logMu            sync.RWMutex
	sandboxLogs      map[string][]*gatewayv1.SandboxLogLine
	logWatchers      map[string]map[chan *gatewayv1.SandboxStreamEvent]struct{}
	logCursorMu      sync.Mutex
	logCursorEpoch   string
	logCursorSeq     map[string]uint64
}

// New returns a server with explicit unimplemented gaps.
func New(version string, workspaces *workspace.Service, sandboxes *sandbox.Service, policy *policyapp.ChunkService, templates *template.Service, settings *settings.Service, providers *provider.Registry, services *endpoint.ServiceRegistry) *Server {
	return &Server{Version: version, Workspaces: workspaces, Sandboxes: sandboxes, Policy: policy, Templates: templates, Settings: settings, Providers: providers, Services: services, SupervisorHub: sshrelay.NewHub(), sandboxLogs: make(map[string][]*gatewayv1.SandboxLogLine), logWatchers: make(map[string]map[chan *gatewayv1.SandboxStreamEvent]struct{}), logCursorEpoch: randomSessionID(), logCursorSeq: make(map[string]uint64), sshSessions: make(map[string]sshSession), staging: make(map[string]stagingUpload), now: time.Now, Credentials: defaultCredentialStore()}
}

func defaultCredentialStore() *providercred.Store {
	store, _ := providercred.NewStore(lifecycle.NewMemoryStore(), []byte("quarshell-dev-provider-credentials"))
	return store
}

// Health is served by the new transport.
func (s *Server) Health(context.Context, *gatewayv1.HealthRequest) (*gatewayv1.HealthResponse, error) {
	return &gatewayv1.HealthResponse{Status: gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY, Version: s.Version}, nil
}

// GetCurrentUser returns the authenticated static operator identity.
func (s *Server) GetCurrentUser(ctx context.Context, _ *gatewayv1.GetCurrentUserRequest) (*gatewayv1.GetCurrentUserResponse, error) {
	principal, ok := principalFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	return &gatewayv1.GetCurrentUserResponse{
		Subject:          principal.subject,
		Roles:            append([]string(nil), principal.roles...),
		IdentityProvider: principal.identityProvider,
	}, nil
}

// GetGatewayInfo reports the new gateway identity.
func (s *Server) GetGatewayInfo(context.Context, *gatewayv1.GetGatewayInfoRequest) (*gatewayv1.GetGatewayInfoResponse, error) {
	return &gatewayv1.GetGatewayInfoResponse{Status: gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY, GatewayVersion: s.Version}, nil
}
