package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	_ "github.com/KLORQ/quarshell-driver-vm/vm"
	"github.com/KLORQ/quarshell-driver/driver"
	_ "github.com/KLORQ/quarshell-driver/driver/all"
	credentials "github.com/KLORQ/quarshell-gateway/credentialstore"
	"github.com/KLORQ/quarshell-gateway/internal/application/endpoint"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/providercred"
	"github.com/KLORQ/quarshell-gateway/internal/application/quota"
	"github.com/KLORQ/quarshell-gateway/internal/application/reconcile"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxlogs"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandboxruntime"
	"github.com/KLORQ/quarshell-gateway/internal/application/settings"
	"github.com/KLORQ/quarshell-gateway/internal/application/template"
	"github.com/KLORQ/quarshell-gateway/internal/application/token"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
	"github.com/KLORQ/quarshell-gateway/internal/gatewayconfig"
	"github.com/KLORQ/quarshell-gateway/internal/sshrelay"
	applicationgrpc "github.com/KLORQ/quarshell-gateway/internal/transport/applicationgrpc"
	applicationhttp "github.com/KLORQ/quarshell-gateway/internal/transport/applicationhttp"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	runtimev1 "github.com/KLORQ/quarshell-proto/gen/go/quarshell/runtime/v1"
	"google.golang.org/grpc"
	grpcCredentials "google.golang.org/grpc/credentials"
)

var gatewayVersion = "0.0.0-dev"

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func loadClientCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return pool, nil
}

func runtimeWorkspaceKind(name string) driver.WorkspaceKind {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "kubernetes":
		return driver.WorkspaceGatewayManaged
	case "vm":
		return driver.WorkspaceGuestOverlay
	default:
		return driver.WorkspaceHostPath
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:7443", "HTTP listen address")
	tokenValue := flag.String("token", os.Getenv("QUARSHELL_TOKEN"), "bearer token (or QUARSHELL_TOKEN)")
	dataPath := flag.String("data", "", "SQLite path; empty uses in-memory state")
	dataDir := flag.String("data-dir", "", "state directory; uses <dir>/state.db when --data is empty")
	name := flag.String("name", "quarshell", "gateway name")
	gatewayID := flag.String("gateway-id", envOrDefault("QUARSHELL_GATEWAY_ID", "openshell"), "stable OpenShell Gateway identity used in session JWTs")
	grpcListen := flag.String("grpc-listen", "127.0.0.1:7444", "gRPC listen address; empty disables")
	replicaID := flag.String("replica-id", os.Getenv("QUARSHELL_GATEWAY_REPLICA_ID"), "stable ID for this Gateway replica")
	replicaPeers := flag.String("replica-peers", os.Getenv("QUARSHELL_GATEWAY_REPLICA_PEERS"), "comma-separated id=http(s)://host:port replica membership")
	replicaSRV := flag.String("replica-discovery-srv", os.Getenv("QUARSHELL_GATEWAY_REPLICA_DISCOVERY_SRV"), "DNS SRV record for dynamic replica membership")
	replicaRefreshInterval := flag.Duration("replica-discovery-interval", 5*time.Second, "replica membership refresh interval")
	gatewayConfigPath := flag.String("config", "", "OpenShell Gateway TOML config path")
	tlsCert := flag.String("tls-cert", "", "TLS certificate path")
	tlsKey := flag.String("tls-key", "", "TLS private key path")
	tlsClientCA := flag.String("tls-client-ca", "", "CA bundle for required client certificates")
	runtimeName := flag.String("runtime", "docker", "compute backend; empty disables")
	runtimeConfig := flag.String("runtime-config", "{}", "backend config JSON (rootless/mounts/etc.)")
	publicGatewayURL := flag.String("gateway-public-url", os.Getenv("QUARSHELL_GATEWAY_PUBLIC_URL"), "public Gateway URL reachable from runtime guests")
	sessionSigningKey := os.Getenv("QUARSHELL_SESSION_SIGNING_KEY")
	runtimeInit := flag.String("runtime-init-binary", os.Getenv("QUARSHELL_RUNTIME_INIT_BINARY"), "guest quarshell-init binary")
	runtimeSupervisor := flag.String("runtime-supervisor-binary", os.Getenv("QUARSHELL_RUNTIME_SUPERVISOR_BINARY"), "guest quarshell-supervisor binary")
	runtimeSSHD := flag.String("runtime-sshd-binary", os.Getenv("QUARSHELL_RUNTIME_SSHD_BINARY"), "guest quarshell-sshd binary")
	runtimeProxy := flag.String("runtime-proxy-binary", os.Getenv("QUARSHELL_RUNTIME_PROXY_BINARY"), "host quarshell proxy binary for VM guest egress and relay")
	runtimePolicy := flag.String("runtime-policy-path", os.Getenv("QUARSHELL_RUNTIME_POLICY_PATH"), "host policy YAML used by VM proxy and guest supervisor")
	sshHost := flag.String("gateway-ssh-host", "127.0.0.1", "gateway host returned by CreateSshSession")
	sshPort := flag.Int("gateway-ssh-port", 7443, "gateway port returned by CreateSshSession")
	sshScheme := flag.String("gateway-ssh-scheme", "http", "gateway scheme returned by CreateSshSession")
	credentialKey := flag.String("credential-key", os.Getenv("QUARSHELL_CREDENTIAL_KEY"), "provider credential encryption key; defaults to --token")
	oauthEndpoint := flag.String("oauth-exchange-endpoint", os.Getenv("QUARSHELL_OAUTH_EXCHANGE_ENDPOINT"), "RFC 8693 token exchange endpoint")
	oauthAudience := flag.String("oauth-exchange-audience", os.Getenv("QUARSHELL_OAUTH_EXCHANGE_AUDIENCE"), "RFC 8693 token exchange audience")
	oauthClientID := flag.String("oauth-exchange-client-id", os.Getenv("QUARSHELL_OAUTH_CLIENT_ID"), "OAuth client ID")
	oauthClientSecret := flag.String("oauth-exchange-client-secret", os.Getenv("QUARSHELL_OAUTH_CLIENT_SECRET"), "OAuth client secret")
	flag.Parse()
	if *replicaRefreshInterval <= 0 {
		log.Fatal("replica discovery interval must be positive")
	}
	var replicaRing *applicationgrpc.ReplicaRing
	if strings.TrimSpace(*replicaID) != "" || strings.TrimSpace(*replicaPeers) != "" || strings.TrimSpace(*replicaSRV) != "" {
		members := []applicationgrpc.GatewayReplica{{ID: strings.TrimSpace(*replicaID)}}
		for _, entry := range strings.Split(*replicaPeers, ",") {
			if strings.TrimSpace(entry) == "" {
				continue
			}
			id, endpoint, ok := strings.Cut(strings.TrimSpace(entry), "=")
			if !ok {
				log.Fatalf("invalid --replica-peers entry %q; expected id=http(s)://host:port", entry)
			}
			if strings.TrimSpace(id) == strings.TrimSpace(*replicaID) {
				members[0].Endpoint = strings.TrimSpace(endpoint)
			} else {
				members = append(members, applicationgrpc.GatewayReplica{ID: strings.TrimSpace(id), Endpoint: strings.TrimSpace(endpoint)})
			}
		}
		var err error
		replicaRing, err = applicationgrpc.NewReplicaRing(*replicaID, members)
		if err != nil {
			log.Fatalf("gateway replica membership: %v", err)
		}
		if strings.TrimSpace(*replicaSRV) != "" {
			scheme := "http"
			if *tlsCert != "" {
				scheme = "https"
			}
			discovered, err := applicationgrpc.DiscoverGatewayReplicas(context.Background(), *replicaSRV, scheme, *replicaID)
			if err != nil {
				log.Fatalf("initial Gateway replica discovery: %v", err)
			}
			if err := replicaRing.UpdateReplicas(discovered); err != nil {
				log.Fatalf("initial Gateway replica membership: %v", err)
			}
		}
	}
	explicit := map[string]bool{}
	flag.Visit(func(value *flag.Flag) { explicit[value.Name] = true })
	runtimeExplicit := explicit["runtime"]
	configPath, found, err := gatewayconfig.SelectPath(*gatewayConfigPath)
	if err != nil {
		log.Fatalf("gateway config: %v", err)
	}
	var databaseURL string
	if found {
		file, err := gatewayconfig.Load(configPath)
		if err != nil {
			log.Fatalf("gateway config: %v", err)
		}
		gateway := file.OpenShell.Gateway
		if !explicit["name"] && gateway.Name != nil {
			*name = *gateway.Name
		}
		if !explicit["listen"] && gateway.BindAddress != nil {
			*listen = *gateway.BindAddress
		}
		if gateway.TLS != nil {
			if !explicit["tls-cert"] && gateway.TLS.CertPath != nil {
				*tlsCert = *gateway.TLS.CertPath
			}
			if !explicit["tls-key"] && gateway.TLS.KeyPath != nil {
				*tlsKey = *gateway.TLS.KeyPath
			}
			if !explicit["tls-client-ca"] && gateway.TLS.ClientCAPath != nil {
				*tlsClientCA = *gateway.TLS.ClientCAPath
			}
		}
		if gateway.DatabaseURL != nil {
			databaseURL = *gateway.DatabaseURL
		}
	}
	*gatewayConfigPath = configPath
	resolvedRuntime, resolvedRuntimeConfig, err := resolveRuntimeConfig(configPath, *runtimeConfig, *runtimeName, runtimeExplicit)
	if err != nil {
		log.Fatalf("gateway config: %v", err)
	}
	*runtimeName = resolvedRuntime

	if strings.TrimSpace(*tokenValue) == "" {
		log.Fatal("quarshell-gateway: --token or QUARSHELL_TOKEN is required")
	}

	if strings.TrimSpace(*dataPath) == "" && strings.TrimSpace(*dataDir) != "" {
		if err := os.MkdirAll(*dataDir, 0o700); err != nil {
			log.Fatalf("create data dir: %v", err)
		}
		*dataPath = filepath.Join(*dataDir, "state.db")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if replicaRing != nil && strings.TrimSpace(*replicaSRV) != "" {
		go func() {
			ticker := time.NewTicker(*replicaRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					scheme := "http"
					if *tlsCert != "" {
						scheme = "https"
					}
					replicas, err := applicationgrpc.DiscoverGatewayReplicas(ctx, *replicaSRV, scheme, *replicaID)
					if err != nil {
						log.Printf("quarshell-gateway: refresh replica discovery: %v", err)
						continue
					}
					if err := replicaRing.UpdateReplicas(replicas); err != nil {
						log.Printf("quarshell-gateway: update replica ring: %v", err)
					}
				}
			}
		}()
	}

	var store lifecycle.Store
	var closer func() error
	if strings.TrimSpace(databaseURL) != "" && strings.TrimSpace(*dataPath) == "" {
		postgres, err := lifecycle.NewPostgresStore(ctx, databaseURL)
		if err != nil {
			log.Fatalf("open PostgreSQL store: %v", err)
		}
		store = postgres
		closer = postgres.Close
	} else if strings.TrimSpace(*dataPath) == "" {
		store = lifecycle.NewMemoryStore()
		log.Printf("quarshell-gateway: using in-memory lifecycle state")
	} else {
		sqlite, err := lifecycle.NewSQLiteStore(ctx, *dataPath)
		if err != nil {
			log.Fatalf("open store: %v", err)
		}
		store = sqlite
		closer = sqlite.Close
	}
	if closer != nil {
		defer func() { _ = closer() }()
	}

	workspaces, err := workspace.NewService(store)
	if err != nil {
		log.Fatalf("workspace service: %v", err)
	}
	sandboxes, err := sandbox.NewService(store)
	if err != nil {
		log.Fatalf("sandbox service: %v", err)
	}
	supervisorHub := sshrelay.NewHub()
	sandboxes.SupervisorSessions = supervisorHub
	var sandboxRuntime sandboxruntime.Runtime
	var dockerRuntime *sandboxruntime.Docker
	var runtimeBackendID string
	if strings.TrimSpace(*runtimeName) != "" {
		backend, registered, err := driver.OpenRegisteredBackendWithConfig(*runtimeName, resolvedRuntimeConfig)
		if err != nil || !registered {
			log.Printf("sandbox runtime %q unavailable: %v", *runtimeName, err)
		} else if runtime := sandboxruntime.NewForBackend(backend, runtimeWorkspaceKind(*runtimeName)); runtime == nil {
			log.Printf("sandbox runtime adapter: invalid backend")
		} else {
			runtime.GatewayURL = strings.TrimSpace(*publicGatewayURL)
			if strings.EqualFold(strings.TrimSpace(*runtimeName), "vm") {
				runtime.Runtime = driver.RuntimeAssets{
					InitBinary: strings.TrimSpace(*runtimeInit), SupervisorBinary: strings.TrimSpace(*runtimeSupervisor),
					SSHBinary: strings.TrimSpace(*runtimeSSHD), EnableSSH: strings.TrimSpace(*runtimeSSHD) != "",
				}
				if strings.TrimSpace(*runtimeProxy) != "" || strings.TrimSpace(*runtimePolicy) != "" {
					runtime.Proxy = &driver.ProxySpec{Binary: strings.TrimSpace(*runtimeProxy), PolicyPath: strings.TrimSpace(*runtimePolicy), Port: 3128}
				}
			}
			sandboxes.Runtime = runtime
			sandboxRuntime = runtime
			dockerRuntime = runtime
			runtimeBackendID = string(backend.ID())
			log.Printf("sandbox runtime: %s", *runtimeName)
		}
	}
	policies, err := policyapp.NewService(store)
	if err != nil {
		log.Fatalf("policy service: %v", err)
	}
	chunks, err := policyapp.NewChunkService(store, policies)
	if err != nil {
		log.Fatalf("policy chunks: %v", err)
	}
	templates, err := template.NewService(store)
	if err != nil {
		log.Fatalf("template service: %v", err)
	}
	settingsService, err := settings.NewService(store)
	if err != nil {
		log.Fatalf("settings service: %v", err)
	}
	quotas, err := quota.NewService(store)
	if err != nil {
		log.Fatalf("quota service: %v", err)
	}
	providers, err := provider.NewService(store)
	if err != nil {
		log.Fatalf("provider service: %v", err)
	}
	providerDefs, err := provider.NewRegistry(store)
	if err != nil {
		log.Fatalf("provider registry: %v", err)
	}
	services, err := endpoint.NewServiceRegistry(store)
	if err != nil {
		log.Fatalf("service registry: %v", err)
	}
	sandboxLogStore, err := sandboxlogs.New(store)
	if err != nil {
		log.Fatalf("sandbox logs: %v", err)
	}
	forwards, err := endpoint.NewForwardRegistry(store)
	if err != nil {
		log.Fatalf("forward registry: %v", err)
	}
	events := eventlog.NewMemoryLog(10000)
	if strings.TrimSpace(sessionSigningKey) == "" {
		sessionSigningKey = *tokenValue
	}
	tokens, err := token.NewServiceForGateway([]byte(sessionSigningKey), strings.TrimSpace(*gatewayID), time.Hour)
	if err != nil {
		log.Fatalf("token service: %v", err)
	}
	sandboxes.Tokens = tokens

	if err := reconcile.Run(ctx, workspaces, sandboxes, sandboxRuntime); err != nil {
		log.Printf("sandbox reconcile: %v", err)
	}

	api, err := applicationhttp.New(workspaces, sandboxes, *tokenValue)
	if err != nil {
		log.Fatalf("http transport: %v", err)
	}
	api.Policies = policies
	api.PolicyChunks = chunks
	api.Templates = templates
	api.Settings = settingsService
	api.Quotas = quotas
	api.Providers = providers
	api.ProviderDefs = providerDefs
	api.Services = services
	api.Forwards = forwards
	api.Events = events
	api.Tokens = tokens
	if dockerRuntime != nil {
		api.Logs = func(ctx context.Context, ref domain.SandboxRef) (io.ReadCloser, error) {
			current, err := sandboxes.Get(ctx, ref)
			if err != nil {
				return nil, err
			}
			return dockerRuntime.Logs(ctx, sandboxruntime.Sandbox{Workspace: current.Workspace, Sandbox: current.Sandbox, RuntimeID: current.RuntimeID})
		}
		api.PTY = func(ctx context.Context, ref domain.SandboxRef, columns, rows uint32) (io.ReadWriteCloser, error) {
			current, err := sandboxes.Get(ctx, ref)
			if err != nil {
				return nil, err
			}
			return dockerRuntime.PTY(ctx, sandboxruntime.Sandbox{Workspace: current.Workspace, Sandbox: current.Sandbox, RuntimeID: current.RuntimeID}, columns, rows)
		}
	}
	api.GatewayName = *name
	api.Capabilities = []string{"workspaces", "sandboxes", "policies", "templates", "settings", "quotas", "providers", "services", "forwards", "tokens", "events"}

	server := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("quarshell-gateway listening on %s", listener.Addr())
	var grpcServer *grpc.Server
	var grpcApplication *applicationgrpc.Server
	if strings.TrimSpace(*grpcListen) != "" {
		grpcListener, err := net.Listen("tcp", *grpcListen)
		if err != nil {
			log.Fatalf("grpc listen: %v", err)
		}
		options := []grpc.ServerOption{
			grpc.UnaryInterceptor(applicationgrpc.UnaryAuthInterceptorWithSandboxTokens(*tokenValue, "gateway-client", tokens)),
			grpc.StreamInterceptor(applicationgrpc.StreamAuthInterceptorWithSandboxTokens(*tokenValue, "gateway-client", tokens)),
		}
		if *tlsCert != "" && *tlsKey != "" {
			certificate, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
			if err != nil {
				log.Fatalf("grpc TLS: %v", err)
			}
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
			// gRPC sandbox/supervisor credentials are bearer/JWT based. Client
			// certificates are enforced on the operator HTTP API only.
			options = append(options, grpc.Creds(grpcCredentials.NewTLS(tlsConfig)))
		}
		grpcServer = grpc.NewServer(options...)
		grpcApplication = applicationgrpc.New(gatewayVersion, workspaces, sandboxes, chunks, templates, settingsService, providerDefs, services)
		grpcApplication.ReplicaRouting = replicaRing
		grpcApplication.SupervisorHub = supervisorHub
		grpcApplication.SandboxLogs = sandboxLogStore
		grpcApplication.Tokens = tokens
		grpcApplication.ProviderBindings = providers
		grpcApplication.PolicyRevisions = policies
		grpcApplication.GatewayHost = *sshHost
		grpcApplication.GatewayPort = *sshPort
		grpcApplication.GatewayScheme = *sshScheme
		grpcApplication.RuntimeBackendID = runtimeBackendID
		key := *credentialKey
		if key == "" {
			key = *tokenValue
		}
		if credentialStore, err := providercred.NewStore(store, []byte(key)); err != nil {
			log.Fatalf("provider credential store: %v", err)
		} else {
			grpcApplication.Credentials = credentialStore
		}
		if *oauthEndpoint != "" || *oauthAudience != "" {
			exchange, err := credentials.NewOAuthExchange(credentials.OAuthConfig{
				Endpoint: *oauthEndpoint, Audience: *oauthAudience, ClientID: *oauthClientID, ClientSecret: *oauthClientSecret,
			})
			if err != nil {
				log.Fatalf("oauth exchange: %v", err)
			}
			grpcApplication.OAuthExchange = exchange
		}
		if dockerRuntime != nil {
			grpcApplication.RootfsStaging = dockerRuntime.RootfsStaging
		}
		gatewayv1.RegisterOpenShellServer(grpcServer, grpcApplication)
		runtimev1.RegisterMainProcessServiceServer(grpcServer, grpcApplication)
		go func() {
			if err := grpcServer.Serve(grpcListener); err != nil {
				log.Printf("grpc serve: %v", err)
			}
		}()
		log.Printf("quarshell-gateway gRPC listening on %s", grpcListener.Addr())
	}
	go func() {
		<-ctx.Done()
		if grpcApplication != nil {
			grpcApplication.BeginDrain()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if grpcServer != nil {
			grpcServer.GracefulStop()
		}
	}()
	serve := server.Serve
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("both --tls-cert and --tls-key are required")
		}
		if *tlsClientCA != "" {
			pool, err := loadClientCA(*tlsClientCA)
			if err != nil {
				log.Fatalf("http client CA: %v", err)
			}
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
		}
		serve = func(l net.Listener) error { return server.ServeTLS(l, *tlsCert, *tlsKey) }
	}
	if err := serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}
