package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/providercred"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSandboxRuntimeReportScopeAndGeneration(t *testing.T) {
	service, err := sandboxapp.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []domain.SandboxID{"sandbox-a", "sandbox-b"} {
		ref := domain.SandboxRef{Workspace: "workspace", Sandbox: id}
		if _, _, err := service.Create(context.Background(), sandboxapp.Request{Workspace: ref.Workspace, Sandbox: id, Generation: 1, Image: "image"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := service.Start(context.Background(), ref, 1, "start-"+domain.OperationID(id)); err != nil {
			t.Fatal(err)
		}
	}
	server := New("test", nil, service, nil, nil, nil, nil, nil)
	ctx := context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "sandbox-a", generation: 2, credentialEpoch: 2,
	})
	if _, err := server.sandboxByID(ctx, "sandbox-b"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox lookup status=%s err=%v", status.Code(err), err)
	}
	stale := context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "sandbox-a", generation: 3, credentialEpoch: 2,
	})
	if _, err := server.sandboxByID(stale, "sandbox-a"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale generation status=%s err=%v", status.Code(err), err)
	}
	if _, err := server.sandboxByID(ctx, "sandbox-a"); err != nil {
		t.Fatalf("current runtime principal: %v", err)
	}
}

func TestGetSandboxProviderEnvironmentWithholdsUnboundSecrets(t *testing.T) {
	ctx := context.Background()
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "workspace", Sandbox: "sandbox-a"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start-sandbox-a")
	if err != nil {
		t.Fatal(err)
	}
	providers, err := provider.NewRegistry(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := providers.Create(ctx, provider.CreateRequest{ID: "p", Name: "p", Driver: "api"}); err != nil {
		t.Fatal(err)
	}
	bindings, err := provider.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bindings.Bind(ctx, provider.BindRequest{Sandbox: ref, Provider: "p", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	credentials, err := providercred.NewStore(store, []byte("test encryption key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.Put(ctx, providercred.Secret{Workspace: ref.Workspace, Provider: "p", Key: "ACCESS_TOKEN", Value: "secret-value"}); err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, providers, nil)
	server.ProviderBindings = bindings
	server.Credentials = credentials
	sandboxCtx := context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: ref.Sandbox,
		generation: started.RuntimeGeneration, credentialEpoch: started.CredentialEpoch,
	})
	response, err := server.GetSandboxProviderEnvironment(sandboxCtx, &gatewayv1.GetSandboxProviderEnvironmentRequest{
		SandboxId: string(ref.Sandbox), SupportsStaticCredentialBindings: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := response.GetEnvironment()["ACCESS_TOKEN"]; leaked || response.GetReadinessReason() != gatewayv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_CREDENTIALS_WITHHELD {
		t.Fatalf("unbound provider credential was not withheld: %+v", response)
	}
}
