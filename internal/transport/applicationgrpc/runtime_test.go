package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRefreshSandboxTokenIsBoundToRunningGeneration(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandbox.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Create(context.Background(), sandbox.Request{Workspace: "ws", Sandbox: "sb", Generation: 7, Image: "img"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxes.Start(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 7, "start-7"); err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenapp.NewService([]byte("0123456789abcdef0123456789abcdef"), 0)
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.Tokens = tokens
	ctx := context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", subject: "guest", workspace: "ws", sandbox: "sb", generation: 8, credentialEpoch: 2,
	})
	response, err := server.RefreshSandboxToken(ctx, &gatewayv1.RefreshSandboxTokenRequest{})
	if err != nil {
		t.Fatalf("RefreshSandboxToken: %v", err)
	}
	claims, err := tokens.Verify(response.GetToken())
	if err != nil || claims.Generation != 8 || claims.CredentialEpoch != 2 || claims.Workspace != "" || claims.Sandbox != "sb" || claims.Audience != "gateway" || response.GetSessionId() != "g0000000000000008" || response.GetExpirationTime() == nil || response.GetCredentialEpoch() != 2 {
		t.Fatalf("refreshed claims=%+v response=%+v err=%v", claims, response, err)
	}
	sandboxClaims, err := tokens.Verify(response.GetSandboxToken())
	if err != nil || sandboxClaims.Generation != 8 || sandboxClaims.CredentialEpoch != 2 || sandboxClaims.Workspace != "" || sandboxClaims.Sandbox != "sb" || sandboxClaims.Audience != "sandbox" || response.GetSandboxExpirationTime() == nil {
		t.Fatalf("refreshed sandbox claims=%+v response=%+v err=%v", sandboxClaims, response, err)
	}
	if _, err := sandboxes.Observe(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, 8, "running"); err != nil {
		t.Fatalf("advance observed generation: %v", err)
	}
	ctx = context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", subject: "guest", workspace: "ws", sandbox: "sb", generation: 8, credentialEpoch: 2,
	})
	if _, err := server.RefreshSandboxToken(ctx, &gatewayv1.RefreshSandboxTokenRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stale credential epoch status=%v err=%v", status.Code(err), err)
	}
	ctx = context.WithValue(context.Background(), principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", subject: "guest", workspace: "ws", sandbox: "sb", generation: 7, credentialEpoch: 2,
	})
	if _, err := server.RefreshSandboxToken(ctx, &gatewayv1.RefreshSandboxTokenRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stale generation status=%v err=%v", status.Code(err), err)
	}
}

func TestRelayOpenMessageRestrictsTCPToLoopback(t *testing.T) {
	if _, err := relayOpenMessage("c", "tcp://10.0.0.2:8080"); err == nil {
		t.Fatal("non-loopback target accepted")
	}
	msg, err := relayOpenMessage("c", "tcp://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	if tcp := msg.GetTcp(); tcp == nil || tcp.GetHost() != "localhost" || tcp.GetPort() != 8080 {
		t.Fatalf("relay target=%+v", msg.GetTarget())
	}
}
