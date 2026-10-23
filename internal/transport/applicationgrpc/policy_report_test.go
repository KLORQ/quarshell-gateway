package applicationgrpc

import (
	"context"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	sandboxapp "github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestReportPolicyStatusRequiresCurrentSandboxAndRecordsLoadResult(t *testing.T) {
	ctx := context.Background()
	store := lifecycle.NewMemoryStore()
	sandboxes, err := sandboxapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	if _, _, err := sandboxes.Create(ctx, sandboxapp.Request{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: 1, Image: "image"}); err != nil {
		t.Fatal(err)
	}
	started, _, err := sandboxes.Start(ctx, ref, 1, "start")
	if err != nil {
		t.Fatal(err)
	}
	policies, err := policyapp.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := policyapp.Scope{Workspace: ref.Workspace, Sandbox: ref.Sandbox}
	draft, _, err := policies.CreateDraft(ctx, policyapp.DraftRequest{Scope: scope, Source: []byte("version: 1\nlandlock:\n  compatibility: best_effort\n"), Author: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Approve(ctx, scope, draft.ID, "operator", "approve"); err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenapp.NewService([]byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.IssueForAudienceEpoch(ref, started.RuntimeGeneration, started.CredentialEpoch, "sandbox", "supervisor", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	incoming := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+raw))
	server := New("test", nil, sandboxes, nil, nil, nil, nil, nil)
	server.PolicyRevisions = policies
	server.Tokens = tokens
	request := &gatewayv1.ReportPolicyStatusRequest{SandboxId: "sb", Version: uint32(draft.Number), Status: gatewayv1.PolicyStatus_POLICY_STATUS_FAILED, LoadError: "proxy setup failed"}
	response, err := UnaryAuthInterceptorWithSandboxTokens("operator", "gateway", tokens)(incoming, request, &grpc.UnaryServerInfo{FullMethod: gatewayv1.OpenShell_ReportPolicyStatus_FullMethodName}, func(ctx context.Context, request any) (any, error) {
		return server.ReportPolicyStatus(ctx, request.(*gatewayv1.ReportPolicyStatusRequest))
	})
	if err != nil || response == nil {
		t.Fatalf("ReportPolicyStatus failed: response=%v err=%v", response, err)
	}
	statusResponse, err := server.GetSandboxPolicyStatus(ctx, &gatewayv1.GetSandboxPolicyStatusRequest{WorkspaceScope: &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}, Sandbox: "sb"})
	if err != nil || statusResponse.GetRevision().GetStatus() != gatewayv1.PolicyStatus_POLICY_STATUS_FAILED {
		t.Fatalf("failed policy report status=%v err=%v", statusResponse.GetRevision().GetStatus(), err)
	}
	if _, err := server.ReportPolicyStatus(context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "other", generation: started.RuntimeGeneration, credentialEpoch: started.CredentialEpoch,
	}), request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox report status=%s err=%v", status.Code(err), err)
	}
	if _, err := server.ReportPolicyStatus(context.WithValue(ctx, principalContextKey{}, authenticatedPrincipal{
		identityProvider: "sandbox-token", sandbox: "sb", generation: started.RuntimeGeneration, credentialEpoch: started.CredentialEpoch + 1,
	}), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stale credential report status=%s err=%v", status.Code(err), err)
	}
}
