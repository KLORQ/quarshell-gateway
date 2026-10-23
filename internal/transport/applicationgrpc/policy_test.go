package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	sandboxv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/sandbox/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPolicyChunkRPC(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	chunks, err := policyapp.NewChunkService(store, nil)
	if err != nil {
		t.Fatalf("NewChunkService: %v", err)
	}
	server := New("test", nil, nil, chunks, nil, nil, nil, nil)
	ctx := context.Background()
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	if _, err := server.EditDraftChunk(ctx, &gatewayv1.EditDraftChunkRequest{
		WorkspaceScope: selector, Sandbox: "sb", ChunkId: "chunk", RequestId: "edit-1",
		ProposedRule: &sandboxv1.NetworkPolicyRule{},
	}); err != nil {
		t.Fatalf("EditDraftChunk: %v", err)
	}
	draft, err := server.GetDraftPolicy(ctx, &gatewayv1.GetDraftPolicyRequest{WorkspaceScope: selector, Sandbox: "sb"})
	if err != nil || len(draft.GetChunks()) != 1 || draft.GetChunks()[0].GetId() != "chunk" {
		t.Fatalf("GetDraftPolicy = %+v err=%v", draft, err)
	}
	if _, err := server.ApproveDraftChunk(ctx, &gatewayv1.ApproveDraftChunkRequest{WorkspaceScope: selector, Sandbox: "sb", ChunkId: "chunk"}); err != nil {
		t.Fatalf("ApproveDraftChunk: %v", err)
	}
	if _, err := server.UndoDraftChunk(ctx, &gatewayv1.UndoDraftChunkRequest{WorkspaceScope: selector, Sandbox: "sb", ChunkId: "chunk"}); err != nil {
		t.Fatalf("UndoDraftChunk: %v", err)
	}
	if _, err := server.RejectDraftChunk(ctx, &gatewayv1.RejectDraftChunkRequest{WorkspaceScope: selector, Sandbox: "sb", ChunkId: "chunk", Reason: "no"}); err != nil {
		t.Fatalf("RejectDraftChunk: %v", err)
	}
	if _, err := server.GetDraftHistory(ctx, &gatewayv1.GetDraftHistoryRequest{WorkspaceScope: selector, Sandbox: "sb"}); err != nil {
		t.Fatalf("GetDraftHistory: %v", err)
	}
	if _, err := server.ClearDraftChunks(ctx, &gatewayv1.ClearDraftChunksRequest{WorkspaceScope: selector, Sandbox: "sb"}); err != nil {
		t.Fatalf("ClearDraftChunks: %v", err)
	}
}

func TestListSandboxPoliciesRPC(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	revisions, err := policyapp.NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server := New("test", nil, nil, nil, nil, nil, nil, nil)
	server.PolicyRevisions = revisions
	ctx := context.Background()
	scope := policyapp.Scope{Workspace: "ws", Sandbox: "sb"}
	first, _, err := revisions.CreateDraft(ctx, policyapp.DraftRequest{
		Scope: scope, Author: "alice", IdempotencyKey: "first",
		Source: []byte("version: 1\nnetwork_policies: {}\n"),
	})
	if err != nil {
		t.Fatalf("CreateDraft first: %v", err)
	}
	if _, err := revisions.Approve(ctx, scope, first.ID, "alice", "approve-first"); err != nil {
		t.Fatalf("Approve first: %v", err)
	}
	if _, err := revisions.Observe(ctx, scope, first.ID, 1); err != nil {
		t.Fatalf("Observe first: %v", err)
	}
	second, _, err := revisions.CreateDraft(ctx, policyapp.DraftRequest{
		Scope: scope, Author: "alice", IdempotencyKey: "second",
		Source: []byte("version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        access: read-only\n"),
	})
	if err != nil {
		t.Fatalf("CreateDraft second: %v", err)
	}
	selector := &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "ws"}}
	page, err := server.ListSandboxPolicies(ctx, &gatewayv1.ListSandboxPoliciesRequest{WorkspaceScope: selector, Sandbox: "sb", PageSize: 1})
	if err != nil || len(page.GetRevisions()) != 1 {
		t.Fatalf("first page = %+v err=%v", page, err)
	}
	got := page.GetRevisions()[0]
	if got.GetVersion() != uint32(second.Number) || got.GetPolicyHash() != second.Hash || got.GetStatus() != gatewayv1.PolicyStatus_POLICY_STATUS_PENDING || got.GetPolicy() != nil || page.GetNextPageToken() == "" {
		t.Fatalf("first revision = %+v", got)
	}
	page, err = server.ListSandboxPolicies(ctx, &gatewayv1.ListSandboxPoliciesRequest{WorkspaceScope: selector, Sandbox: "sb", PageSize: 1, PageToken: page.GetNextPageToken()})
	if err != nil || len(page.GetRevisions()) != 1 {
		t.Fatalf("second page = %+v err=%v", page, err)
	}
	if page.GetRevisions()[0].GetVersion() != uint32(first.Number) || page.GetRevisions()[0].GetStatus() != gatewayv1.PolicyStatus_POLICY_STATUS_LOADED || page.GetNextPageToken() != "" {
		t.Fatalf("second revision = %+v", page.GetRevisions()[0])
	}
	statusResponse, err := server.GetSandboxPolicyStatus(ctx, &gatewayv1.GetSandboxPolicyStatusRequest{WorkspaceScope: selector, Sandbox: "sb"})
	if err != nil || statusResponse.GetRevision().GetVersion() != uint32(second.Number) || statusResponse.GetActiveVersion() != uint32(first.Number) {
		t.Fatalf("GetSandboxPolicyStatus = %+v err=%v", statusResponse, err)
	}
	missing, err := server.GetSandboxPolicyStatus(ctx, &gatewayv1.GetSandboxPolicyStatusRequest{WorkspaceScope: selector, Sandbox: "sb", Version: 99})
	if status.Code(err) != codes.NotFound || missing != nil {
		t.Fatalf("missing policy status = %+v err=%v", missing, err)
	}
	if _, err := server.ListSandboxPolicies(ctx, &gatewayv1.ListSandboxPoliciesRequest{WorkspaceScope: selector, Sandbox: "sb", Global: true}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("global history status = %v", err)
	}
}
