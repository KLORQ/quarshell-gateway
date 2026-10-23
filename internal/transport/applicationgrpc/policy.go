package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/policy"
	datamodelv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/datamodel/v1"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func domainSandboxID(value string) domain.SandboxID { return domain.SandboxID(value) }

func domainOperationID(value string) domain.OperationID { return domain.OperationID(value) }

func policyScopeFor(selector *datamodelv1.WorkspaceSelector, sandboxName string) policy.Scope {
	return policy.Scope{Workspace: workspaceID(selector), Sandbox: domainSandboxID(sandboxName)}
}

func (s *Server) policyService() error {
	if s.Policy == nil {
		return status.Error(codes.Unavailable, "policy service is not configured")
	}
	return nil
}

// GetDraftPolicy returns draft chunks.
func (s *Server) GetDraftPolicy(ctx context.Context, request *gatewayv1.GetDraftPolicyRequest) (*gatewayv1.GetDraftPolicyResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	draft, err := s.Policy.GetDraft(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()))
	if err != nil {
		return nil, grpcError(err)
	}
	filter := request.GetStatusFilter()
	chunks := make([]*gatewayv1.PolicyChunk, 0, len(draft.Chunks))
	for _, chunk := range draft.Chunks {
		if filter != "" && string(chunk.Status) != filter {
			continue
		}
		chunks = append(chunks, &gatewayv1.PolicyChunk{Id: chunk.ID, Status: string(chunk.Status), Rationale: string(chunk.Source)})
	}
	return &gatewayv1.GetDraftPolicyResponse{Chunks: chunks}, nil
}

// EditDraftChunk upserts a chunk from its JSON rule.
func (s *Server) EditDraftChunk(ctx context.Context, request *gatewayv1.EditDraftChunkRequest) (*gatewayv1.EditDraftChunkResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	source, err := protojson.Marshal(request.GetProposedRule())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid proposed_rule")
	}
	if _, err := s.Policy.Edit(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()), request.GetChunkId(), 0, source, "gateway", domainOperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.EditDraftChunkResponse{}, nil
}

// ApproveDraftChunk approves one chunk.
func (s *Server) ApproveDraftChunk(ctx context.Context, request *gatewayv1.ApproveDraftChunkRequest) (*gatewayv1.ApproveDraftChunkResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	if _, err := s.Policy.Approve(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()), request.GetChunkId(), "gateway"); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ApproveDraftChunkResponse{}, nil
}

// RejectDraftChunk rejects one chunk.
func (s *Server) RejectDraftChunk(ctx context.Context, request *gatewayv1.RejectDraftChunkRequest) (*gatewayv1.RejectDraftChunkResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	if _, err := s.Policy.Reject(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()), request.GetChunkId(), "gateway", request.GetReason()); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.RejectDraftChunkResponse{}, nil
}

// ApproveAllDraftChunks approves every chunk.
func (s *Server) ApproveAllDraftChunks(ctx context.Context, request *gatewayv1.ApproveAllDraftChunksRequest) (*gatewayv1.ApproveAllDraftChunksResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	if _, err := s.Policy.ApproveAll(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()), "gateway"); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ApproveAllDraftChunksResponse{}, nil
}

// UndoDraftChunk restores the previous chunk snapshot.
func (s *Server) UndoDraftChunk(ctx context.Context, request *gatewayv1.UndoDraftChunkRequest) (*gatewayv1.UndoDraftChunkResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	if _, err := s.Policy.Undo(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()), request.GetChunkId()); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.UndoDraftChunkResponse{}, nil
}

// ClearDraftChunks removes all chunks for a scope.
func (s *Server) ClearDraftChunks(ctx context.Context, request *gatewayv1.ClearDraftChunksRequest) (*gatewayv1.ClearDraftChunksResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	if err := s.Policy.Clear(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()), domainOperationID(request.GetRequestId())); err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.ClearDraftChunksResponse{}, nil
}

// GetDraftHistory returns policy revisions.
func (s *Server) GetDraftHistory(ctx context.Context, request *gatewayv1.GetDraftHistoryRequest) (*gatewayv1.GetDraftHistoryResponse, error) {
	if err := s.policyService(); err != nil {
		return nil, err
	}
	revisions, _, err := s.Policy.History(ctx, policyScopeFor(request.GetWorkspaceScope(), request.GetSandbox()))
	if err != nil {
		return nil, grpcError(err)
	}
	entries := make([]*gatewayv1.DraftHistoryEntry, 0, len(revisions))
	for _, revision := range revisions {
		entries = append(entries, &gatewayv1.DraftHistoryEntry{ChunkId: revision.ID, EventType: string(revision.Status), Description: revision.ID})
	}
	return &gatewayv1.GetDraftHistoryResponse{Entries: entries}, nil
}
