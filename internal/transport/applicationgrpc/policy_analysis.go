package applicationgrpc

import (
	"context"
	"fmt"

	"github.com/KLORQ/quarshell-gateway/internal/application/policy"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// SubmitPolicyAnalysis stages proposed chunks as draft policy chunks.
func (s *Server) SubmitPolicyAnalysis(ctx context.Context, request *gatewayv1.SubmitPolicyAnalysisRequest) (*gatewayv1.SubmitPolicyAnalysisResponse, error) {
	if s.Policy == nil {
		return nil, status.Error(codes.Unavailable, "policy chunks are not configured")
	}
	scope := policy.Scope{Workspace: workspaceID(request.GetWorkspaceScope()), Sandbox: domainSandboxID(request.GetName())}
	if !scope.Valid() {
		return nil, status.Error(codes.InvalidArgument, "workspace and sandbox are required")
	}
	response := &gatewayv1.SubmitPolicyAnalysisResponse{}
	for index, chunk := range request.GetProposedChunks() {
		source, err := protojson.Marshal(chunk.GetProposedRule())
		if err != nil || len(source) == 0 {
			response.RejectedChunks++
			response.RejectionReasons = append(response.RejectionReasons, fmt.Sprintf("chunk %d: invalid rule", index))
			continue
		}
		id := chunk.GetId()
		if id == "" {
			id = fmt.Sprintf("analysis-%d", index)
		}
		if _, err := s.Policy.Edit(ctx, scope, id, 0, source, "analysis", domainOperationID(fmt.Sprintf("analysis:%s:%d", scope.Key(), index))); err != nil {
			response.RejectedChunks++
			response.RejectionReasons = append(response.RejectionReasons, fmt.Sprintf("chunk %s: %v", id, err))
			continue
		}
		response.AcceptedChunks++
		response.AcceptedChunkIds = append(response.AcceptedChunkIds, id)
	}
	return response, nil
}
