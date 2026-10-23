package applicationgrpc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stagingUpload struct {
	path      string
	maxBytes  uint64
	workspace domain.WorkspaceID
	expiresAt time.Time
}

// BeginRootfsTarStaging allocates a single-use rootfs archive upload slot.
func (s *Server) BeginRootfsTarStaging(ctx context.Context, request *gatewayv1.BeginRootfsTarStagingRequest) (*gatewayv1.BeginRootfsTarStagingResponse, error) {
	if s.RootfsStaging == nil {
		return nil, status.Error(codes.Unavailable, "rootfs staging is not configured")
	}
	workspace := workspaceID(request.GetWorkspaceScope())
	if workspace == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace is required")
	}
	name := strings.TrimSpace(request.GetFileName())
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return nil, status.Error(codes.InvalidArgument, "file_name must be a base name")
	}
	if request.GetSizeBytes() == 0 {
		return nil, status.Error(codes.InvalidArgument, "size_bytes must be positive")
	}
	directory, maxBytes, err := s.RootfsStaging(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	if request.GetSizeBytes() > maxBytes {
		return nil, status.Error(codes.InvalidArgument, "archive exceeds backend limit")
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, status.Error(codes.Internal, "mint staging token")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	fileDir := filepath.Join(directory, token)
	if err := os.MkdirAll(fileDir, 0o700); err != nil {
		return nil, status.Error(codes.Unavailable, "prepare staging directory")
	}
	path := filepath.Join(fileDir, name)
	expires := s.now().Add(15 * time.Minute)
	s.stagingMu.Lock()
	if s.staging == nil {
		s.staging = make(map[string]stagingUpload)
	}
	s.staging[token] = stagingUpload{path: path, maxBytes: maxBytes, workspace: workspace, expiresAt: expires}
	s.stagingMu.Unlock()
	return &gatewayv1.BeginRootfsTarStagingResponse{
		StagingToken: token, UploadPath: path, MaxBytes: maxBytes, ExpirationTime: timestamppb.New(expires),
	}, nil
}

// consumeStagingToken resolves a staging token into a validated archive path.
func (s *Server) consumeStagingToken(workspace domain.WorkspaceID, token string) (string, error) {
	s.stagingMu.Lock()
	upload, ok := s.staging[token]
	delete(s.staging, token)
	s.stagingMu.Unlock()
	if !ok || upload.workspace != workspace || !s.now().Before(upload.expiresAt) {
		return "", status.Error(codes.FailedPrecondition, "rootfs staging token is invalid or expired")
	}
	info, err := os.Lstat(upload.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return "", status.Error(codes.FailedPrecondition, "rootfs archive is missing or invalid")
	}
	if uint64(info.Size()) > upload.maxBytes {
		return "", status.Error(codes.FailedPrecondition, "rootfs archive exceeds backend limit")
	}
	return upload.path, nil
}
