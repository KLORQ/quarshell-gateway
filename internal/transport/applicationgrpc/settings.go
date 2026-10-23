package applicationgrpc

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	sandboxv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/sandbox/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const globalSettingsWorkspace domain.WorkspaceID = "gateway"

// GetGatewayConfig returns the gateway-global settings map.
func (s *Server) GetGatewayConfig(ctx context.Context, _ *sandboxv1.GetGatewayConfigRequest) (*sandboxv1.GetGatewayConfigResponse, error) {
	if s.Settings == nil {
		return nil, status.Error(codes.Unavailable, "settings service is not configured")
	}
	items, err := s.Settings.List(ctx, globalSettingsWorkspace)
	if err != nil {
		return nil, grpcError(err)
	}
	settings := make(map[string]*sandboxv1.SettingValue, len(items))
	var revision uint64
	for _, item := range items {
		value := &sandboxv1.SettingValue{}
		if err := protojson.Unmarshal(item.Value, value); err != nil {
			return nil, status.Error(codes.Internal, "stored setting is invalid")
		}
		settings[item.Key] = value
		if item.Version > revision {
			revision = item.Version
		}
	}
	return &sandboxv1.GetGatewayConfigResponse{Settings: settings, SettingsRevision: revision}, nil
}

// UpdateConfig applies one global setting mutation.
func (s *Server) UpdateConfig(ctx context.Context, request *gatewayv1.UpdateConfigRequest) (*gatewayv1.UpdateConfigResponse, error) {
	if s.Settings == nil {
		return nil, status.Error(codes.Unavailable, "settings service is not configured")
	}
	if request.GetSettingKey() == "" {
		return nil, status.Error(codes.Unimplemented, "policy config updates are not migrated")
	}
	if request.GetDeleteSetting() {
		if err := s.Settings.Delete(ctx, globalSettingsWorkspace, request.GetSettingKey(), domain.OperationID(request.GetRequestId())); err != nil {
			return nil, grpcError(err)
		}
		return &gatewayv1.UpdateConfigResponse{Deleted: true}, nil
	}
	value, err := protojson.Marshal(request.GetSettingValue())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid setting value")
	}
	setting, _, err := s.Settings.Set(ctx, globalSettingsWorkspace, request.GetSettingKey(), value, 0, domain.OperationID(request.GetRequestId()))
	if err != nil {
		return nil, grpcError(err)
	}
	return &gatewayv1.UpdateConfigResponse{SettingsRevision: setting.Version}, nil
}
