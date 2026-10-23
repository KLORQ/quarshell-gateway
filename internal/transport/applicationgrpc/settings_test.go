package applicationgrpc

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/settings"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	sandboxv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/sandbox/v1"
)

func TestSettingsRPC(t *testing.T) {
	service, err := settings.NewService(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server := New("test", nil, nil, nil, nil, service, nil, nil)
	ctx := context.Background()
	updated, err := server.UpdateConfig(ctx, &gatewayv1.UpdateConfigRequest{
		Global: true, SettingKey: "log_level",
		SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "debug"}},
	})
	if err != nil || updated.GetSettingsRevision() == 0 {
		t.Fatalf("UpdateConfig = %+v err=%v", updated, err)
	}
	config, err := server.GetGatewayConfig(ctx, &sandboxv1.GetGatewayConfigRequest{})
	if err != nil || config.GetSettings()["log_level"].GetStringValue() != "debug" {
		t.Fatalf("GetGatewayConfig = %+v err=%v", config, err)
	}
	deleted, err := server.UpdateConfig(ctx, &gatewayv1.UpdateConfigRequest{Global: true, SettingKey: "log_level", DeleteSetting: true})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("Delete setting = %+v err=%v", deleted, err)
	}
}
