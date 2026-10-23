package applicationgrpc

import (
	"context"
	"testing"

	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
)

func TestHealthAndInfo(t *testing.T) {
	server := New("test", nil, nil, nil, nil, nil, nil, nil)
	health, err := server.Health(context.Background(), &gatewayv1.HealthRequest{})
	if err != nil || health.GetVersion() != "test" || health.GetStatus() != gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY {
		t.Fatalf("Health = %+v err=%v", health, err)
	}
	info, err := server.GetGatewayInfo(context.Background(), &gatewayv1.GetGatewayInfoRequest{})
	if err != nil || info.GetGatewayVersion() != "test" {
		t.Fatalf("GetGatewayInfo = %+v err=%v", info, err)
	}
}
