package applicationgrpc

import (
	"net"
	"reflect"
	"testing"
)

func TestGatewayReplicasFromSRVUsesPodIDsAndStableEndpoints(t *testing.T) {
	replicas, err := gatewayReplicasFromSRV([]*net.SRV{
		{Target: "gateway-1.gateway-headless.ns.svc.cluster.local.", Port: 7444},
		{Target: "gateway-0.gateway-headless.ns.svc.cluster.local.", Port: 7444},
	}, "https", "gateway-0")
	if err != nil {
		t.Fatal(err)
	}
	want := []GatewayReplica{
		{ID: "gateway-1", Endpoint: "https://gateway-1.gateway-headless.ns.svc.cluster.local:7444"},
		{ID: "gateway-0"},
	}
	if !reflect.DeepEqual(replicas, want) {
		t.Fatalf("replicas = %#v, want %#v", replicas, want)
	}
}

func TestGatewayReplicasFromSRVRejectsEmptyOrInvalidRecords(t *testing.T) {
	if _, err := gatewayReplicasFromSRV(nil, "http", "gateway-0"); err == nil {
		t.Fatal("empty DNS membership unexpectedly accepted")
	}
	if _, err := gatewayReplicasFromSRV([]*net.SRV{{Target: ".", Port: 7444}}, "http", "gateway-0"); err == nil {
		t.Fatal("empty target unexpectedly accepted")
	}
}
