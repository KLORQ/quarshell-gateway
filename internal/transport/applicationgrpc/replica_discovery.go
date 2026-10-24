package applicationgrpc

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// DiscoverGatewayReplicas resolves a DNS SRV record into a deterministic membership view.
// IDs use the first label of each target, which matches Kubernetes StatefulSet pod names.
func DiscoverGatewayReplicas(ctx context.Context, srvName, scheme, localID string) ([]GatewayReplica, error) {
	srvName = strings.TrimSpace(srvName)
	if srvName == "" {
		return nil, fmt.Errorf("replica discovery SRV name is required")
	}
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("replica discovery scheme must be http or https")
	}
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", srvName)
	if err != nil {
		return nil, fmt.Errorf("resolve Gateway replica SRV %q: %w", srvName, err)
	}
	return gatewayReplicasFromSRV(records, scheme, localID)
}

func gatewayReplicasFromSRV(records []*net.SRV, scheme, localID string) ([]GatewayReplica, error) {
	localID = strings.ToLower(strings.TrimSpace(localID))
	if localID == "" {
		return nil, fmt.Errorf("local Gateway replica ID is required")
	}
	replicas := make([]GatewayReplica, 0, len(records))
	localFound := false
	for _, record := range records {
		host := strings.TrimSuffix(strings.TrimSpace(record.Target), ".")
		if host == "" || record.Port == 0 {
			continue
		}
		id := strings.ToLower(strings.SplitN(host, ".", 2)[0])
		endpoint := scheme + "://" + net.JoinHostPort(host, fmt.Sprint(record.Port))
		if id == localID {
			endpoint = ""
			localFound = true
		}
		replicas = append(replicas, GatewayReplica{ID: id, Endpoint: endpoint})
	}
	if len(replicas) == 0 {
		return nil, fmt.Errorf("replica discovery returned no usable endpoints")
	}
	if !localFound {
		replicas = append(replicas, GatewayReplica{ID: localID})
	}
	return replicas, nil
}
