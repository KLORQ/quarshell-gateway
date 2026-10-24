package applicationgrpc

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const replicaVirtualNodes = 128

// GatewayReplica identifies one Gateway replica in the current membership view.
type GatewayReplica struct {
	ID       string
	Endpoint string
}

// ReplicaRing provides deterministic sandbox placement across configured Gateways.
type ReplicaRing struct {
	mu      sync.RWMutex
	localID string
	peers   map[string]string
	points  []replicaPoint
}

// UpdateReplicas atomically replaces the ring membership after discovery changes.
func (ring *ReplicaRing) UpdateReplicas(replicas []GatewayReplica) error {
	if ring == nil {
		return fmt.Errorf("gateway replica ring is nil")
	}
	updated, err := NewReplicaRing(ring.localID, replicas)
	if err != nil {
		return err
	}
	ring.mu.Lock()
	ring.peers, ring.points = updated.peers, updated.points
	ring.mu.Unlock()
	return nil
}

type replicaPoint struct {
	hash uint64
	id   string
}

// NewReplicaRing validates and creates the same virtual-node ring on each replica.
func NewReplicaRing(localID string, replicas []GatewayReplica) (*ReplicaRing, error) {
	localID = strings.ToLower(strings.TrimSpace(localID))
	if localID == "" {
		return nil, fmt.Errorf("gateway replica ID is required")
	}
	ring := &ReplicaRing{localID: localID, peers: make(map[string]string)}
	seen := make(map[string]struct{}, len(replicas))
	for _, replica := range replicas {
		id := strings.ToLower(strings.TrimSpace(replica.ID))
		if id == "" {
			return nil, fmt.Errorf("gateway replica ID is required")
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("duplicate gateway replica ID %q", id)
		}
		seen[id] = struct{}{}
		endpoint := strings.TrimSpace(replica.Endpoint)
		if id != localID {
			if err := validateReplicaEndpoint(endpoint); err != nil {
				return nil, fmt.Errorf("gateway replica %q: %w", id, err)
			}
			ring.peers[id] = endpoint
		} else if endpoint != "" {
			if err := validateReplicaEndpoint(endpoint); err != nil {
				return nil, fmt.Errorf("gateway replica %q: %w", id, err)
			}
		}
		for vnode := 0; vnode < replicaVirtualNodes; vnode++ {
			ring.points = append(ring.points, replicaPoint{hash: replicaHash(fmt.Sprintf("%s#%d", id, vnode)), id: id})
		}
	}
	if _, exists := seen[localID]; !exists {
		return nil, fmt.Errorf("local replica %q is missing from membership", localID)
	}
	sort.Slice(ring.points, func(i, j int) bool {
		if ring.points[i].hash != ring.points[j].hash {
			return ring.points[i].hash < ring.points[j].hash
		}
		return ring.points[i].id < ring.points[j].id
	})
	return ring, nil
}

// Redirect returns the preferred peer for a new session, or a replacement peer
// while this replica drains. Redirected sessions are accepted unless draining.
func (ring *ReplicaRing) Redirect(sandboxID string, redirected, draining bool) (GatewayReplica, bool) {
	if ring == nil || sandboxID == "" {
		return GatewayReplica{}, false
	}
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	if len(ring.points) == 0 {
		return GatewayReplica{}, false
	}
	owner := ring.ownerLocked(sandboxID, "")
	if draining {
		owner = ring.ownerLocked(sandboxID, ring.localID)
	}
	if owner == "" || owner == ring.localID || (!draining && redirected) {
		return GatewayReplica{}, false
	}
	endpoint := ring.peers[owner]
	if endpoint == "" {
		return GatewayReplica{}, false
	}
	return GatewayReplica{ID: owner, Endpoint: endpoint}, true
}

func (ring *ReplicaRing) owner(sandboxID, excluded string) string {
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	return ring.ownerLocked(sandboxID, excluded)
}

func (ring *ReplicaRing) ownerLocked(sandboxID, excluded string) string {
	point := replicaHash(sandboxID)
	index := sort.Search(len(ring.points), func(i int) bool { return ring.points[i].hash >= point })
	for offset := 0; offset < len(ring.points); offset++ {
		candidate := ring.points[(index+offset)%len(ring.points)].id
		if candidate != excluded {
			return candidate
		}
	}
	return ""
}

func replicaHash(value string) uint64 {
	digest := sha256.Sum256([]byte(value))
	return binary.BigEndian.Uint64(digest[:8])
}

func validateReplicaEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("endpoint must be http(s)://host:port")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("endpoint must be http(s)://host:port")
	}
	return nil
}
