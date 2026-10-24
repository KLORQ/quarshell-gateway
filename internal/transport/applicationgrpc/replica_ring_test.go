package applicationgrpc

import "testing"

func TestReplicaRingRedirectAndDrain(t *testing.T) {
	members := []GatewayReplica{{ID: "a", Endpoint: "https://a.example:7444"}, {ID: "b", Endpoint: "https://b.example:7444"}}
	ring, err := NewReplicaRing("a", members)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := ring.Redirect("sandbox-1", false, true)
	if !ok || peer.ID != "b" {
		t.Fatalf("draining redirect = %#v, %v; want replica b", peer, ok)
	}
	if _, ok := ring.Redirect("sandbox-1", true, false); ok {
		t.Fatal("redirected session should not be redirected again")
	}
}

func TestReplicaRingStableAcrossMembershipOrder(t *testing.T) {
	first, err := NewReplicaRing("a", []GatewayReplica{{ID: "a"}, {ID: "b", Endpoint: "http://b.example:7444"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewReplicaRing("a", []GatewayReplica{{ID: "b", Endpoint: "http://b.example:7444"}, {ID: "a"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, sandbox := range []string{"one", "two", "three", "four"} {
		if got, want := first.owner(sandbox, ""), second.owner(sandbox, ""); got != want {
			t.Fatalf("owner(%q) differs: %q != %q", sandbox, got, want)
		}
	}
}

func TestReplicaRingMembershipUpdatesAtomically(t *testing.T) {
	ring, err := NewReplicaRing("a", []GatewayReplica{{ID: "a"}, {ID: "b", Endpoint: "http://b.example:7444"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.UpdateReplicas([]GatewayReplica{{ID: "a"}, {ID: "c", Endpoint: "http://c.example:7444"}}); err != nil {
		t.Fatal(err)
	}
	for _, sandbox := range []string{"one", "two", "three", "four", "five", "six"} {
		if owner := ring.owner(sandbox, ""); owner == "b" {
			t.Fatalf("removed replica remained in ring for %q", sandbox)
		}
	}
	if err := ring.UpdateReplicas([]GatewayReplica{{ID: "a"}, {ID: "c", Endpoint: "invalid"}}); err == nil {
		t.Fatal("invalid update unexpectedly accepted")
	}
	if owner := ring.owner("one", ""); owner == "b" {
		t.Fatalf("failed update replaced the ring: %q", owner)
	}
}
