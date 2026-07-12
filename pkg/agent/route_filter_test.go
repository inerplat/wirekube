package agent

import (
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/inerplat/wirekube/pkg/wireguard"
)

func TestFilterRoutesForConnectedPeersKeepsRelayBootstrapRoutes(t *testing.T) {
	connectedKey := "connected-peer-key"
	relayedKey := "relayed-peer-key"
	unreadyKey := "unready-peer-key"

	a := &Agent{
		log: logr.Discard(),
		wgMgr: &fakeWGEngine{
			stats: []wireguard.PeerStats{
				{PublicKeyB64: connectedKey, LastHandshake: time.Now()},
				{PublicKeyB64: relayedKey},
				{PublicKeyB64: unreadyKey},
			},
		},
	}

	routes := []string{
		"198.18.18.1/32",
		"198.18.18.2/32",
		"10.0.0.154/32",
		"198.18.18.3/32",
		"198.18.18.4/32",
	}
	routeOwners := map[string]string{
		"198.18.18.1/32": connectedKey,
		"198.18.18.2/32": relayedKey,
		"10.0.0.154/32":  relayedKey,
		"198.18.18.3/32": unreadyKey,
	}
	allowBeforeHandshake := map[string]bool{
		relayedKey: true,
	}

	got := a.filterRoutesForConnectedPeers(routes, routeOwners, allowBeforeHandshake, "198.18.0.0/16")
	want := []string{
		"198.18.18.1/32",
		"198.18.18.2/32",
		"198.18.18.4/32",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterRoutesForConnectedPeers() = %v, want %v", got, want)
	}
}

func TestFilterRoutesForConnectedPeersDoesNotBootstrapWithoutMeshCIDR(t *testing.T) {
	relayedKey := "relayed-peer-key"

	a := &Agent{
		log: logr.Discard(),
		wgMgr: &fakeWGEngine{
			stats: []wireguard.PeerStats{{PublicKeyB64: relayedKey}},
		},
	}

	routes := []string{"198.18.18.2/32"}
	routeOwners := map[string]string{"198.18.18.2/32": relayedKey}
	allowBeforeHandshake := map[string]bool{relayedKey: true}

	got := a.filterRoutesForConnectedPeers(routes, routeOwners, allowBeforeHandshake, "")
	if len(got) != 0 {
		t.Fatalf("filterRoutesForConnectedPeers() = %v, want no routes", got)
	}
}

func TestFilterRoutesForConnectedPeersBootstrapsExternalMeshHostRoute(t *testing.T) {
	externalKey := "external-peer-key"

	a := &Agent{
		log: logr.Discard(),
		wgMgr: &fakeWGEngine{
			stats: []wireguard.PeerStats{{PublicKeyB64: externalKey}},
		},
	}

	routes := []string{"198.18.18.20/32"}
	routeOwners := map[string]string{"198.18.18.20/32": externalKey}
	allowBeforeHandshake := map[string]bool{externalKey: true}

	got := a.filterRoutesForConnectedPeers(routes, routeOwners, allowBeforeHandshake, "198.18.18.0/24")
	if !reflect.DeepEqual(got, routes) {
		t.Fatalf("filterRoutesForConnectedPeers() = %v, want %v", got, routes)
	}
}

func TestIsMeshHostRoute(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		meshCIDR string
		want     bool
	}{
		{name: "mesh host route", cidr: "198.18.18.2/32", meshCIDR: "198.18.0.0/16", want: true},
		{name: "underlay host route", cidr: "10.0.0.154/32", meshCIDR: "198.18.0.0/16", want: false},
		{name: "mesh aggregate", cidr: "198.18.18.0/24", meshCIDR: "198.18.0.0/16", want: false},
		{name: "invalid mesh", cidr: "198.18.18.2/32", meshCIDR: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMeshHostRoute(tt.cidr, tt.meshCIDR); got != tt.want {
				t.Fatalf("isMeshHostRoute(%q, %q) = %v, want %v", tt.cidr, tt.meshCIDR, got, tt.want)
			}
		})
	}
}
