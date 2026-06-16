package agent

import (
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/wirekube/wirekube/pkg/wireguard"
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
		"198.18.18.3/32",
		"198.18.18.4/32",
	}
	routeOwners := map[string]string{
		"198.18.18.1/32": connectedKey,
		"198.18.18.2/32": relayedKey,
		"198.18.18.3/32": unreadyKey,
	}
	allowBeforeHandshake := map[string]bool{
		relayedKey: true,
	}

	got := a.filterRoutesForConnectedPeers(routes, routeOwners, allowBeforeHandshake)
	want := []string{
		"198.18.18.1/32",
		"198.18.18.2/32",
		"198.18.18.4/32",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterRoutesForConnectedPeers() = %v, want %v", got, want)
	}
}
