package agent

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

func dormantTestPeer(pubKey string, reportedAt *time.Time) *wirekubev1alpha1.WireKubePeer {
	peer := &wirekubev1alpha1.WireKubePeer{}
	peer.Name = "peer"
	peer.Spec.PublicKey = pubKey
	if reportedAt != nil {
		t := metav1.NewTime(*reportedAt)
		peer.Status.LastReportedAt = &t
	}
	return peer
}

func TestPeerIsDormant(t *testing.T) {
	const pubKey = "peer-key"
	now := time.Now()
	stale := now.Add(-dormantPeerThreshold - time.Minute)
	fresh := now.Add(-time.Second)

	tests := []struct {
		name       string
		reportedAt *time.Time
		handshake  time.Time
		agentUp    time.Duration
		want       bool
	}{
		{
			name:       "fresh heartbeat is alive",
			reportedAt: &fresh,
			agentUp:    time.Hour,
			want:       false,
		},
		{
			name:       "stale heartbeat with no handshake is dormant",
			reportedAt: &stale,
			agentUp:    time.Hour,
			want:       true,
		},
		{
			// The case that matters for a NAT-bound peer carried by relay:
			// its heartbeat may lag, but traffic proves it is there.
			name:       "recent handshake vetoes a stale heartbeat",
			reportedAt: &stale,
			handshake:  now.Add(-time.Second),
			agentUp:    time.Hour,
			want:       false,
		},
		{
			// Rolling upgrade: the peer still runs an agent that never writes
			// LastReportedAt. Declaring it dormant would cut off a live
			// relay-dependent peer, so a young agent must not judge yet.
			name:    "missing heartbeat is inconclusive while this agent is young",
			agentUp: time.Minute,
			want:    false,
		},
		{
			name:    "missing heartbeat is dormant once this agent has been up long enough",
			agentUp: time.Hour,
			want:    true,
		},
		{
			name:      "stale handshake does not rescue a missing heartbeat",
			handshake: now.Add(-dormantPeerThreshold - time.Minute),
			agentUp:   time.Hour,
			want:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{startedAt: now.Add(-tc.agentUp)}
			stats := map[string]wireguard.PeerStats{
				pubKey: {PublicKeyB64: pubKey, LastHandshake: tc.handshake},
			}
			if got := a.peerIsDormant(dormantTestPeer(pubKey, tc.reportedAt), stats, now); got != tc.want {
				t.Fatalf("peerIsDormant = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestPeerIsDormantWithoutStatsEntry(t *testing.T) {
	now := time.Now()
	stale := now.Add(-dormantPeerThreshold - time.Minute)
	a := &Agent{startedAt: now.Add(-time.Hour)}

	if !a.peerIsDormant(dormantTestPeer("missing-key", &stale), map[string]wireguard.PeerStats{}, now) {
		t.Fatal("peerIsDormant = false; want true when the peer has no WireGuard stats at all")
	}
}

func TestNoteDormantTransitionTracksEdges(t *testing.T) {
	a := &Agent{dormantPeers: map[string]bool{}}

	a.noteDormantTransition("peer", false)
	if a.dormantPeers["peer"] {
		t.Fatal("peer marked dormant after a live observation")
	}

	a.noteDormantTransition("peer", true)
	if !a.dormantPeers["peer"] {
		t.Fatal("peer not marked dormant after a dormant observation")
	}

	a.noteDormantTransition("peer", false)
	if _, ok := a.dormantPeers["peer"]; ok {
		t.Fatal("dormant entry survived recovery; it would suppress the next transition log")
	}
}
