package agent

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

var (
	peerLatency = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_latency_seconds",
		Help:      "ICMP round-trip time to a peer in seconds.",
	}, []string{"source", "peer", "transport"})

	peerBytesSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_bytes_sent_total",
		Help:      "Total bytes sent to a WireGuard peer.",
	}, []string{"source", "peer"})

	peerBytesReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_bytes_received_total",
		Help:      "Total bytes received from a WireGuard peer.",
	}, []string{"source", "peer"})

	peerConnected = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_connected",
		Help:      "Whether a peer currently has a usable transport path (1=yes, 0=no).",
	}, []string{"source", "peer", "nat_type"})

	peerTransport = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_transport_mode",
		Help:      "Transport mode gauge (1=direct, 2=relay).",
	}, []string{"source", "peer"})

	peerLastHandshake = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_last_handshake_seconds",
		Help:      "Seconds since the last WireGuard handshake.",
	}, []string{"source", "peer"})

	peerDirectRxAge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_direct_rx_age_seconds",
		Help:      "Seconds since the last packet arrived from this peer on the direct UDP socket. The watermark PathMonitor demotes on, exported to make warm flapping diagnosable.",
	}, []string{"source", "peer"})

	// Heartbeat and send-leg series. The leg counters are what make the
	// relay's duplicate load measurable from the agent side: dual/(sum) is
	// the share of packets this node mirrors onto the relay. They are
	// absolute counters in the Bind, so they are exported as _total gauges
	// (Set, not Inc) like peerBytesSent above.
	peerSendPackets = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_send_packets_total",
		Help:      "Packets this node sent to the peer, by which legs carried them (direct_only, dual, relay_only).",
	}, []string{"source", "peer", "leg"})

	peerHeartbeatPongs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_heartbeat_pongs_total",
		Help:      "Heartbeat pongs matched from this peer on the direct leg.",
	}, []string{"source", "peer"})

	peerHeartbeatAuthFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_heartbeat_auth_failures_total",
		Help:      "Heartbeat frames claiming this peer that failed authentication (bad MAC, wrong length).",
	}, []string{"source", "peer"})

	peerHeartbeatReplayDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_heartbeat_replay_drops_total",
		Help:      "Heartbeat frames from this peer dropped as stale, unknown or already-consumed. Non-zero on paths with RTT spikes.",
	}, []string{"source", "peer"})

	peerDirectRTT = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_direct_rtt_seconds",
		Help:      "Round-trip time of the last heartbeat pong on the direct leg.",
	}, []string{"source", "peer"})

	peerDirectPongAge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_direct_pong_age_seconds",
		Help:      "Seconds since the last heartbeat pong from this peer. Paired with peer_last_handshake_seconds this finds a path that answers pings while the session behind it is dead.",
	}, []string{"source", "peer"})

	peerMTUProbeStale = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_mtu_probe_stale",
		Help:      "1 while MTU-sized heartbeat probes go unanswered although small ones are answered, which forces dual-send.",
	}, []string{"source", "peer"})

	peerEndpointType = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_endpoint_type",
		Help:      "Where WireGuard's endpoint for this peer currently points (0=none, 1=direct address, 2=relay loopback proxy).",
	}, []string{"source", "peer"})

	suppressedRoutes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "suppressed_routes",
		Help:      "Routes withheld from the WireKube table by routing policy, by reason (local, excluded).",
	}, []string{"source", "reason"})

	nodeNATType = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "node_nat_type",
		Help:      "NAT type detected for this node (1=cone, 2=symmetric, 3=port-restricted-cone, 4=open, 0=unknown).",
	}, []string{"node"})

	peerCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peers_total",
		Help:      "Total number of WireKubePeer resources.",
	})

	relayedPeersCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "relayed_peers_total",
		Help:      "Number of peers currently using relay transport.",
	})

	directPeersCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "direct_peers_total",
		Help:      "Number of peers currently using direct P2P transport.",
	})

	peerICEStateMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_ice_state",
		Help:      "ICE negotiation state for a peer (0=relay, 1=gathering, 2=checking, 3=connected, 4=birthday, 5=failed).",
	}, []string{"source", "peer"})
)

// dropStaleMetricLabels removes Prometheus label combinations for peer
// names that the agent emitted samples for last cycle but did not see in
// the current peer list. Without this, deleting a WireKubePeer (or a
// whole node) leaves its labels in /metrics until the agent process
// restarts — Grafana would keep charting a long-vanished peer.
//
// DeletePartialMatch hits every label combination whose "peer" label
// matches, so transport / nat_type variants of the same peer are pulled
// in a single call.
func (a *Agent) dropStaleMetricLabels(currentPeers map[string]struct{}) {
	for name := range a.peerMetricLabels {
		if _, alive := currentPeers[name]; alive {
			continue
		}
		// Never drop labels for the local agent. Per-peer metrics are not
		// supposed to be emitted for self, but defending the invariant
		// here keeps the cleanup loop safe if a future change adds one.
		if name == a.nodeName {
			continue
		}
		labels := prometheus.Labels{"peer": name}
		peerLatency.DeletePartialMatch(labels)
		peerBytesSent.DeletePartialMatch(labels)
		peerBytesReceived.DeletePartialMatch(labels)
		peerConnected.DeletePartialMatch(labels)
		peerTransport.DeletePartialMatch(labels)
		peerLastHandshake.DeletePartialMatch(labels)
		peerICEStateMetric.DeletePartialMatch(labels)
		peerDirectRxAge.DeletePartialMatch(labels)
		peerEndpointType.DeletePartialMatch(labels)
		peerSendPackets.DeletePartialMatch(labels)
		peerHeartbeatPongs.DeletePartialMatch(labels)
		peerHeartbeatAuthFailures.DeletePartialMatch(labels)
		peerHeartbeatReplayDrops.DeletePartialMatch(labels)
		peerDirectRTT.DeletePartialMatch(labels)
		peerDirectPongAge.DeletePartialMatch(labels)
		peerMTUProbeStale.DeletePartialMatch(labels)
	}
	a.peerMetricLabels = currentPeers
}

// updateMetrics publishes Prometheus metrics from WireGuard stats and peer CRDs.
// All per-peer metrics include a "source" label set to this node's name, allowing
// Grafana to distinguish which agent is reporting and build proper mesh views.
func (a *Agent) updateMetrics(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList) {
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		return
	}
	statsByKey := make(map[string]struct {
		sent, recv int64
		handshake  time.Time
		endpoint   string
	})
	wgStatsByKey := make(map[string]wireguard.PeerStats, len(stats))
	for _, s := range stats {
		wgStatsByKey[s.PublicKeyB64] = s
		statsByKey[s.PublicKeyB64] = struct {
			sent, recv int64
			handshake  time.Time
			endpoint   string
		}{s.BytesSent, s.BytesReceived, s.LastHandshake, s.ActualEndpoint}
	}

	me := a.nodeName
	relayed := 0
	direct := 0
	currentPeers := make(map[string]struct{}, len(peerList.Items))

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == me {
			natVal := float64(0)
			switch a.detectedNATType {
			case "cone":
				natVal = 1
			case "symmetric":
				natVal = 2
			case "port-restricted-cone":
				natVal = 3
			case "open":
				natVal = 4
			}
			nodeNATType.WithLabelValues(me).Set(natVal)
			continue
		}

		currentPeers[p.Name] = struct{}{}

		s, ok := statsByKey[p.Spec.PublicKey]
		if ok {
			peerBytesSent.WithLabelValues(me, p.Name).Set(float64(s.sent))
			peerBytesReceived.WithLabelValues(me, p.Name).Set(float64(s.recv))

			if !s.handshake.IsZero() {
				peerLastHandshake.WithLabelValues(me, p.Name).Set(time.Since(s.handshake).Seconds())
			}
		}

		// Align the metric with WireKubePeer.status.connections: PathMonitor
		// is the single source of truth for transport mode. Only a confirmed
		// direct path (PathModeDirect) counts as direct here; PathModeWarm,
		// PathUnknown, and PathModeRelay all count as relay. The legacy
		// relayedPeers map stays populated by ICE for its own bookkeeping but
		// can lag behind the datapath, so it is intentionally not used here.
		isRelayed := a.publishedTransportForPeer(p, nil) == "relay"
		connected := float64(0)
		if a.peerTransportUsable(p, wgStatsByKey) {
			connected = 1
		}
		peerConnected.WithLabelValues(me, p.Name, p.Status.NATType).Set(connected)

		// Diagnostics for warm flapping: the direct-socket receive watermark
		// PathMonitor acts on, and where the WG endpoint currently points.
		// Together they answer "why did this pair leave direct" without log
		// archaeology: a rising rx age with endpoint_type=1 is a quiet direct
		// wire; endpoint_type=2 means keepalives are riding the relay leg.
		// A gauge left behind freezes at its last value, and a frozen "12s
		// ago" is worse than no data: the watermark resets to zero when the
		// peer's key or the bind's path entry is recreated, so the series is
		// deleted rather than left stale.
		if rx := a.wgMgr.LastDirectReceive(p.Spec.PublicKey); rx > 0 {
			peerDirectRxAge.WithLabelValues(me, p.Name).Set(time.Since(time.Unix(0, rx)).Seconds())
		} else {
			peerDirectRxAge.DeleteLabelValues(me, p.Name)
		}
		if st, ok := a.wgMgr.PeerPathStats(p.Spec.PublicKey); ok {
			peerSendPackets.WithLabelValues(me, p.Name, "direct_only").Set(float64(st.SentDirectOnly))
			peerSendPackets.WithLabelValues(me, p.Name, "dual").Set(float64(st.SentDual))
			peerSendPackets.WithLabelValues(me, p.Name, "relay_only").Set(float64(st.SentRelayOnly))
			peerHeartbeatPongs.WithLabelValues(me, p.Name).Set(float64(st.PongsRecv))
			peerHeartbeatAuthFailures.WithLabelValues(me, p.Name).Set(float64(st.AuthFail))
			peerHeartbeatReplayDrops.WithLabelValues(me, p.Name).Set(float64(st.ReplayDrop))
			peerMTUProbeStale.WithLabelValues(me, p.Name).Set(boolGauge(st.MTUStale))
			if st.RTTNs > 0 {
				peerDirectRTT.WithLabelValues(me, p.Name).Set(time.Duration(st.RTTNs).Seconds())
			}
			// Same freeze argument as the rx-age gauge above: a stale pong
			// age reads as a healthy path that simply went quiet.
			if st.LastPongNs > 0 {
				peerDirectPongAge.WithLabelValues(me, p.Name).Set(time.Since(time.Unix(0, st.LastPongNs)).Seconds())
			} else {
				peerDirectPongAge.DeleteLabelValues(me, p.Name)
			}
		}
		epType := float64(0)
		if ok && s.endpoint != "" {
			if isLocalhostEndpoint(s.endpoint) {
				epType = 2
			} else {
				epType = 1
			}
		}
		peerEndpointType.WithLabelValues(me, p.Name).Set(epType)

		transport := float64(1)
		if isRelayed {
			transport = 2
			relayed++
		} else {
			direct++
		}
		peerTransport.WithLabelValues(me, p.Name).Set(transport)

		iceVal := float64(0)
		if state, exists := a.iceStates[p.Name]; exists {
			switch state.State {
			case iceStateGathering:
				iceVal = 1
			case iceStateChecking:
				iceVal = 2
			case iceStateConnected:
				iceVal = 3
			case iceStateBirthday:
				iceVal = 4
			case iceStateFailed:
				iceVal = 5
			}
		}
		peerICEStateMetric.WithLabelValues(me, p.Name).Set(iceVal)
	}

	peerCount.Set(float64(len(peerList.Items)))
	relayedPeersCount.Set(float64(relayed))
	directPeersCount.Set(float64(direct))

	a.dropStaleMetricLabels(currentPeers)
}

// measurePeerLatency runs a single ICMP ping to each connected peer and records
// the round-trip time. Skips peers without a reachable AllowedIP. It runs in a
// background goroutine and must not touch shared agent maps: the relayed-peer
// set is passed in as a snapshot taken on the sync goroutine.
func (a *Agent) measurePeerLatency(peerList *wirekubev1alpha1.WireKubePeerList, relayed map[string]bool) {
	myPeerName := a.nodeName

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == myPeerName || len(p.Spec.AllowedIPs) == 0 {
			continue
		}

		target := ""
		for _, cidr := range p.Spec.AllowedIPs {
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ones == 32 {
				target = ip.String()
				break
			}
		}
		if target == "" {
			continue
		}

		transport := "direct"
		if relayed[p.Name] {
			transport = "relay"
		}

		rtt := pingHost(target)
		if rtt >= 0 {
			peerLatency.WithLabelValues(myPeerName, p.Name, transport).Set(rtt)
		}
	}
}

// pingHost sends a single ICMP ping and returns the RTT in seconds, or -1 on failure.
func pingHost(ip string) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", ip).CombinedOutput()
	if err != nil {
		return -1
	}

	// Parse "time=1.23 ms" from ping output.
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, "time=")
		if idx < 0 {
			continue
		}
		rest := line[idx+5:]
		parts := strings.Fields(rest)
		if len(parts) < 1 {
			continue
		}
		val := strings.TrimRight(parts[0], "ms")
		ms, err := strconv.ParseFloat(val, 64)
		if err != nil {
			continue
		}
		unit := ""
		if len(parts) > 1 {
			unit = parts[1]
		}
		switch unit {
		case "ms":
			return ms / 1000.0
		case "s":
			return ms
		default:
			return ms / 1000.0
		}
	}
	return -1
}

// setSuppressedRouteMetrics rewrites the per-reason suppression counts.
func setSuppressedRouteMetrics(node string, current map[string]string) {
	counts := map[string]int{"local": 0, "excluded": 0}
	for _, reason := range current {
		key := reason
		if strings.HasPrefix(key, "local") {
			key = "local"
		}
		counts[key]++
	}
	for reason, n := range counts {
		suppressedRoutes.WithLabelValues(node, reason).Set(float64(n))
	}
}

// boolGauge renders a flag as the 0/1 a Prometheus gauge expects.
func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
