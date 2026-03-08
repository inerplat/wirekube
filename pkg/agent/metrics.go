package agent

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

var (
	peerLatency = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_latency_seconds",
		Help:      "ICMP round-trip time to a peer in seconds.",
	}, []string{"peer", "endpoint", "transport"})

	peerBytesSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_bytes_sent_total",
		Help:      "Total bytes sent to a WireGuard peer.",
	}, []string{"peer"})

	peerBytesReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_bytes_received_total",
		Help:      "Total bytes received from a WireGuard peer.",
	}, []string{"peer"})

	peerConnected = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_connected",
		Help:      "Whether a peer has a recent WireGuard handshake (1=yes, 0=no).",
	}, []string{"peer", "nat_type"})

	peerTransport = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_transport_mode",
		Help:      "Transport mode gauge (1=direct, 2=relay, 3=mixed).",
	}, []string{"peer"})

	peerLastHandshake = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "peer_last_handshake_seconds",
		Help:      "Seconds since the last WireGuard handshake.",
	}, []string{"peer"})

	nodeNATType = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "node_nat_type",
		Help:      "NAT type detected for this node (1=cone, 2=symmetric, 0=unknown).",
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
)

// updateMetrics publishes Prometheus metrics from WireGuard stats and peer CRDs.
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
	for _, s := range stats {
		statsByKey[s.PublicKeyB64] = struct {
			sent, recv int64
			handshake  time.Time
			endpoint   string
		}{s.BytesSent, s.BytesReceived, s.LastHandshake, s.ActualEndpoint}
	}

	myPeerName := a.nodeName
	relayed := 0

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == myPeerName {
			natVal := float64(0)
			switch a.detectedNATType {
			case "cone":
				natVal = 1
			case "symmetric":
				natVal = 2
			}
			nodeNATType.WithLabelValues(myPeerName).Set(natVal)
			continue
		}

		s, ok := statsByKey[p.Spec.PublicKey]
		if ok {
			peerBytesSent.WithLabelValues(p.Name).Set(float64(s.sent))
			peerBytesReceived.WithLabelValues(p.Name).Set(float64(s.recv))

			connected := float64(0)
			if !s.handshake.IsZero() && time.Since(s.handshake) < 3*time.Minute {
				connected = 1
			}
			peerConnected.WithLabelValues(p.Name, p.Status.NATType).Set(connected)

			if !s.handshake.IsZero() {
				peerLastHandshake.WithLabelValues(p.Name).Set(time.Since(s.handshake).Seconds())
			}
		}

		transport := float64(1) // direct
		if a.relayedPeers[p.Name] {
			transport = 2 // relay
			relayed++
		}
		peerTransport.WithLabelValues(p.Name).Set(transport)
	}

	peerCount.Set(float64(len(peerList.Items)))
	relayedPeersCount.Set(float64(relayed))
}

// measurePeerLatency runs a single ICMP ping to each connected peer and
// records the round-trip time. Skips peers without a reachable AllowedIP.
func (a *Agent) measurePeerLatency(peerList *wirekubev1alpha1.WireKubePeerList) {
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
		if a.relayedPeers[p.Name] {
			transport = "relay"
		}

		rtt := pingHost(target)
		if rtt >= 0 {
			peerLatency.WithLabelValues(p.Name, p.Spec.Endpoint, transport).Set(rtt)
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

func init() {
	// Ensure metrics are registered (promauto handles this).
	_ = fmt.Sprintf
}
