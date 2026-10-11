package agent

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

var (
	ipsecTunnelEstablished = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "ipsec_tunnel_established",
		Help:      "1 when the gateway IPsec tunnel terminated on this node has an installed CHILD_SA, else 0.",
	}, []string{"gateway", "tunnel"})

	ipsecTunnelChildSAs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "ipsec_tunnel_child_sas",
		Help:      "Installed CHILD_SAs of the gateway IPsec tunnel terminated on this node.",
	}, []string{"gateway", "tunnel"})

	ipsecTunnelCarrier = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "ipsec_tunnel_carrier",
		Help:      "1 when the remote networks are routed into this tunnel, 0 when it stands by for a redundant tunnel.",
	}, []string{"gateway", "tunnel"})

	ipsecGuardDropped = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Name:      "ipsec_guard_dropped_packets",
		Help:      "Packets the plaintext guard dropped because no IPsec SA covered them (iptables rule counter).",
	}, []string{"local", "remote"})
)

func (a *Agent) recordTunnelMetrics(gateway string, tunnels []wirekubev1alpha1.GatewayIPsecTunnelStatus) {
	for _, t := range tunnels {
		established, carrier := 0.0, 0.0
		if t.Phase == wirekubev1alpha1.IPsecTunnelPhaseEstablished {
			established = 1
		}
		if t.Carrier {
			carrier = 1
		}
		ipsecTunnelEstablished.WithLabelValues(gateway, t.Name).Set(established)
		ipsecTunnelChildSAs.WithLabelValues(gateway, t.Name).Set(float64(t.InstalledChildSAs))
		ipsecTunnelCarrier.WithLabelValues(gateway, t.Name).Set(carrier)
		a.ipsec.reported[[2]string{gateway, t.Name}] = true
	}
}

// dropStaleTunnelMetrics deletes the series of tunnels that left this node.
func (a *Agent) dropStaleTunnelMetrics(current map[string][]*tunnelPlan) {
	keep := map[[2]string]bool{}
	for gw, plans := range current {
		for _, p := range plans {
			keep[[2]string{gw, p.spec.Name}] = true
		}
	}
	for key := range a.ipsec.reported {
		if keep[key] {
			continue
		}
		ipsecTunnelEstablished.DeleteLabelValues(key[0], key[1])
		ipsecTunnelChildSAs.DeleteLabelValues(key[0], key[1])
		ipsecTunnelCarrier.DeleteLabelValues(key[0], key[1])
		delete(a.ipsec.reported, key)
	}
}

func recordGuardMetrics(dp ipsecDataplane, pairs []ipsec.SelectorPair) {
	ipsecGuardDropped.Reset()
	if len(pairs) == 0 {
		return
	}
	drops, err := dp.GuardDrops()
	if err != nil {
		return
	}
	for p, n := range drops {
		ipsecGuardDropped.WithLabelValues(p.Local, p.Remote).Set(float64(n))
	}
}
