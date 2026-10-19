package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// gatewayProbes runs spec.healthCheck for the gateways this node is a peerRef of,
// for the controller to read from this node's status. Standbys probe too, so a
// gateway never fails over to a node that cannot reach the target.
type gatewayProbes struct {
	mu     sync.Mutex
	states map[string]*gatewayProbeState
	// probe is replaceable in tests.
	probe func(ctx context.Context, target string) error
}

type gatewayProbeState struct {
	// config identifies what this state is counting failures of. A change
	// of target or threshold, or a gateway deleted and recreated under the
	// same name, starts a fresh state rather than inheriting the old count.
	config  string
	running bool
	lastRun time.Time
	result  wirekubev1alpha1.GatewayProbeStatus
}

// schedule starts the probes that are due, without waiting for them, and
// forgets gateways this node no longer probes for. Probes therefore run at
// most once per call, which is once per agent sync.
func (g *gatewayProbes) schedule(gateways []wirekubev1alpha1.WireKubeGateway, node string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.states == nil {
		g.states = map[string]*gatewayProbeState{}
	}
	if g.probe == nil {
		g.probe = probeTarget
	}
	wanted := map[string]bool{}
	for i := range gateways {
		gw := &gateways[i]
		hc := gw.Spec.HealthCheck
		if hc == nil || !hc.Enabled || hc.Target == "" || !slices.Contains(gw.Spec.PeerRefs, node) {
			continue
		}
		wanted[gw.Name] = true
		config := fmt.Sprintf("%s|%s|%d", gw.UID, hc.Target, hc.FailureThreshold)
		st, ok := g.states[gw.Name]
		if !ok || st.config != config {
			st = &gatewayProbeState{config: config, result: wirekubev1alpha1.GatewayProbeStatus{Gateway: gw.Name, Healthy: true}}
			g.states[gw.Name] = st
		}
		interval := time.Duration(hc.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 30 * time.Second
		}
		if st.running || (!st.lastRun.IsZero() && now.Sub(st.lastRun) < interval) {
			continue
		}
		timeout := time.Duration(hc.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		threshold := hc.FailureThreshold
		if threshold <= 0 {
			threshold = 3
		}
		st.running, st.lastRun = true, now
		go g.run(gw.Name, st, hc.Target, timeout, threshold)
	}
	for name := range g.states {
		if !wanted[name] {
			delete(g.states, name)
		}
	}
}

// run probes once and records the result in st, unless st has been replaced
// or dropped meanwhile: then the result describes a configuration nobody
// asks about any more.
func (g *gatewayProbes) run(gateway string, st *gatewayProbeState, target string, timeout time.Duration, threshold int32) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	err := g.probe(ctx, target)
	cancel()

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.states[gateway] != st {
		return
	}
	st.running = false
	st.result.CheckedAt = metav1.NewTime(time.Now())
	if err == nil {
		st.result.ConsecutiveFailures = 0
		st.result.Healthy = true
		st.result.Message = ""
		return
	}
	st.result.ConsecutiveFailures++
	st.result.Message = err.Error()
	if st.result.ConsecutiveFailures >= threshold {
		st.result.Healthy = false
	}
}

// results returns the finished probes, ordered by gateway.
func (g *gatewayProbes) results() []wirekubev1alpha1.GatewayProbeStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []wirekubev1alpha1.GatewayProbeStatus
	for _, st := range g.states {
		if !st.result.CheckedAt.IsZero() {
			out = append(out, st.result)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Gateway < out[j].Gateway })
	return out
}

// probeTarget connects over TCP when target carries a port, and sends an
// ICMP echo otherwise.
func probeTarget(ctx context.Context, target string) error {
	if _, _, err := net.SplitHostPort(target); err == nil {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	return pingOnce(ctx, target)
}

func pingOnce(ctx context.Context, host string) error {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	ip := addrs[0]
	network, listen, proto := "ip4:icmp", "0.0.0.0", 1
	var echo, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if ip.To4() == nil {
		network, listen, proto = "ip6:ipv6-icmp", "::", 58
		echo, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	dst := &net.IPAddr{IP: ip}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return fmt.Errorf("open ICMP socket: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	id := os.Getpid() & 0xffff
	msg := icmp.Message{Type: echo, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("wirekube-gateway-probe")}}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		return fmt.Errorf("send ICMP echo to %s: %w", dst, err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("no ICMP echo reply from %s: %w", dst, err)
		}
		fromIP, ok := from.(*net.IPAddr)
		if !ok || !fromIP.IP.Equal(ip) {
			continue
		}
		parsed, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		if body, ok := parsed.Body.(*icmp.Echo); ok && parsed.Type == reply && body.ID == id {
			return nil
		}
	}
}
