package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func probedGateway(name string, refs ...string) wirekubev1alpha1.WireKubeGateway {
	return wirekubev1alpha1.WireKubeGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: wirekubev1alpha1.WireKubeGatewaySpec{
			PeerRefs:    refs,
			HealthCheck: &wirekubev1alpha1.GatewayHealthCheck{Enabled: true, Target: "10.77.1.1:443", IntervalSeconds: 5, FailureThreshold: 2},
		},
	}
}

// settle waits for the in-flight probes to finish.
func settle(t *testing.T, g *gatewayProbes) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		busy := false
		for _, st := range g.states {
			busy = busy || st.running
		}
		g.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("probes did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestGatewayProbesTrackFailuresAndRecovery(t *testing.T) {
	var failing atomic.Bool
	var calls atomic.Int32
	g := &gatewayProbes{probe: func(context.Context, string) error {
		calls.Add(1)
		if failing.Load() {
			return errors.New("connection refused")
		}
		return nil
	}}
	gws := []wirekubev1alpha1.WireKubeGateway{probedGateway("site", "gw-a", "gw-b"), probedGateway("elsewhere", "gw-c")}
	now := time.Unix(1000, 0)
	run := func() []wirekubev1alpha1.GatewayProbeStatus {
		g.schedule(gws, "gw-b", now)
		settle(t, g)
		now = now.Add(5 * time.Second)
		return g.results()
	}

	if got := run(); len(got) != 1 || got[0].Gateway != "site" || !got[0].Healthy {
		t.Fatalf("results = %+v; want one healthy result for the gateway this node serves", got)
	}
	failing.Store(true)
	if got := run(); !got[0].Healthy || got[0].ConsecutiveFailures != 1 {
		t.Fatalf("one failure under a threshold of 2 marked unhealthy: %+v", got[0])
	}
	if got := run(); got[0].Healthy || got[0].ConsecutiveFailures != 2 || got[0].Message == "" {
		t.Fatalf("threshold reached but still healthy: %+v", got[0])
	}
	failing.Store(false)
	if got := run(); !got[0].Healthy || got[0].ConsecutiveFailures != 0 {
		t.Fatalf("a passing probe did not recover: %+v", got[0])
	}

	// Within the interval nothing new starts.
	before := calls.Load()
	g.schedule(gws, "gw-b", now.Add(-4*time.Second))
	settle(t, g)
	if calls.Load() != before {
		t.Fatal("probed again inside the interval")
	}
}

func TestProbeTargetTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeTarget(ctx, addr); err != nil {
		t.Fatalf("probe of a listening port failed: %v", err)
	}
	ln.Close()
	if err := probeTarget(ctx, addr); err == nil {
		t.Fatal("probe of a closed port passed")
	}
}

func TestProbeTargetICMP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a raw ICMP socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeTarget(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("ping 127.0.0.1: %v", err)
	}
}

// TestGatewayProbeResultsFollowTheConfig covers a target change while a
// probe of the old target is still running: the old probe's result must not
// land in the new target's state, and the new state starts healthy.
func TestGatewayProbeResultsFollowTheConfig(t *testing.T) {
	release := make(chan struct{})
	g := &gatewayProbes{probe: func(_ context.Context, target string) error {
		if target == "10.77.1.1:443" {
			<-release
			return errors.New("old target down")
		}
		return nil
	}}
	gw := probedGateway("site", "gw-a")
	gw.Spec.HealthCheck.FailureThreshold = 1
	now := time.Unix(1000, 0)
	g.schedule([]wirekubev1alpha1.WireKubeGateway{gw}, "gw-a", now)

	gw.Spec.HealthCheck.Target = "10.77.1.2:443"
	g.schedule([]wirekubev1alpha1.WireKubeGateway{gw}, "gw-a", now.Add(time.Second))
	settle(t, g)
	close(release)
	time.Sleep(50 * time.Millisecond)

	got := g.results()
	if len(got) != 1 || !got[0].Healthy || got[0].ConsecutiveFailures != 0 {
		t.Fatalf("results = %+v; the old target's failure leaked into the new one", got)
	}
}

func TestProbeTargetICMPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a raw ICMP socket")
	}
	sock, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		t.Skipf("no IPv6 here: %v", err)
	}
	sock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeTarget(ctx, "::1"); err != nil {
		t.Fatalf("ping ::1: %v", err)
	}
}
