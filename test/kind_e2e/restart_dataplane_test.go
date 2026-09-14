//go:build kind_e2e

package kind_e2e

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests probe what an agent restart does to a node's data path while the
// relay is unavailable. They were written from a production incident on a
// cluster where a rolling restart of the agent DaemonSet took the pod network
// down across several nodes for minutes.
//
// The existing TestAgentRestart only asserts that the peer's reported
// connection mode comes back. It never looks at the kernel routes or at
// whether packets kept flowing, so it passes while the data path is gone.

// wireKubeRouteTable returns the node's WireKube routing table as text.
func wireKubeRouteTable(t *testing.T, nodeName string) string {
	t.Helper()
	out, err := ctrExec("exec", nodeName, "ip", "route", "show", "table", "22347")
	if err != nil {
		t.Fatalf("read WireKube route table on %s: %v", nodeName, err)
	}
	return out
}

func routeTableHas(table, addr string) bool {
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == addr || fields[0] == addr+"/32") {
			return true
		}
	}
	return false
}

// A restart must not withdraw the route to a peer's node address.
//
// The route matters more than the mode a peer reports. Cilium in tunnel mode
// sends VXLAN to node addresses, so those routes carry every pod packet
// between nodes. If they disappear, the pod network on that node stops even
// though every WireKubePeer still reads "connected".
//
// The relay is taken down first because that is the condition the incident
// happened under, and because canRouteBeforeHandshake refuses to install any
// route before a handshake when the relay is unusable.
func TestRestartWithoutRelayKeepsNodeRoutes(t *testing.T) {
	ctx := context.Background()

	peers := resetTransportState(ctx, t)
	subject := peers[0]
	remote := peers[1]
	waitForDirectWithTraffic(ctx, t, subject, remote)

	remoteIP := nodeIPForPeer(t, remote)
	before := wireKubeRouteTable(t, subject)
	t.Logf("%s route table before restart:\n%s", subject, before)
	if !routeTableHas(before, remoteIP) {
		t.Fatalf("precondition failed: %s has no route to %s (%s) before the restart",
			subject, remote, remoteIP)
	}

	restoreRelay := scaleRelayEntrypoint(ctx, t, 0)
	defer restoreRelay()
	t.Logf("relay scaled to zero; %s now has no relay leg", subject)

	restartAgentOnNode(ctx, t, subject)

	// Sample once a second. The agent syncs every 5s here, so a withdrawal
	// and its recovery both land well inside this window.
	const (
		sampleFor    = 60 * time.Second
		sampleEvery  = time.Second
		maxWithdrawn = 5 * time.Second
	)
	var withdrawn, longest time.Duration
	var run time.Duration
	deadline := time.Now().Add(sampleFor)
	for time.Now().Before(deadline) {
		if routeTableHas(wireKubeRouteTable(t, subject), remoteIP) {
			run = 0
		} else {
			withdrawn += sampleEvery
			run += sampleEvery
			if run > longest {
				longest = run
			}
		}
		time.Sleep(sampleEvery)
	}

	t.Logf("route to %s (%s) absent for %s total, longest continuous run %s",
		remote, remoteIP, withdrawn, longest)
	t.Logf("%s route table after restart:\n%s", subject, wireKubeRouteTable(t, subject))

	if longest > maxWithdrawn {
		t.Errorf("node route withdrawn for %s during a restart with no relay (max %s); "+
			"the pod network on %s is down for that whole window",
			longest, maxWithdrawn, subject)
	}
}

// Packets must keep flowing to a node whose agent restarts while the relay is
// down.
//
// The ping runs from the peer that is NOT restarted, so it survives the pod
// deletion and measures the restarting node's return path. Echo replies leave
// the restarted node, so a route withdrawal there shows up as a gap here.
func TestRestartWithoutRelayKeepsDataPath(t *testing.T) {
	ctx := context.Background()

	peers := resetTransportState(ctx, t)
	subject := peers[0]
	remote := peers[1]
	waitForDirectWithTraffic(ctx, t, subject, remote)

	subjectIP := nodeIPForPeer(t, subject)
	pinger := agentPodForNode(ctx, t, remote)

	// 2 pps for 120 s: long enough to cover the pod delete, the new pod's
	// first syncs, and the recovery.
	type pingResult struct {
		out string
		err error
	}
	pingDone := make(chan pingResult, 1)
	go func() {
		out, err := execInPod(ctx, t, pinger, "agent",
			[]string{"ping", "-i", "0.5", "-c", "240", "-W", "2", subjectIP})
		pingDone <- pingResult{out, err}
	}()

	time.Sleep(4 * time.Second)

	restoreRelay := scaleRelayEntrypoint(ctx, t, 0)
	defer restoreRelay()
	t.Logf("relay scaled to zero; restarting %s with no relay leg", subject)

	restartAgentOnNode(ctx, t, subject)

	result := <-pingDone
	if result.err != nil {
		t.Logf("ping returned an error (expected when loss is high): %v", result.err)
	}

	gap := longestPingSeqGap(result.out)
	// At 2 pps the bimodal warm-send bound used elsewhere in this suite is 8
	// packets. A restart should not be worse than a failover, so allow 20 to
	// cover pod scheduling, then fail on anything larger.
	const maxSeqGap = 20
	t.Logf("longest consecutive seq gap across the restart: %d (max allowed %d)", gap, maxSeqGap)
	if gap > maxSeqGap {
		t.Errorf("data path to %s was down for %d consecutive probes during a restart with no relay (max %d)",
			subject, gap, maxSeqGap)
	}
}

// agentLogsSince returns the agent log on a node for the given window.
func agentLogsSince(ctx context.Context, t *testing.T, nodeName string, window time.Duration) string {
	t.Helper()
	pod := agentPodForNode(ctx, t, nodeName)
	out, err := kubectlInCP("logs", "-n", agentNamespace, pod.Name,
		"--since="+strconv.Itoa(int(window.Seconds()))+"s")
	if err != nil {
		t.Fatalf("read agent logs on %s: %v", nodeName, err)
	}
	return out
}

// A peer that has just reconnected on a healthy direct path must not be demoted
// to relay by the active probe.
//
// probeDirectEndpoint applies a direct endpoint but sends no keepalive, and the
// probe counts itself successful only if a NEW handshake appears within
// activeProbeWait. WireGuard does not rehandshake a live session, so a peer
// that just connected can fail a probe it should pass. On the incident cluster
// one node demoted all nine of its peers this way within a minute of starting,
// every one of them reporting failures=1.
//
// The restart is what makes the probe run: ICE re-evaluates every peer while
// the session is fresh, which is exactly the window the bug lives in.
func TestRestartDoesNotDemoteHealthyDirectPeers(t *testing.T) {
	ctx := context.Background()

	peers := resetTransportState(ctx, t)
	subject := peers[0]
	remote := peers[1]
	waitForDirectWithTraffic(ctx, t, subject, remote)

	restartAgentOnNode(ctx, t, subject)

	// Let the new agent reconnect and then run a few ICE evaluations.
	eventually(t, func() bool {
		return connectionMode(ctx, t, subject, remote) == "direct"
	}, directTimeout, pollInterval, subject+" → "+remote+" should return to direct after restart")
	t.Log("direct restored; watching 60s of ICE evaluations")
	time.Sleep(60 * time.Second)

	logs := agentLogsSince(ctx, t, subject, 5*time.Minute)
	var demotions []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "active probe failed, reverting to relay") {
			demotions = append(demotions, strings.TrimSpace(line))
		}
	}

	t.Logf("%s → %s = %q after the observation window",
		subject, remote, connectionMode(ctx, t, subject, remote))
	for _, d := range demotions {
		t.Logf("demotion: %s", d)
	}

	if len(demotions) > 0 {
		t.Errorf("the active probe demoted %d peer(s) to relay after a restart that recovered a direct path",
			len(demotions))
	}
}
