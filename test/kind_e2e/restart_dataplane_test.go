//go:build kind_e2e && kind_e2e_restart

// These cases carry a second build tag so the existing e2e job does not grow by
// the eight minutes they take. The regular matrix already runs close to its
// twenty-minute budget. A dedicated job selects them with
// -tags kind_e2e,kind_e2e_restart.

package kind_e2e

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests probe what an agent restart does to a node's data path.
//
// They come from an incident where a rolling restart of the agent DaemonSet
// stranded one node for six minutes. The cause, read off the cluster's own
// metrics: the node demoted all nine of its peers to relay seconds after
// restarting, and its relay leg went away two seconds later. Transport mode
// relay with no relay is a blackhole.
//
// wirekube_suppressed_routes stayed at zero for the whole window, so no route
// was ever withdrawn. The first draft of these tests assumed route withdrawal
// was the mechanism; the metrics say otherwise, and the two route tests below
// are kept as regression cover rather than as evidence of the incident.
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
// This did NOT happen during the incident: suppressed_routes was zero
// throughout. The test is regression cover for canRouteBeforeHandshake, which
// refuses to install any route before a handshake when the relay is unusable,
// and for the one-tick grace window on preserved routes. Neither has been seen
// to fire in production.
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
// deletion and measures the restarting node's return path.
//
// On its own this passes with a gap of zero, and the reason matters: with the
// relay already gone before the restart, no demotion happens, so the peer stays
// direct and nothing is lost. The incident needed a demotion first. That case
// is TestRestartLosingRelayDuringDemotionBlackholes below.
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

// A peer demoted to relay while the relay leg is gone has nowhere to send.
//
// This is the sequence the incident actually followed, read off the cluster's
// own metrics rather than inferred from the code:
//
//	02:12:26  agent restarts, peers promote warm -> direct
//	02:12:30  all nine peers demoted to relay (relayed_peers_total 1 -> 9)
//	02:12:32  relay connect starts failing, i/o timeout
//	02:18:26  relay reconnects, traffic resumes
//
// wirekube_suppressed_routes stayed at zero throughout, so no route was ever
// withdrawn. The transport mode was the whole of it: PathModeRelay with no
// relay leg means the Bind has nowhere to put the packet.
//
// Only the node hosting the relay pod demoted every peer. The other four nodes
// demoted two apiece during their own restarts and rode it out, because their
// relay leg was still there.
//
// The two tests above isolate the halves of this and both pass: a demotion with
// a live relay costs nothing, and a dead relay with no demotion costs nothing.
// The outage needs both, so this test kills the relay in the window between the
// restart and the demotion that follows it.
func TestRestartLosingRelayDuringDemotionBlackholes(t *testing.T) {
	ctx := context.Background()

	peers := resetTransportState(ctx, t)
	subject := peers[0]
	remote := peers[1]
	waitForDirectWithTraffic(ctx, t, subject, remote)

	subjectIP := nodeIPForPeer(t, subject)
	pinger := agentPodForNode(ctx, t, remote)

	type pingResult struct {
		out string
		err error
	}
	pingDone := make(chan pingResult, 1)
	go func() {
		out, err := execInPod(ctx, t, pinger, "agent",
			[]string{"ping", "-i", "0.5", "-c", "300", "-W", "2", subjectIP})
		pingDone <- pingResult{out, err}
	}()
	time.Sleep(4 * time.Second)

	// Restart with the relay still up, exactly as on the incident cluster. The
	// demotion needs a relay it believes in; killing the relay first stops the
	// demotion from happening at all, which is what made the earlier attempt
	// measure nothing.
	restartAgentOnNode(ctx, t, subject)

	// The relay disappears while the agent is coming back, the way it did for
	// the node that was hosting it.
	restoreRelay := scaleRelayEntrypoint(ctx, t, 0)
	defer restoreRelay()
	t.Logf("relay scaled to zero right after %s restarted", subject)

	// Give the ICE layer time to run its evaluations and demote.
	time.Sleep(75 * time.Second)

	logs := agentLogsSince(ctx, t, subject, 5*time.Minute)
	demotions := strings.Count(logs, "active probe failed, reverting to relay")
	t.Logf("demotions after the restart: %d", demotions)

	result := <-pingDone
	if result.err != nil {
		t.Logf("ping returned an error (expected when loss is high): %v", result.err)
	}
	gap := longestPingSeqGap(result.out)

	t.Logf("longest consecutive seq gap: %d", gap)
	if demotions == 0 {
		t.Skipf("no demotion occurred, so the blackhole condition never formed; "+
			"seq gap was %d", gap)
	}

	// At 2 pps a six-minute blackhole is 720 probes. Anything past 20 already
	// means the peer is stranded rather than merely reconverging.
	const maxSeqGap = 20
	if gap > maxSeqGap {
		t.Errorf("%d peers were demoted to relay with no relay leg and the data path "+
			"was down for %d consecutive probes (max %d)", demotions, gap, maxSeqGap)
	}
}

// An agent restart must not hold the data path hostage to a relay dial that
// will never answer.
//
// Measured on the incident cluster by restarting one node under continuous
// ping. Both the mesh address and a pod address on that node lost the same
// 22 consecutive probes at 0.5 s spacing, an 11.0 s outage starting the moment
// the pod was deleted. The agent log accounts for it exactly:
//
//	07:18:36  container starts, initRelay entered
//	          (ten seconds, no log output)
//	07:18:46  relay initial connect failed: dial tcp ...:3478: i/o timeout
//	07:18:46  first sync runs, tunnel comes back
//
// Pool.Connect is called synchronously from setup before Run reaches its first
// sync, and dialTimeout is ten seconds. When the relay address does not answer,
// the agent spends all of it before configuring a single WireGuard peer. The
// error it then logs says "will retry in background", which is where the dial
// belonged from the start.
//
// The contrast with TestRestartWithoutRelayKeepsDataPath is the evidence.
// There the relay is scaled to zero, connect() is refused instantly, and the
// gap is zero. Here the same restart with the same relay outage costs the full
// timeout, because the address is dropped rather than refused.
func TestRestartWithBlackholedRelayStallsTheDataPath(t *testing.T) {
	ctx := context.Background()

	peers := resetTransportState(ctx, t)
	subject := peers[0]
	remote := peers[1]
	waitForDirectWithTraffic(ctx, t, subject, remote)

	subjectIP := nodeIPForPeer(t, subject)
	pinger := agentPodForNode(ctx, t, remote)

	type pingResult struct {
		out string
		err error
	}
	pingDone := make(chan pingResult, 1)
	go func() {
		out, err := execInPod(ctx, t, pinger, "agent",
			[]string{"ping", "-i", "0.5", "-c", "180", "-W", "2", subjectIP})
		pingDone <- pingResult{out, err}
	}()
	time.Sleep(4 * time.Second)

	// In place before the restart, so the agent that comes back finds the
	// relay address unreachable during its own startup.
	restoreRelay := blackholeRelayTCP(t, subject)
	defer restoreRelay()

	restartAgentOnNode(ctx, t, subject)

	result := <-pingDone
	if result.err != nil {
		t.Logf("ping returned an error (expected when loss is high): %v", result.err)
	}
	gap := longestPingSeqGap(result.out)

	// At 2 pps the suite's bimodal warm-send bound is 8 probes. A full
	// dialTimeout is 20 on top of whatever the pod swap costs, so the two
	// outcomes are far apart and the threshold does not need to be precise.
	const maxSeqGap = 8
	t.Logf("longest consecutive seq gap with the relay blackholed: %d (%.1fs), max allowed %d",
		gap, float64(gap)*0.5, maxSeqGap)
	if gap > maxSeqGap {
		t.Errorf("the data path was down for %d consecutive probes (%.1fs) because startup "+
			"waited out a relay dial that never answered (max %d)",
			gap, float64(gap)*0.5, maxSeqGap)
	}
}
