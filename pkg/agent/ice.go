package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/agent/nat"
	"github.com/wirekube/wirekube/pkg/wireguard"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ICE-like connection states per peer.
const (
	iceStateRelay     = "relay"
	iceStateGathering = "gathering"
	iceStateChecking  = "checking"
	iceStateConnected = "connected"
	iceStateBirthday  = "birthday"
	iceStateFailed    = "failed"
)

// Candidate types in priority order (higher = preferred).
const (
	candidateTypeHost  = "host"
	candidateTypeSrflx = "srflx" // server-reflexive (STUN)
	candidateTypeRelay = "relay"
	candidateTypePrflx = "prflx" // peer-reflexive (WG-observed)
)

// Timing constants for ICE probe evaluation and handshake validation.
const (
	defaultHandshakeValidWindow = 3 * time.Minute
	activeProbeWait      = 8 * time.Second
	passiveProbeTimeout  = 60 * time.Second
	iceCheckTimeout      = 90 * time.Second
	// restartRelayRetry is the shortened retry interval used immediately after
	// agent restart to quickly re-evaluate direct connectivity for peers that
	// were relayed before the restart.
	restartRelayRetry = 15 * time.Second

	// directConnectedWindow is the maximum age of a WireGuard LastHandshake that
	// still indicates a live direct connection. Must exceed handshakeValidWindow
	// (3 min, which equals WG's REKEY_AFTER_TIME) to bridge the gap between:
	//   a) the last relay-mediated handshake (before the relay→direct upgrade), and
	//   b) the first WG re-handshake on the direct path (3 min after (a)).
	//
	// Without this buffer, isDirectConnected fails immediately after upgrade when
	// the preserved WG session's LastHandshake is near the 3-min boundary, causing
	// a flip-flop: upgrade → detected-as-disconnected → revert-to-relay → repeat.
	//
	// 5 min = 3 min (REKEY_AFTER_TIME) + 2 min (probe timing + re-handshake grace).
	// After the first successful direct re-handshake, LastHandshake is fresh and
	// the normal 3-min window applies on subsequent cycles.
	defaultDirectConnectedWindow = 5 * time.Minute
)

// Relay mode constants matching WireKubeMesh.spec.relay.mode values.
const (
	relayModeAlways = "always"
	relayModeNever  = "never"
)

// Well-known virtual interface prefixes to skip during IP discovery.
var virtualIfacePrefixes = []string{
	"docker", "veth", "cilium", "cni", "flannel",
	"br-", "virbr", "wg", "wire_kube", "lxc",
}

// maxSuspendedProbes is the number of consecutive probe failures before
// relay suspension is disabled for a peer. After this many failures, probes
// still run but relay delivery stays active to avoid periodic disruptions
// in environments where direct connectivity is impossible.
const maxSuspendedProbes = 5

// peerICEState tracks ICE negotiation state for a single peer.
type peerICEState struct {
	State         string
	LastCheck     time.Time
	CheckCount    int
	BirthdayTried bool
	// FailCount tracks consecutive isDirectConnected failures.
	FailCount int
	// UpgradedAt records when this peer was last upgraded to direct.
	// Used to provide a grace period for WG to complete the first
	// direct re-handshake (up to REKEY_AFTER_TIME = 3 min).
	UpgradedAt time.Time

	// ProbeFailCount tracks consecutive ICE probe failures (active probe
	// returned directObserved=false). After maxSuspendedProbes failures,
	// relay delivery is no longer suspended during probes to avoid periodic
	// 8-second disruptions in environments where direct is impossible.
	ProbeFailCount int

	// LastHealthProbeOK records the last time an active health probe
	// confirmed the direct connection is alive despite a stale LastHandshake.
	// Used as a cooldown to avoid re-probing every sync cycle.
	LastHealthProbeOK time.Time

	// relaySuspendedForProbe is true when relay delivery was suspended at
	// the start of an active probe (in startICECheck). evaluateICECheck
	// resumes delivery when the probe completes. This pre-suspension
	// prevents relay packets from causing WG to roam to localhost during
	// the probe window, which is critical after mode=always→auto transitions
	// where the relay proxy is fully active (not standby).
	relaySuspendedForProbe bool

	directProbeApplied bool

	// ProbeStartHandshake records the time this ICE check was initiated.
	// evaluateICECheck uses it to detect handshakes that occurred after
	// the probe started.
	ProbeStartHandshake time.Time

	// holePunch holds the result of a successful birthday attack.
	// If non-nil, the UDP proxy is active and WG should use its local address.
	holePunch *holePunchProxy
}

// holePunchProxy bridges WireGuard traffic through a birthday-attack hole-punched path.
type holePunchProxy struct {
	localConn *net.UDPConn         // receives from WG (localhost:random → localhost:wgport)
	holeConn  *net.UDPConn         // the hole-punched socket
	peerAddr  atomic.Pointer[net.UDPAddr] // peer's NAT-mapped address; updated on rebind
	wgPort    int
	stopCh    chan struct{}
	once      sync.Once
}

func newHolePunchProxy(holeResult *nat.HolePunchResult, wgPort int) (*holePunchProxy, error) {
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort}
	localConn, err := net.DialUDP("udp4", localAddr, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("creating local proxy socket: %w", err)
	}

	hp := &holePunchProxy{
		localConn: localConn,
		holeConn:  holeResult.LocalConn,
		wgPort:    wgPort,
		stopCh:    make(chan struct{}),
	}
	hp.peerAddr.Store(holeResult.PeerAddr)
	return hp, nil
}

// ListenAddr returns the local address WireGuard should use as peer endpoint.
func (hp *holePunchProxy) ListenAddr() string {
	return hp.localConn.LocalAddr().String()
}

// Run starts bidirectional forwarding. Blocks until Close is called.
func (hp *holePunchProxy) Run() {
	go hp.forwardWGToHole()
	hp.forwardHoleToWG()
}

func (hp *holePunchProxy) forwardWGToHole() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-hp.stopCh:
			return
		default:
		}
		hp.localConn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := hp.localConn.Read(buf)
		if err != nil {
			continue
		}
		hp.holeConn.WriteToUDP(buf[:n], hp.peerAddr.Load())
	}
}

func (hp *holePunchProxy) forwardHoleToWG() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-hp.stopCh:
			return
		default:
		}
		hp.holeConn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := hp.holeConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		current := hp.peerAddr.Load()
		if !addr.IP.Equal(current.IP) {
			continue
		}
		// Accept port changes for NAT rebinding.
		if addr.Port != current.Port {
			hp.peerAddr.Store(addr)
		}
		hp.localConn.Write(buf[:n])
	}
}

func (hp *holePunchProxy) Close() {
	hp.once.Do(func() {
		close(hp.stopCh)
		hp.localConn.Close()
		hp.holeConn.Close()
	})
}

// gatherICECandidates collects local connectivity candidates.
func (a *Agent) gatherICECandidates(epResult *EndpointResult) []wirekubev1alpha1.ICECandidate {
	candidates := make([]wirekubev1alpha1.ICECandidate, 0, 4)

	// Host candidate: node's internal IP + WG listen port.
	if internalIP := a.getNodeInternalIP(); internalIP != "" {
		candidates = append(candidates, wirekubev1alpha1.ICECandidate{
			Type:     candidateTypeHost,
			Address:  fmt.Sprintf("%s:%d", internalIP, a.wgMgr.ListenPort()),
			Priority: 100,
		})
	}

	// Server-reflexive candidate: STUN-discovered public endpoint.
	if epResult != nil && epResult.Endpoint != "" {
		prio := int32(200)
		if epResult.NATType == nat.NATSymmetric {
			prio = 50 // low priority — mapped port is unstable
		}
		candidates = append(candidates, wirekubev1alpha1.ICECandidate{
			Type:     candidateTypeSrflx,
			Address:  epResult.Endpoint,
			Priority: prio,
		})
	}

	// Relay candidate: added later if relay is available.
	if a.relayPool != nil && a.relayPool.IsConnected() {
		candidates = append(candidates, wirekubev1alpha1.ICECandidate{
			Type:     candidateTypeRelay,
			Address:  "relay",
			Priority: 10,
		})
	}

	return candidates
}

// getNodeInternalIP returns this node's internal IP address.
// Tries multiple strategies for environments without internet access:
//  1. Kubernetes Node object InternalIP (most reliable)
//  2. Network interface scan (works offline)
//  3. UDP dial to external IP (original fallback)
func (a *Agent) getNodeInternalIP() string {
	// Strategy 1: Kubernetes Node InternalIP.
	node := &corev1.Node{}
	if err := a.client.Get(context.Background(), client.ObjectKey{Name: a.nodeName}, node); err == nil {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				return addr.Address
			}
		}
	}

	// Strategy 2: scan non-loopback network interfaces.
	if ip := firstNonLoopbackIPv4(); ip != "" {
		return ip
	}

	// Strategy 3: UDP dial (requires outbound connectivity).
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// firstNonLoopbackIPv4 scans network interfaces for the first usable IPv4 address,
// skipping loopback, docker/veth/cilium/wg virtual interfaces.
func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

func isVirtualInterface(name string) bool {
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// publishICEState updates this node's WireKubePeer status with ICE candidates
// and port prediction data.
func (a *Agent) publishICEState(ctx context.Context, peerName string, candidates []wirekubev1alpha1.ICECandidate,
	portPred *nat.PortPrediction, iceState string) error {

	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return err
	}
	patch := client.MergeFrom(peer.DeepCopy())
	peer.Status.ICECandidates = candidates
	peer.Status.ICEState = iceState

	if portPred != nil {
		pp := &wirekubev1alpha1.PortPrediction{
			BasePort:    int32(portPred.BasePort),
			Increment:   int32(portPred.Increment),
			Jitter:      int32(portPred.Jitter),
			SamplePorts: make([]int32, len(portPred.SamplePorts)),
		}
		for i, p := range portPred.SamplePorts {
			pp.SamplePorts[i] = int32(p)
		}
		peer.Status.PortPrediction = pp
	}

	return a.client.Status().Patch(ctx, peer, patch)
}

// runICENegotiation evaluates peers and attempts connectivity upgrades.
// Called from the sync loop. Returns quickly; heavy work runs in background goroutines.
//
// Probe strategy (passive-first, make-before-break):
//  1. Passive observation: keep relay, watch for peer-initiated direct handshake.
//  2. Active probe: if passive fails, ForceEndpoint to test direct path.
//  3. Make-before-break: relay proxy is closed one cycle AFTER WG switches to direct.
func (a *Agent) runICENegotiation(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList,
	statsByKey map[string]wireguard.PeerStats) {

	if a.relayPool == nil {
		return
	}

	// When relay mode is "always", skip all ICE negotiation — peers must stay
	// on relay unconditionally. Without this guard, the ICE loop would probe
	// and upgrade peers back to direct, defeating the mode=always intent.
	if a.relayMode == relayModeAlways {
		return
	}

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == a.nodeName || p.Spec.PublicKey == "" {
			continue
		}

		state := a.getICEState(p.Name)

		switch state.State {
		case iceStateConnected:
			if !a.isDirectConnected(p, statsByKey) {
				// Handshake is stale — but the connection may still be alive
				// (WG re-handshake in progress). Run active health probe before
				// reverting to relay.
				if a.probeDirectHealth(p) {
					continue
				}
				fmt.Printf("[ice] peer %s: health probe failed, activating standby relay\n", p.Name)
				a.revertToRelay(p)
			}
			continue

		case iceStateRelay:
			if !a.relayedPeers[p.Name] {
				continue
			}
			if !state.LastCheck.IsZero() && time.Since(state.LastCheck) < a.relayRetry {
				continue
			}
			a.startICECheck(ctx, p, statsByKey)

		case iceStateChecking:
			a.evaluateICECheck(ctx, p, statsByKey)

		case iceStateBirthday:
			if state.holePunch != nil {
				a.upgradeToDirect(p, state.holePunch.ListenAddr())
			}

		case iceStateFailed:
			if isPortRestrictedSymmetricPair(a.detectedNATType, p.Status.NATType) {
				continue // permanently stay on relay
			}
			if time.Since(state.LastCheck) >= a.relayRetry {
				state.State = iceStateRelay
				state.BirthdayTried = false
				a.setICEState(p.Name, state)
			}
		}
	}
}

func (a *Agent) getICEState(peerName string) *peerICEState {
	if a.iceStates == nil {
		a.iceStates = make(map[string]*peerICEState)
	}
	s, ok := a.iceStates[peerName]
	if !ok {
		s = &peerICEState{State: iceStateRelay}
		a.iceStates[peerName] = s
	}
	return s
}

func (a *Agent) setICEState(peerName string, s *peerICEState) {
	if a.iceStates == nil {
		a.iceStates = make(map[string]*peerICEState)
	}
	a.iceStates[peerName] = s
}

// startICECheck initiates a connectivity check for a relayed peer.
// Uses a passive-first strategy to minimize disruption:
//   - Passive: observe if the peer initiates direct (no WG endpoint change).
//   - Active: ForceEndpoint probe only when passive fails or isn't applicable.
func (a *Agent) startICECheck(ctx context.Context, peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) {

	state := a.getICEState(peer.Name)
	state.State = iceStateChecking
	state.LastCheck = time.Now()
	state.CheckCount++
	state.directProbeApplied = false // reset so resolveEndpointForPeer re-anchors LastCheck

	// Record the current time as the probe baseline for the backup handshake
	// detection in evaluateICECheck. Using time.Now() (not s.LastHandshake)
	// ensures we only treat handshakes that occur AFTER the probe starts as
	// "fresh". Using the old LastHandshake causes false positives when the WG
	// interface was preserved across restarts: the pre-restart handshake
	// timestamp predates ProbeStartHandshake, making any relay keepalive look
	// like a new direct handshake when lastRelayHS is also zero (because the
	// relay proxy has never delivered a WG handshake packet type 1/2 — only
	// keepalive type 4 packets were forwarded over the preserved session).
	state.ProbeStartHandshake = time.Now()

	if a.trySameNATDirect(peer) {
		a.setICEState(peer.Name, state)
		return
	}

	peerNAT := peer.Status.NATType
	myNAT := a.detectedNATType

	// Port-restricted cone ↔ Symmetric: direct P2P is impossible.
	// Symmetric NAT allocates a new port for each destination, so the reply
	// comes from a port that port-restricted cone NAT hasn't opened a filter
	// for. Neither side can complete the handshake — skip probe entirely.
	if isPortRestrictedSymmetricPair(myNAT, peerNAT) {
		fmt.Printf("[ice] peer %s: port-restricted-cone↔symmetric — direct P2P impossible, staying on relay permanently\n", peer.Name)
		state.State = iceStateFailed
		a.setICEState(peer.Name, state)
		return
	}

	// Suspend relay delivery before probing so WG doesn't roam to localhost.
	// Skip after maxSuspendedProbes consecutive failures to avoid periodic
	// disruptions in environments where direct connectivity is impossible.
	suspendRelayForProbe := func() {
		if state.ProbeFailCount < maxSuspendedProbes && a.relayPool != nil {
			if keyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey); err == nil && len(keyBytes) == 32 {
				var pubKey [32]byte
				copy(pubKey[:], keyBytes)
				a.relayPool.SuspendDelivery(pubKey)
				state.relaySuspendedForProbe = true
			}
		}
	}

	switch {
	case myNAT != "symmetric" && peerNAT != "symmetric":
		// Cone ↔ Cone: both endpoints are stable. Active probe is safe and fast
		// because the peer can reach us at our stable STUN endpoint simultaneously.
		fmt.Printf("[ice] peer %s: cone↔cone — active probe to %s\n", peer.Name, peer.Spec.Endpoint)
		suspendRelayForProbe()
		a.probeDirectEndpoint(peer)

	case myNAT != "symmetric" && peerNAT == "symmetric":
		// Cone ↔ Symmetric: simultaneous active probe from both sides.
		//
		// Passive-only approach fails for two reasons:
		//   1. The symmetric peer's relay keepalives (sent while we stay on relay)
		//      arrive at our relay proxy and are forwarded to our WG with a
		//      localhost source. WG roams back to the localhost proxy address,
		//      so ActualEndpoint stays "127.0.0.1:PORT" and probeOK is always
		//      false even when the direct handshake succeeds.
		//   2. Many home routers use address-restricted cone NAT: inbound packets
		//      from a source IP are only forwarded if we have previously sent
		//      something to that IP. Passive mode never sends to the symmetric
		//      peer's IP, so the NAT filter blocks their probe.
		//
		// By probing actively on both sides simultaneously:
		//   - We send to the symmetric peer's CRD endpoint (packet is dropped by
		//     their symmetric NAT, but it opens our address-restricted filter for
		//     their IP and stops our WG from sending keepalives via relay).
		//   - The symmetric peer probes our stable STUN endpoint; with our NAT
		//     filter now open their probe gets through and the handshake completes.
		//   - Both relay proxies are closed before probing, preventing relay
		//     packets from causing WG to roam back to localhost during the window.
		fmt.Printf("[ice] peer %s: cone↔symmetric — simultaneous probe to %s (opens NAT filter)\n", peer.Name, peer.Spec.Endpoint)
		suspendRelayForProbe()
		a.probeDirectEndpoint(peer)

	case myNAT == "symmetric" && peerNAT != "symmetric":
		// Symmetric ↔ Cone: we should probe the peer's stable endpoint.
		fmt.Printf("[ice] peer %s: symmetric↔cone — active probe to %s\n", peer.Name, peer.Spec.Endpoint)
		suspendRelayForProbe()
		a.probeDirectEndpoint(peer)

	case myNAT == "symmetric" && peerNAT == "symmetric":
		if !a.isBirthdayAttackEnabled(peer) {
			fmt.Printf("[ice] peer %s: symmetric↔symmetric — birthday attack disabled, staying on relay\n", peer.Name)
			state.State = iceStateFailed
		} else if !state.BirthdayTried {
			fmt.Printf("[ice] peer %s: symmetric↔symmetric — initiating birthday attack\n", peer.Name)
			state.State = iceStateBirthday
			state.BirthdayTried = true
			go a.runBirthdayAttack(ctx, peer)
		} else {
			fmt.Printf("[ice] peer %s: symmetric↔symmetric — birthday attack already attempted, staying on relay\n", peer.Name)
			state.State = iceStateFailed
		}
	}

	a.setICEState(peer.Name, state)
}

// isPortRestrictedSymmetricPair returns true when one side is port-restricted
// cone and the other is symmetric. Direct P2P is impossible for this combination:
// symmetric NAT maps each destination to a new source port, so the port-restricted
// cone NAT never has a matching filter entry for the reply.
func isPortRestrictedSymmetricPair(myNAT, peerNAT string) bool {
	prc := string(nat.NATPortRestrictedCone)
	sym := string(nat.NATSymmetric)
	return (myNAT == prc && peerNAT == sym) || (myNAT == sym && peerNAT == prc)
}

// trySameNATDirect checks if the peer shares our public NAT IP.
// If so, we probe via the peer's host candidate (internal LAN IP) instead of
// the public STUN endpoint, since two hosts behind the same NAT can
// communicate directly on the LAN.
func (a *Agent) trySameNATDirect(peer *wirekubev1alpha1.WireKubePeer) bool {
	myPublicIP := extractIP(a.directEndpoints[a.nodeName])
	if myPublicIP == "" {
		// Try from the endpoint field on our own peer (stored during setup).
		for k, v := range a.directEndpoints {
			if k == a.nodeName {
				myPublicIP = extractIP(v)
				break
			}
		}
	}
	// Use the STUN-discovered endpoint IP as our public IP.
	if myPublicIP == "" && a.ownPublicKeyB64 != "" {
		// Fallback: compare STUN endpoint IPs via CRD.
		own := &wirekubev1alpha1.WireKubePeer{}
		if err := a.client.Get(context.Background(), client.ObjectKey{Name: a.nodeName}, own); err == nil {
			myPublicIP = extractIP(own.Spec.Endpoint)
		}
	}
	if myPublicIP == "" {
		return false
	}

	peerPublicIP := extractIP(peer.Spec.Endpoint)
	if peerPublicIP == "" || myPublicIP != peerPublicIP {
		return false
	}

	// Same public IP — find the peer's host candidate.
	hostAddr := ""
	for _, c := range peer.Status.ICECandidates {
		if c.Type == candidateTypeHost && c.Address != "" {
			hostAddr = c.Address
			break
		}
	}
	if hostAddr == "" {
		fmt.Printf("[ice] peer %s: same NAT (%s) but no host candidate available\n", peer.Name, myPublicIP)
		return false
	}

	fmt.Printf("[ice] peer %s: same NAT detected (%s) — probing via LAN endpoint %s\n", peer.Name, myPublicIP, hostAddr)
	a.directEndpoints[peer.Name] = hostAddr
	a.directProbing[peer.Name] = true
	return true
}

func extractIP(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	return host
}

// isBirthdayAttackEnabled checks the WireKubeMesh global setting and per-peer
// annotation override to determine if birthday attack is allowed.
// Priority: peer annotation > mesh global > default (disabled).
func (a *Agent) isBirthdayAttackEnabled(peer *wirekubev1alpha1.WireKubePeer) bool {
	const annKey = "wirekube.io/birthday-attack"

	// Per-peer annotation override (highest priority).
	if ann, ok := peer.Annotations[annKey]; ok {
		return ann == "enabled"
	}

	// Also check our own peer annotation.
	ownPeer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(context.Background(), client.ObjectKey{Name: a.nodeName}, ownPeer); err == nil {
		if ann, ok := ownPeer.Annotations[annKey]; ok {
			return ann == "enabled"
		}
	}

	// WireKubeMesh global setting.
	mesh, err := a.getMesh(context.Background())
	if err == nil && mesh.Spec.NATTraversal != nil {
		return mesh.Spec.NATTraversal.BirthdayAttack == "enabled"
	}

	// Default: disabled.
	return false
}

// startPassiveProbe begins observing whether the peer initiates a direct
// WireGuard handshake. The relay proxy and WG endpoint are left unchanged,
// so there is zero traffic disruption. If the peer's agent runs an active
// probe towards our stable STUN endpoint, the kernel will learn the peer's
// actual NAT-mapped address, which we detect in evaluateICECheck.
func (a *Agent) startPassiveProbe(peer *wirekubev1alpha1.WireKubePeer) {
	a.passiveProbing[peer.Name] = time.Now()
}

// probeDirectEndpoint switches WG to the peer's direct endpoint for a
// handshake probe while keeping relay fully active — zero traffic disruption.
//
// Two-phase evaluation (in evaluateICECheck):
//
//	Phase 1: observe fresh WG handshake while relay stays active (zero disruption).
//	Phase 2: if direct path confirmed, 200ms micro-suspension to discover the
//	         peer's actual NAT-mapped endpoint without relay interference.
//
// This avoids the 8-second relay suspension that would disrupt traffic in
// environments where direct connectivity is impossible.
func (a *Agent) probeDirectEndpoint(peer *wirekubev1alpha1.WireKubePeer) {
	directEp := a.directEndpoints[peer.Name]
	if directEp == "" {
		directEp = peer.Spec.Endpoint
	}
	if directEp == "" {
		return
	}
	a.directEndpoints[peer.Name] = directEp
	a.directProbing[peer.Name] = true

	// Immediately force WG to use the direct endpoint. Without this, the
	// endpoint change only takes effect on the next sync cycle (5s later),
	// but relay may already be suspended — leaving WG pointing at localhost
	// with no path for handshakes.
	if err := a.wgMgr.ForceEndpoint(peer.Spec.PublicKey, directEp); err != nil {
		fmt.Printf("[ice] peer %s: ForceEndpoint(%s) failed: %v\n", peer.Name, directEp, err)
	}
}


// processRelayGrace marks peers as non-relayed after upgrading to direct.
// Relay proxies remain in standby mode for instant failover.
// directEndpoints is preserved — for symmetric peers it holds the discovered
// NAT-mapped endpoint which must be maintained for ForceEndpoint.
func (a *Agent) processRelayGrace() {
	for name := range a.relayGracePeers {
		delete(a.relayedPeers, name)
		delete(a.relayGracePeers, name)
		fmt.Printf("[ice] peer %s: relay proxy moved to standby (grace complete)\n", name)
	}
}

// evaluateICECheck examines WireGuard handshake stats to determine whether
// a connectivity probe succeeded. Handles both passive and active probes.
//
// Passive probe flow (zero disruption):
//  1. startPassiveProbe: marks peer, WG endpoint unchanged (relay continues).
//  2. evaluateICECheck: checks if WG kernel learned a non-localhost endpoint
//     (the peer initiated a direct handshake from their side).
//  3. If detected → upgrade. If not after 60s → escalate to active probe.
//
// Active probe flow (brief disruption):
//  1. probeDirectEndpoint: ForceEndpoint=true, WG switches to direct.
//  2. evaluateICECheck: waits 35s, checks handshake stats.
func (a *Agent) evaluateICECheck(ctx context.Context, peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) {

	state := a.getICEState(peer.Name)

	// --- Passive probe evaluation ---
	if passiveStart, ok := a.passiveProbing[peer.Name]; ok {
		s, hasStats := stats[peer.Spec.PublicKey]

		// Check if WG learned a non-localhost endpoint (peer initiated direct).
		if hasStats && !s.LastHandshake.IsZero() &&
			time.Since(s.LastHandshake) < a.handshakeValidWindow &&
			s.ActualEndpoint != "" && !isLocalhostEndpoint(s.ActualEndpoint) {

			delete(a.passiveProbing, peer.Name)
			fmt.Printf("[ice] peer %s: passive probe detected direct path (%s)\n", peer.Name, s.ActualEndpoint)
			a.upgradeToDirect(peer, "")
			state.State = iceStateConnected
			a.setICEState(peer.Name, state)
			return
		}

		if time.Since(passiveStart) > passiveProbeTimeout {
			delete(a.passiveProbing, peer.Name)
			fmt.Printf("[ice] peer %s: passive probe timed out, escalating to active probe\n", peer.Name)
			a.probeDirectEndpoint(peer)
			state.LastCheck = time.Now()
			state.directProbeApplied = false
			a.setICEState(peer.Name, state)
		}
		return
	}

	// --- Active probe evaluation (two-phase, zero disruption) ---
	if a.directProbing[peer.Name] {
		if time.Since(state.LastCheck) < activeProbeWait {
			return
		}

		s, ok := stats[peer.Spec.PublicKey]

		// Decode pubkey for relay handshake tracking.
		var pubKey [32]byte
		hasPubKey := false
		if keyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey); err == nil && len(keyBytes) == 32 {
			copy(pubKey[:], keyBytes)
			hasPubKey = true
		}

		// Phase 1: check for a fresh WG handshake that completed after the probe
		// started. Relay stays fully active — zero traffic disruption.
		freshHandshake := ok && !s.LastHandshake.IsZero() &&
			s.LastHandshake.After(state.ProbeStartHandshake)

		delete(a.directProbing, peer.Name)
		delete(a.probeForced, peer.Name)

		// Helper to resume relay delivery if it was pre-suspended in startICECheck.
		resumeRelayDelivery := func(flush bool) {
			if state.relaySuspendedForProbe && hasPubKey && a.relayPool != nil {
				a.relayPool.ResumeDelivery(pubKey, flush)
				state.relaySuspendedForProbe = false
			}
		}

		// When relay was pre-suspended during the probe, WG's keepalive (1s
		// interval from ForceEndpoint poke) was sent to the direct endpoint.
		// If the peer responded, WG updated ActualEndpoint to the direct IP.
		// A full WG re-handshake may NOT have happened (session still valid),
		// so freshHandshake can be false even though direct works. In this
		// case, use ActualEndpoint alone to determine direct connectivity.
		if state.relaySuspendedForProbe && ok &&
			s.ActualEndpoint != "" && !isLocalhostEndpoint(s.ActualEndpoint) {
			resumeRelayDelivery(false)
			discoveredEp := s.ActualEndpoint
			state.ProbeFailCount = 0
			fmt.Printf("[ice] peer %s: active probe succeeded via endpoint check (discovered=%s)\n", peer.Name, discoveredEp)
			if peer.Status.NATType == "symmetric" && discoveredEp != "" {
				a.directEndpoints[peer.Name] = discoveredEp
			}
			a.upgradeToDirect(peer, "")
			state.State = iceStateConnected
			a.setICEState(peer.Name, state)
			return
		}

		if freshHandshake {
			// Phase 2: distinguish direct vs relay-mediated handshake.
			//
			// Strategy: First check if the relay proxy delivered any WG handshake
			// packets after the probe started. If not, the handshake was direct.
			//
			// If the relay DID deliver packets (common when relay is concurrently
			// active after a revertToRelay), use a brief micro-suspension (200ms)
			// to let WG settle and check ActualEndpoint. This handles the case
			// where both relay and direct paths delivered handshakes simultaneously.
			directObserved := true
			discoveredEp := ""

			relayDeliveredSinceProbe := false
			if hasPubKey && a.relayPool != nil {
				lastRelayHS := a.relayPool.LastRelayHandshake(pubKey)
				relayDeliveredSinceProbe = !lastRelayHS.IsZero() && lastRelayHS.After(state.ProbeStartHandshake)
			}

			if relayDeliveredSinceProbe {
				// Relay was active during probe — both paths may have delivered
				// handshakes. Briefly suspend relay to isolate the direct signal.
				if hasPubKey && a.relayPool != nil {
					a.relayPool.SuspendDelivery(pubKey)
					time.Sleep(200 * time.Millisecond)
					freshStats, err := a.wgMgr.GetStats()
					if err == nil {
						for _, fs := range freshStats {
							if fs.PublicKeyB64 == peer.Spec.PublicKey &&
								fs.ActualEndpoint != "" && !isLocalhostEndpoint(fs.ActualEndpoint) {
								discoveredEp = fs.ActualEndpoint
								break
							}
						}
					}
					if discoveredEp != "" {
						a.relayPool.ResumeDelivery(pubKey, false)
					} else {
						a.relayPool.ResumeDelivery(pubKey, true)
						directObserved = false
					}
				}
			} else {
				// No relay involvement — handshake was direct.
				if s.ActualEndpoint != "" && !isLocalhostEndpoint(s.ActualEndpoint) {
					discoveredEp = s.ActualEndpoint
				}
			}

			if directObserved {
				resumeRelayDelivery(false) // discard buffered relay packets
				state.ProbeFailCount = 0
				fmt.Printf("[ice] peer %s: active probe succeeded (discovered=%s)\n", peer.Name, discoveredEp)
				if peer.Status.NATType == "symmetric" && discoveredEp != "" {
					a.directEndpoints[peer.Name] = discoveredEp
				}
				a.upgradeToDirect(peer, "")
				state.State = iceStateConnected
				a.setICEState(peer.Name, state)
				return
			}

			fmt.Printf("[ice] peer %s: fresh handshake but relay-mediated (lastRelayHS after probe start)\n", peer.Name)
		}

		// Probe failed — resume relay delivery if it was suspended.
		resumeRelayDelivery(true) // flush buffered packets back to WG
		state.ProbeFailCount++
		if a.relayedPeers[peer.Name] || a.directEndpoints[peer.Name] != "" {
			a.enableRelayForPeer(peer)
		}

		if a.detectedNATType == "symmetric" && peer.Status.NATType == "symmetric" && !state.BirthdayTried {
			fmt.Printf("[ice] peer %s: active probe failed, trying birthday attack\n", peer.Name)
			state.State = iceStateBirthday
			state.BirthdayTried = true
			a.setICEState(peer.Name, state)
			go a.runBirthdayAttack(ctx, peer)
			return
		}

		fmt.Printf("[ice] peer %s: active probe failed (failures=%d), reverting to relay\n",
			peer.Name, state.ProbeFailCount)
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		a.setICEState(peer.Name, state)
		return
	}

	if time.Since(state.LastCheck) > iceCheckTimeout {
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		a.setICEState(peer.Name, state)
	}
}

// runBirthdayAttack executes the birthday attack for a symmetric↔symmetric peer pair.
// Runs in a background goroutine.
func (a *Agent) runBirthdayAttack(ctx context.Context, peer *wirekubev1alpha1.WireKubePeer) {
	state := a.getICEState(peer.Name)

	// Get peer's port prediction and public IP.
	peerPP := peer.Status.PortPrediction
	if peerPP == nil || len(peerPP.SamplePorts) == 0 {
		fmt.Printf("[birthday] peer %s: no port prediction data available\n", peer.Name)
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		return
	}

	peerPublicIP := ""
	if peer.Spec.Endpoint != "" {
		host, _, err := net.SplitHostPort(peer.Spec.Endpoint)
		if err == nil {
			peerPublicIP = host
		}
	}
	if peerPublicIP == "" {
		fmt.Printf("[birthday] peer %s: cannot determine public IP\n", peer.Name)
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		return
	}

	// Convert CRD port prediction to nat.PortPrediction and generate candidates.
	pp := nat.PortPrediction{
		BasePort:  int(peerPP.BasePort),
		Increment: int(peerPP.Increment),
		Jitter:    int(peerPP.Jitter),
	}
	for _, p := range peerPP.SamplePorts {
		pp.SamplePorts = append(pp.SamplePorts, int(p))
	}
	candidatePorts := pp.GenerateCandidates(256)

	// Decode public keys for the probe.
	var myPubKey, peerPubKey [32]byte
	myKeyBytes, err := base64.StdEncoding.DecodeString(a.getOwnPublicKey())
	if err != nil {
		state.State = iceStateFailed
		return
	}
	copy(myPubKey[:], myKeyBytes)

	peerKeyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey)
	if err != nil {
		state.State = iceStateFailed
		return
	}
	copy(peerPubKey[:], peerKeyBytes)

	fmt.Printf("[birthday] peer %s: starting attack (IP=%s, %d candidate ports)\n",
		peer.Name, peerPublicIP, len(candidatePorts))

	result, err := nat.BirthdayAttack(ctx, myPubKey, peerPubKey, peerPublicIP, candidatePorts)
	if err != nil {
		fmt.Printf("[birthday] peer %s: failed: %v\n", peer.Name, err)
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		return
	}

	// Create a hole-punch proxy to bridge WG through the discovered path.
	proxy, err := newHolePunchProxy(result, a.wgMgr.ListenPort())
	if err != nil {
		fmt.Printf("[birthday] peer %s: proxy creation failed: %v\n", peer.Name, err)
		result.LocalConn.Close()
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		return
	}

	go proxy.Run()
	state.holePunch = proxy
	state.State = iceStateConnected
	a.upgradeToDirect(peer, proxy.ListenAddr())
	fmt.Printf("[birthday] peer %s: hole-punched path established via %s\n",
		peer.Name, proxy.ListenAddr())
}

// upgradeToDirect switches a peer from relay to direct transport.
// The relay proxy is kept alive in standby mode (not closed) so that
// failover back to relay is instant if the direct path fails later.
func (a *Agent) upgradeToDirect(peer *wirekubev1alpha1.WireKubePeer, proxyAddr string) {
	delete(a.peerFirstSeen, peer.Name)

	state := a.getICEState(peer.Name)
	state.State = iceStateConnected
	state.FailCount = 0
	state.UpgradedAt = time.Now()
	a.setICEState(peer.Name, state)

	if proxyAddr != "" {
		a.holePunchEndpoints[peer.Name] = proxyAddr
	}

	if a.relayedPeers[peer.Name] {
		a.relayGracePeers[peer.Name] = true
		delete(a.relayedPeers, peer.Name)
		fmt.Printf("[ice] peer %s: upgraded to direct (relay proxy in standby)\n", peer.Name)
	}
}

// revertToRelay switches a peer back to relay transport.
func (a *Agent) revertToRelay(peer *wirekubev1alpha1.WireKubePeer) {
	state := a.getICEState(peer.Name)
	// Cleanup hole-punch proxy if active.
	if state.holePunch != nil {
		state.holePunch.Close()
		state.holePunch = nil
	}
	delete(a.holePunchEndpoints, peer.Name)
	// Clear pre-warm flag since relay is now being fully activated.
	delete(a.relayPrewarmed, peer.Name)

	state.State = iceStateRelay
	// Set LastCheck far enough in the past so the next sync cycle retries
	// immediately instead of waiting the full relayRetry interval. This is
	// critical for fast relay→direct recovery after transient UDP blockage.
	state.LastCheck = time.Now().Add(-a.relayRetry)
	state.BirthdayTried = false
	a.setICEState(peer.Name, state)

	// Re-enable relay for this peer.
	a.enableRelayForPeer(peer)
}

// prewarmRelayForPeer is retained for compatibility but no longer called
// directly — the new prewarmAllPeerRelays in agent.go handles global standby.

// probeDirectHealth performs an active connectivity check when isDirectConnected
// reports a stale handshake. It pokes WG's keepalive (1s interval) to trigger
// an immediate re-handshake attempt on the current endpoint, then waits briefly
// to see if the handshake succeeds.
//
// This avoids false-positive relay failovers during normal WG REKEY_AFTER_TIME
// (120s) cycles where the re-handshake is simply delayed by a few seconds.
// With this probe, handshakeValidWindow can be set much lower (e.g. 10s for
// tests) without causing flip-flop between direct and relay.
func (a *Agent) probeDirectHealth(peer *wirekubev1alpha1.WireKubePeer) bool {
	state := a.getICEState(peer.Name)

	// Cooldown: skip if a recent probe already confirmed health.
	if !state.LastHealthProbeOK.IsZero() && time.Since(state.LastHealthProbeOK) < a.handshakeValidWindow {
		return true
	}

	fmt.Printf("[ice] peer %s: handshake stale, starting active health probe (timeout=%v)\n",
		peer.Name, a.healthProbeTimeout)

	if err := a.wgMgr.PokeKeepalive(peer.Spec.PublicKey); err != nil {
		fmt.Printf("[ice] peer %s: PokeKeepalive failed: %v\n", peer.Name, err)
		return false
	}

	time.Sleep(a.healthProbeTimeout)

	// Re-fetch WG stats after the probe window.
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		fmt.Printf("[ice] peer %s: GetStats failed after probe: %v\n", peer.Name, err)
		return false
	}
	freshStats := make(map[string]wireguard.PeerStats)
	for _, s := range stats {
		freshStats[s.PublicKeyB64] = s
	}

	s, ok := freshStats[peer.Spec.PublicKey]
	if !ok {
		return false
	}

	// Success: handshake completed during the probe window.
	if !s.LastHandshake.IsZero() && time.Since(s.LastHandshake) < a.healthProbeTimeout+2*time.Second {
		fmt.Printf("[ice] peer %s: health probe succeeded (handshake age=%v)\n",
			peer.Name, time.Since(s.LastHandshake).Round(time.Second))
		state.LastHealthProbeOK = time.Now()
		a.setICEState(peer.Name, state)
		return true
	}

	fmt.Printf("[ice] peer %s: health probe failed (lastHS age=%v, endpoint=%s)\n",
		peer.Name, time.Since(s.LastHandshake).Round(time.Second), s.ActualEndpoint)
	return false
}

// isDirectConnected checks if a peer has a recent handshake via a direct
// (non-localhost) endpoint.
//
// Window selection:
//   - Within directConnectedWindow (5 min) of upgrade: use the longer window
//     to allow WG's first direct re-handshake (REKEY_AFTER_TIME = 3 min).
//   - After the grace period: use handshakeValidWindow (3 min) for faster
//     detection when UDP is blocked after the direct path is established.
func (a *Agent) isDirectConnected(peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) bool {
	s, ok := stats[peer.Spec.PublicKey]
	if !ok {
		fmt.Printf("[ice] peer %s: isDirectConnected=false (peer not in WG stats)\n", peer.Name)
		return false
	}
	if s.LastHandshake.IsZero() {
		fmt.Printf("[ice] peer %s: isDirectConnected=false (no WG handshake yet)\n", peer.Name)
		return false
	}
	// A localhost ActualEndpoint means WG is communicating via relay proxy,
	// not via a direct path. This catches cases where the relay proxy was
	// re-activated (e.g. pre-warmed standby) and WG roamed to it.
	if isLocalhostEndpoint(s.ActualEndpoint) {
		fmt.Printf("[ice] peer %s: isDirectConnected=false (endpoint=%s is localhost/relay)\n",
			peer.Name, s.ActualEndpoint)
		return false
	}

	// Use a longer window right after upgrade to allow WG to complete its
	// first direct re-handshake. Once the grace period expires, tighten the
	// window so UDP failures are detected within ~3 min instead of 5.
	state := a.getICEState(peer.Name)
	window := a.handshakeValidWindow
	if !state.UpgradedAt.IsZero() && time.Since(state.UpgradedAt) < a.directConnectedWindow {
		window = a.directConnectedWindow
	}

	age := time.Since(s.LastHandshake)
	if age >= window {
		fmt.Printf("[ice] peer %s: isDirectConnected=false (lastHS age=%v >= window=%v, endpoint=%s)\n",
			peer.Name, age.Round(time.Second), window, s.ActualEndpoint)
		return false
	}
	return true
}

func isLocalhostEndpoint(ep string) bool {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
