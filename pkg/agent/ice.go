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

	"github.com/wirekube/wirekube/pkg/agent/nat"
	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
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
	activeProbeWait             = 8 * time.Second
	passiveProbeTimeout         = 60 * time.Second
	iceCheckTimeout             = 90 * time.Second
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
	directFailoverProbeCooldown  = 15 * time.Second
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

	// ProbeFailCount tracks consecutive ICE probe failures.
	ProbeFailCount int

	// LastHealthProbeOK records the last time an active health probe
	// confirmed the direct connection is alive despite a stale LastHandshake.
	// Used as a cooldown to avoid re-probing every sync cycle.
	LastHealthProbeOK time.Time

	directProbeApplied bool

	// ProbeStartHandshake records the time this ICE check was initiated.
	// evaluateICECheck uses it to detect handshakes that occurred after
	// the probe started.
	ProbeStartHandshake time.Time
	// ProbeStartDirectReceive records the direct-receive watermark captured
	// when an active probe starts. Userspace probes can receive a direct reply
	// before the next sync loop re-anchors LastCheck, so active-probe success
	// must compare against the previous direct-RX snapshot rather than wall time.
	ProbeStartDirectReceive int64

	// NextProbeAfter delays relay->direct reprobes after a direct path failed
	// and we intentionally fell back to relay. This avoids oscillation during
	// active outages where the direct path is still blocked.
	NextProbeAfter time.Time

	// holePunch holds the result of a successful birthday attack.
	// If non-nil, the UDP proxy is active and WG should use its local address.
	holePunch *holePunchProxy
}

// holePunchProxy bridges WireGuard traffic through a birthday-attack hole-punched path.
type holePunchProxy struct {
	localConn *net.UDPConn                // receives from WG (localhost:random → localhost:wgport)
	holeConn  *net.UDPConn                // the hole-punched socket
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
		hp.localConn.SetReadDeadline(time.Now().Add(time.Second)) //nolint:errcheck
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
		hp.holeConn.SetReadDeadline(time.Now().Add(time.Second)) //nolint:errcheck
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
		hp.localConn.Write(buf[:n]) //nolint:errcheck
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
				if a.shouldFastFailToRelay(p, statsByKey) {
					a.log.Info("direct traffic inactive, activating standby relay immediately", "peer", p.Name)
					a.revertToRelay(p)
					a.deferDirectReprobe(p.Name, directFailoverProbeCooldown)
					continue
				}
				// Handshake is stale — but the connection may still be alive
				// (WG re-handshake in progress). Run active health probe before
				// reverting to relay.
				if a.probeDirectHealth(p) {
					continue
				}
				a.log.Info("health probe failed, activating standby relay", "peer", p.Name)
				a.revertToRelay(p)
				a.deferDirectReprobe(p.Name, directFailoverProbeCooldown)
			}
			continue

		case iceStateRelay:
			if !a.relayedPeers[p.Name] {
				continue
			}
			if !state.NextProbeAfter.IsZero() && time.Now().Before(state.NextProbeAfter) {
				continue
			}
			// Fast-track: if we received direct UDP from this relay-pinned
			// peer AFTER the last probe attempt, probe immediately. This
			// breaks the bilateral relay deadlock: when peer A probes us,
			// their direct handshake arrives on our bind even though we
			// virtualize it (LastDirect is still updated). Probing back
			// immediately ensures both sides enter PathWarm
			// simultaneously, allowing direct traffic to flow
			// bidirectionally so both probes succeed.
			if lastDirect := a.wgMgr.LastDirectReceive(p.Spec.PublicKey); lastDirect > 0 &&
				(state.LastCheck.IsZero() || time.Unix(0, lastDirect).After(state.LastCheck)) {
				a.log.Info("direct inbound from relay peer, fast-tracking probe",
					"peer", p.Name, "lastDirect", time.Unix(0, lastDirect).Format(time.RFC3339))
				a.startICECheck(ctx, p, statsByKey)
				continue
			}
			// Use shorter retry interval for early failures to speed up
			// relay→direct recovery after agent restart or transient blockage.
			const maxFastRetries = 3
			retryWait := a.relayRetry
			if state.ProbeFailCount <= maxFastRetries {
				retryWait = a.relayRetry / 3
				if retryWait < 5*time.Second {
					retryWait = 5 * time.Second
				}
			}
			if !state.LastCheck.IsZero() && time.Since(state.LastCheck) < retryWait {
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
			if !state.NextProbeAfter.IsZero() && time.Now().Before(state.NextProbeAfter) {
				continue
			}
			// Use shorter retry for the first few failures to speed up
			// relay→direct recovery (e.g. after agent restart or mode change).
			// After maxFastRetries, fall back to the full relayRetry interval.
			const maxFastRetries = 3
			retryInterval := a.relayRetry
			if state.ProbeFailCount <= maxFastRetries {
				retryInterval = a.relayRetry / 3
				if retryInterval < 5*time.Second {
					retryInterval = 5 * time.Second
				}
			}
			if time.Since(state.LastCheck) >= retryInterval {
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
	state.ProbeStartDirectReceive = a.wgMgr.LastDirectReceive(peer.Spec.PublicKey)

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
		// Same-NAT peers still need the active probe path machinery so WG
		// immediately points at the LAN candidate and the bind enters probing
		// mode. Merely recording the host candidate leaves some environments
		// stuck on relay until a later sync applies the endpoint.
		a.probeDirectEndpoint(peer)
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
		a.log.Info("port-restricted-cone↔symmetric — direct P2P impossible, staying on relay permanently", "peer", peer.Name)
		state.State = iceStateFailed
		a.setICEState(peer.Name, state)
		return
	}

	switch {
	case myNAT != "symmetric" && peerNAT != "symmetric":
		// Cone ↔ Cone: both endpoints are stable. Active probe is safe and fast
		// because the peer can reach us at our stable STUN endpoint simultaneously.
		a.log.V(1).Info("cone↔cone — active probe", "peer", peer.Name, "endpoint", peer.Spec.Endpoint)
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
		// Relay stays fully active while probing so failover remains seamless even
		// when the direct path is impossible.
		a.log.V(1).Info("cone↔symmetric — simultaneous probe (opens NAT filter)", "peer", peer.Name, "endpoint", peer.Spec.Endpoint)
		a.probeDirectEndpoint(peer)

	case myNAT == "symmetric" && peerNAT != "symmetric":
		// Symmetric ↔ Cone: we should probe the peer's stable endpoint.
		a.log.V(1).Info("symmetric↔cone — active probe", "peer", peer.Name, "endpoint", peer.Spec.Endpoint)
		a.probeDirectEndpoint(peer)

	case myNAT == "symmetric" && peerNAT == "symmetric":
		switch {
		case !a.isBirthdayAttackEnabled(peer):
			a.log.Info("symmetric↔symmetric — birthday attack disabled, staying on relay", "peer", peer.Name)
			state.State = iceStateFailed
		case !state.BirthdayTried:
			a.log.Info("symmetric↔symmetric — initiating birthday attack", "peer", peer.Name)
			state.State = iceStateBirthday
			state.BirthdayTried = true
			go a.runBirthdayAttack(ctx, peer)
		default:
			a.log.Info("symmetric↔symmetric — birthday attack already attempted, staying on relay", "peer", peer.Name)
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
		a.log.V(1).Info("same NAT but no host candidate available", "peer", peer.Name, "publicIP", myPublicIP)
		return false
	}

	a.log.Info("same NAT detected — probing via LAN endpoint", "peer", peer.Name, "publicIP", myPublicIP, "lanEndpoint", hostAddr)
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

// probeDirectEndpoint switches WG to the peer's direct endpoint for a
// handshake probe while keeping relay fully active.
//
// Two-phase evaluation (in evaluateICECheck):
//
//	Phase 1: observe fresh WG handshake while application data stays on relay.
//	Phase 2: if direct path confirmed, upgrade traffic to direct.
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
		a.log.Error(err, "ForceEndpoint failed", "peer", peer.Name, "endpoint", directEp)
	}
	// Warm mode: every outgoing packet is duplicated to both UDP and relay.
	// If the direct path works, WireGuard accepts the first copy and discards
	// the second via replay-window dedup; if it doesn't, the relay copy still
	// lands. This collapses the previous Probing/RelayProbe distinction:
	// whether or not the peer has been direct before, we want both legs
	// carrying traffic during the probe so the blackout is zero regardless
	// of which side of the direct path happens to be broken.
	if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, wireguard.PathWarm, directEp); err != nil {
		a.log.Error(err, "SetPeerPath(Warm) failed", "peer", peer.Name)
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
		a.log.Info("relay proxy moved to standby (grace complete)", "peer", name)
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
// Active probe flow (non-disruptive):
//  1. probeDirectEndpoint: ForceEndpoint=true, WG switches to direct.
//  2. evaluateICECheck: waits for the probe window, then accepts success only
//     when a fresh handshake is backed by direct receive evidence.
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
			a.log.Info("passive probe detected direct path", "peer", peer.Name, "endpoint", s.ActualEndpoint)
			a.upgradeToDirect(peer, "")
			state.State = iceStateConnected
			a.setICEState(peer.Name, state)
			return
		}

		if time.Since(passiveStart) > passiveProbeTimeout {
			delete(a.passiveProbing, peer.Name)
			a.log.Info("passive probe timed out, escalating to active probe", "peer", peer.Name)
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
		freshHandshake := ok && !s.LastHandshake.IsZero() &&
			s.LastHandshake.After(state.ProbeStartHandshake)

		delete(a.directProbing, peer.Name)
		delete(a.probeForced, peer.Name)

		if freshHandshake {
			directObserved := false
			discoveredEp := ""
			lastDirect := a.wgMgr.LastDirectReceive(peer.Spec.PublicKey)
			if s.ActualEndpoint != "" && !isLocalhostEndpoint(s.ActualEndpoint) {
				discoveredEp = s.ActualEndpoint
			}
			switch {
			case lastDirect < 0:
				// Kernel engine has no direct-RX signal. A fresh handshake on a
				// non-localhost endpoint remains the best available proof.
				directObserved = discoveredEp != ""
			case lastDirect > 0 && lastDirect > state.ProbeStartDirectReceive:
				directObserved = true
			}

			if directObserved {
				state.ProbeFailCount = 0
				a.log.Info("active probe succeeded", "peer", peer.Name, "discoveredEndpoint", discoveredEp)
				if peer.Status.NATType == "symmetric" && discoveredEp != "" {
					a.directEndpoints[peer.Name] = discoveredEp
				}
				a.upgradeToDirect(peer, "")
				state.State = iceStateConnected
				a.setICEState(peer.Name, state)
				return
			}

			a.log.V(1).Info("fresh handshake observed but no direct traffic proof", "peer", peer.Name, "endpoint", s.ActualEndpoint)
		}

		state.ProbeFailCount++
		if a.relayedPeers[peer.Name] || a.directEndpoints[peer.Name] != "" {
			a.enableRelayForPeer(peer)
		}

		if a.detectedNATType == "symmetric" && peer.Status.NATType == "symmetric" && !state.BirthdayTried {
			a.log.Info("active probe failed, trying birthday attack", "peer", peer.Name)
			state.State = iceStateBirthday
			state.BirthdayTried = true
			a.setICEState(peer.Name, state)
			go a.runBirthdayAttack(ctx, peer)
			return
		}

		a.log.Info("active probe failed, reverting to relay", "peer", peer.Name, "failures", state.ProbeFailCount)
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
		a.log.Info("no port prediction data available", "peer", peer.Name)
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
		a.log.Info("cannot determine public IP for birthday attack", "peer", peer.Name)
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

	a.log.Info("starting birthday attack", "peer", peer.Name, "peerIP", peerPublicIP, "candidatePorts", len(candidatePorts))

	result, err := nat.BirthdayAttack(ctx, myPubKey, peerPubKey, peerPublicIP, candidatePorts)
	if err != nil {
		a.log.Error(err, "birthday attack failed", "peer", peer.Name)
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		return
	}

	// Create a hole-punch proxy to bridge WG through the discovered path.
	proxy, err := newHolePunchProxy(result, a.wgMgr.ListenPort())
	if err != nil {
		a.log.Error(err, "birthday attack proxy creation failed", "peer", peer.Name)
		result.LocalConn.Close()
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		return
	}

	go proxy.Run()
	state.holePunch = proxy
	state.State = iceStateConnected
	a.upgradeToDirect(peer, proxy.ListenAddr())
	a.log.Info("hole-punched path established", "peer", peer.Name, "proxyAddr", proxy.ListenAddr())
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
	state.NextProbeAfter = time.Time{}
	a.setICEState(peer.Name, state)

	if proxyAddr != "" {
		a.holePunchEndpoints[peer.Name] = proxyAddr
	}

	// Notify the engine that this peer's path is now direct.
	directAddr := a.directEndpoints[peer.Name]
	if proxyAddr != "" {
		directAddr = proxyAddr
	}
	if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, wireguard.PathDirect, directAddr); err != nil {
		a.log.Error(err, "SetPeerPath(Direct) failed", "peer", peer.Name)
	}
	a.log.V(1).Info("SetPeerPath(Direct) applied", "peer", peer.Name, "directAddr", directAddr, "wasRelayed", a.relayedPeers[peer.Name])

	if a.relayedPeers[peer.Name] {
		a.relayGracePeers[peer.Name] = true
		delete(a.relayedPeers, peer.Name)
		a.log.Info("upgraded to direct (relay proxy in standby)", "peer", peer.Name)
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

	// Notify the engine that this peer's path is now relay.
	if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, wireguard.PathRelay, ""); err != nil {
		a.log.Error(err, "SetPeerPath(Relay) failed", "peer", peer.Name)
	}
	a.log.V(1).Info("SetPeerPath(Relay) applied", "peer", peer.Name, "directAddr", a.directEndpoints[peer.Name])

	// Re-enable relay for this peer.
	a.enableRelayForPeer(peer)

	// Trigger an immediate relay-side keepalive/handshake so the fallback path
	// is usable before the next application packet arrives. Without this, the
	// first few data packets after direct-path loss can sit behind a fresh relay
	// handshake, stretching the blackout window in userspace failover tests.
	if err := a.wgMgr.PokeKeepalive(peer.Spec.PublicKey); err != nil {
		a.log.Error(err, "PokeKeepalive failed during relay fallback", "peer", peer.Name)
	}
}

func (a *Agent) deferDirectReprobe(peerName string, delay time.Duration) {
	state := a.getICEState(peerName)
	next := time.Now().Add(delay)
	if next.After(state.NextProbeAfter) {
		state.NextProbeAfter = next
		a.setICEState(peerName, state)
	}
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

	a.log.V(1).Info("handshake stale, starting active health probe", "peer", peer.Name, "timeout", a.healthProbeTimeout)

	if err := a.wgMgr.PokeKeepalive(peer.Spec.PublicKey); err != nil {
		a.log.Error(err, "PokeKeepalive failed", "peer", peer.Name)
		return false
	}
	// Probe the direct path while keeping the relay leg live: Warm mode
	// duplicates every packet to both UDP and relay, so data keeps flowing
	// over the relay even if the direct leg is still broken, while any
	// successful direct handshake/traffic during the probe window shows up
	// as fresh DirectHealth.LastSeen evidence.
	if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, wireguard.PathWarm, a.directEndpoints[peer.Name]); err != nil {
		a.log.Error(err, "SetPeerPath(Warm) failed during health probe", "peer", peer.Name)
	}

	probeStartedAt := time.Now()
	time.Sleep(a.healthProbeTimeout)

	// Re-fetch WG stats after the probe window.
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		a.log.Error(err, "GetStats failed after health probe", "peer", peer.Name)
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

	// Success only when the probe observed direct traffic again. A fresh
	// handshake alone is not enough because Warm mode duplicates packets to
	// the relay too, so the tunnel can stay alive via the relay leg even
	// while the direct path is blocked.
	directObserved := a.hasRecentDirectReceive(peer.Spec.PublicKey)
	if !directObserved {
		lastDirect := a.wgMgr.LastDirectReceive(peer.Spec.PublicKey)
		directObserved = lastDirect < 0 &&
			s.ActualEndpoint != "" &&
			!isLocalhostEndpoint(s.ActualEndpoint) &&
			!s.LastHandshake.IsZero() &&
			s.LastHandshake.After(probeStartedAt)
	}

	if directObserved {
		a.log.V(1).Info("health probe succeeded", "peer", peer.Name, "handshakeAge", time.Since(s.LastHandshake).Round(time.Second))
		state.LastHealthProbeOK = time.Now()
		if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, wireguard.PathDirect, a.directEndpoints[peer.Name]); err != nil {
			a.log.Error(err, "SetPeerPath(Direct) failed after health probe", "peer", peer.Name)
		}
		a.setICEState(peer.Name, state)
		return true
	}

	a.log.Info("health probe failed", "peer", peer.Name, "lastHandshakeAge", time.Since(s.LastHandshake).Round(time.Second), "endpoint", s.ActualEndpoint)
	return false
}

func (a *Agent) directHandshakeWindow(state *peerICEState, s wireguard.PeerStats) time.Duration {
	window := a.handshakeValidWindow
	if !state.UpgradedAt.IsZero() && time.Since(state.UpgradedAt) < a.directConnectedWindow {
		return a.directConnectedWindow
	}

	// Preserved-interface restart recovery has no direct-RX history yet, but the
	// surviving WG session can remain healthy until the next normal re-handshake.
	// Keep the legacy 3-minute handshake window in this specific state even when
	// tests tighten handshakeValidWindow to 10s for faster steady-state failover.
	if a.wasInterfacePreserved &&
		state.State == iceStateConnected &&
		state.UpgradedAt.IsZero() &&
		s.ActualEndpoint != "" &&
		!isLocalhostEndpoint(s.ActualEndpoint) &&
		window < defaultHandshakeValidWindow {
		return defaultHandshakeValidWindow
	}

	return window
}

// hasUsableWireGuardPath reports whether the peer currently has any usable WG
// transport path. A fresh handshake is enough even when the endpoint has roamed
// to the local relay proxy, because relay-assisted traffic is still keeping the
// tunnel alive.
//
// Window selection:
//   - Recent direct data-plane traffic keeps the path alive even when the
//     most recent WireGuard handshake is old. This avoids unnecessary relay
//     fallback on long-lived sessions that are actively carrying traffic.
//   - If there is no recent direct traffic, fall back to handshake age:
//     use the longer directConnectedWindow right after upgrade, then tighten
//     to handshakeValidWindow for faster blocked-UDP detection.
func (a *Agent) hasUsableWireGuardPath(peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) bool {
	s, ok := stats[peer.Spec.PublicKey]
	if !ok {
		a.log.V(1).Info("hasUsableWireGuardPath=false (peer not in WG stats)", "peer", peer.Name)
		return false
	}
	if s.LastHandshake.IsZero() {
		a.log.V(1).Info("hasUsableWireGuardPath=false (no WG handshake yet)", "peer", peer.Name)
		return false
	}

	if a.hasRecentDirectReceive(peer.Spec.PublicKey) {
		return true
	}

	state := a.getICEState(peer.Name)
	window := a.directHandshakeWindow(state, s)
	age := time.Since(s.LastHandshake)
	if age >= window {
		a.log.V(1).Info("hasUsableWireGuardPath=false (handshake too old)", "peer", peer.Name,
			"lastHandshakeAge", age.Round(time.Second), "window", window, "endpoint", s.ActualEndpoint)
		return false
	}

	if isLocalhostEndpoint(s.ActualEndpoint) {
		a.log.V(1).Info("hasUsableWireGuardPath=true (relay-assisted, handshake fresh)", "peer", peer.Name,
			"handshakeAge", age.Round(time.Second), "endpoint", s.ActualEndpoint)
	}
	return true
}

// isDirectConnected checks whether the preferred direct path itself is still
// healthy. Relay-assisted handshakes keep the tunnel usable, but they should
// not suppress direct->relay failover when no recent direct traffic has been
// observed.
func (a *Agent) isDirectConnected(peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) bool {
	s, ok := stats[peer.Spec.PublicKey]
	if !ok {
		a.log.V(1).Info("isDirectConnected=false (peer not in WG stats)", "peer", peer.Name)
		return false
	}
	if s.LastHandshake.IsZero() {
		a.log.V(1).Info("isDirectConnected=false (no WG handshake yet)", "peer", peer.Name)
		return false
	}
	state := a.getICEState(peer.Name)

	if a.hasRecentDirectReceive(peer.Spec.PublicKey) {
		return true
	}

	// UserspaceEngine can observe recent direct UDP traffic directly. If that
	// signal exists but has gone quiet, fail over promptly instead of waiting
	// for the longer handshake window to expire while ActualEndpoint still
	// points at the old direct address.
	if lastDirect := a.wgMgr.LastDirectReceive(peer.Spec.PublicKey); lastDirect > 0 {
		if a.peerHadDirectReceiveSinceLastSync(peer.Spec.PublicKey, lastDirect) {
			a.log.V(1).Info("isDirectConnected=true (direct receive observed since last sync)", "peer", peer.Name,
				"lastDirect", time.Unix(0, lastDirect).UTC(), "endpoint", s.ActualEndpoint)
			return true
		}
		if !a.peerHadMeaningfulTrafficSinceLastSync(peer.Spec.PublicKey, s) {
			a.log.V(1).Info("isDirectConnected=true (idle peer, deferring to handshake health)", "peer", peer.Name,
				"endpoint", s.ActualEndpoint)
			goto handshakeFallback
		}
		// Direct traffic was observed but not recently; path has gone quiet.
		a.log.V(1).Info("isDirectConnected=false (recent direct traffic missing)", "peer", peer.Name,
			"window", a.recentDirectReceiveWindow(), "endpoint", s.ActualEndpoint)
		return false
	}

	// A localhost endpoint means WireGuard has roamed to the relay proxy.
	// That may keep the tunnel alive, but it is not evidence that the direct
	// path still works, so direct failover should proceed.
	if isLocalhostEndpoint(s.ActualEndpoint) {
		a.log.V(1).Info("isDirectConnected=false (endpoint is localhost/relay)", "peer", peer.Name, "endpoint", s.ActualEndpoint)
		return false
	}

	// If we've never received a direct packet from this peer, we cannot claim
	// direct connectivity. This handles peers that started in relay mode (or
	// after agent restart) where LastDirectReceive=0. Without this guard, we'd
	// rely only on LastHandshake age, missing OS-level path failures (firewall,
	// iptables blocking) that handshake alone cannot detect.
	if lastDirect := a.wgMgr.LastDirectReceive(peer.Spec.PublicKey); lastDirect == 0 {
		if a.wasInterfacePreserved &&
			state.State == iceStateConnected &&
			!isLocalhostEndpoint(s.ActualEndpoint) {
			if a.peerHadMeaningfulTrafficSinceLastSync(peer.Spec.PublicKey, s) {
				a.log.V(1).Info("isDirectConnected=false (preserved restart missing first direct receive under traffic)",
					"peer", peer.Name, "endpoint", s.ActualEndpoint)
				return false
			}
			a.log.V(1).Info("isDirectConnected=true (preserved restart idle, waiting for first direct receive)",
				"peer", peer.Name, "endpoint", s.ActualEndpoint)
			goto handshakeFallback
		}
		a.log.V(1).Info("isDirectConnected=false (no direct receive ever observed)", "peer", peer.Name, "endpoint", s.ActualEndpoint)
		return false
	}

handshakeFallback:
	window := a.directHandshakeWindow(state, s)
	if !a.peerHadMeaningfulTrafficSinceLastSync(peer.Spec.PublicKey, s) &&
		state.State == iceStateConnected &&
		s.ActualEndpoint != "" &&
		!isLocalhostEndpoint(s.ActualEndpoint) &&
		window < defaultDirectConnectedWindow {
		// Quiet established peers can go longer than handshakeValidWindow
		// without a re-handshake while the direct path is still usable.
		// Keep them on direct unless real data-plane traffic shows the path
		// has actually gone stale.
		window = defaultDirectConnectedWindow
	}
	age := time.Since(s.LastHandshake)
	if age >= window {
		a.log.V(1).Info("isDirectConnected=false (handshake too old)", "peer", peer.Name,
			"lastHandshakeAge", age.Round(time.Second), "window", window, "endpoint", s.ActualEndpoint)
		return false
	}
	return true
}

func (a *Agent) hasRecentDirectReceive(pubKey string) bool {
	lastDirect := a.wgMgr.LastDirectReceive(pubKey)
	if lastDirect <= 0 {
		return false
	}
	age := time.Since(time.Unix(0, lastDirect))
	return age < a.recentDirectReceiveWindow()
}

func (a *Agent) hasRecentRelayReceive(pubKey string) bool {
	lastRelay := a.wgMgr.LastRelayReceive(pubKey)
	if lastRelay <= 0 {
		return false
	}
	age := time.Since(time.Unix(0, lastRelay))
	return age < a.recentDirectReceiveWindow()
}

func (a *Agent) peerHadDirectReceiveSinceLastSync(pubKey string, lastDirect int64) bool {
	prev, ok := a.peerTrafficSnapshots[pubKey]
	if !ok || lastDirect <= 0 {
		return false
	}
	if lastDirect <= prev.lastDirectRX {
		return false
	}
	maxAge := a.syncEvery + a.recentDirectReceiveWindow()
	if maxAge <= 0 {
		maxAge = a.recentDirectReceiveWindow()
	}
	return time.Since(time.Unix(0, lastDirect)) <= maxAge
}

func (a *Agent) shouldFastFailToRelay(peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) bool {
	state := a.getICEState(peer.Name)
	if state.State != iceStateConnected || a.relayedPeers[peer.Name] {
		return false
	}
	s, ok := stats[peer.Spec.PublicKey]
	if !ok {
		return false
	}
	if a.wgMgr.LastDirectReceive(peer.Spec.PublicKey) < 0 {
		return false
	}
	if !a.peerHadMeaningfulTrafficSinceLastSync(peer.Spec.PublicKey, s) {
		return false
	}
	if !a.isDirectConnected(peer, stats) {
		// About to failover to relay. Log if relay is also stale for operator visibility.
		if !a.hasRecentRelayReceive(peer.Spec.PublicKey) {
			if lastRelay := a.wgMgr.LastRelayReceive(peer.Spec.PublicKey); lastRelay > 0 {
				a.log.Info("fast-fail to relay: relay path also appears stale, proceeding anyway",
					"peer", peer.Name,
					"lastRelayAge", time.Since(time.Unix(0, lastRelay)).Round(time.Second))
			}
		}
		return true
	}
	return false
}

func (a *Agent) recentDirectReceiveWindow() time.Duration {
	// Userspace bind emits LastDirectReceive on every direct UDP packet, but the
	// agent only re-evaluates transports once per sync loop. A window shorter
	// than one reconcile interval creates false relay downgrades in otherwise
	// healthy direct sessions whenever there is a brief lull between syncs.
	//
	// Keep the window small enough for prompt failover, but wide enough to span
	// one normal sync interval in CI and production.
	window := 1500 * time.Millisecond
	if a.syncEvery > 0 {
		candidate := a.syncEvery + 500*time.Millisecond
		if candidate > window {
			window = candidate
		}
	}
	if window > 5*time.Second {
		window = 5 * time.Second
	}
	if a.healthProbeTimeout > 0 && a.healthProbeTimeout < window {
		window = a.healthProbeTimeout
	}
	if window < time.Second {
		window = time.Second
	}
	return window
}

func isLocalhostEndpoint(ep string) bool {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
