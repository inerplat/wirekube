package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
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

// peerICEState tracks ICE negotiation state for a single peer.
type peerICEState struct {
	State         string
	LastCheck     time.Time
	CheckCount    int
	BirthdayTried bool

	// holePunch holds the result of a successful birthday attack.
	// If non-nil, the UDP proxy is active and WG should use its local address.
	holePunch *holePunchProxy
}

// holePunchProxy bridges WireGuard traffic through a birthday-attack hole-punched path.
type holePunchProxy struct {
	localConn *net.UDPConn // receives from WG (localhost:random → localhost:wgport)
	holeConn  *net.UDPConn // the hole-punched socket
	peerAddr  *net.UDPAddr // peer's NAT-mapped address
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

	return &holePunchProxy{
		localConn: localConn,
		holeConn:  holeResult.LocalConn,
		peerAddr:  holeResult.PeerAddr,
		wgPort:    wgPort,
		stopCh:    make(chan struct{}),
	}, nil
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
		hp.holeConn.WriteToUDP(buf[:n], hp.peerAddr)
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
		// Only accept packets from the peer's known address.
		if !addr.IP.Equal(hp.peerAddr.IP) {
			continue
		}
		// Update peer address if port changes (NAT rebinding).
		hp.peerAddr = addr
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
		name := iface.Name
		// Skip well-known virtual interfaces.
		for _, skip := range []string{"docker", "veth", "cilium", "cni", "flannel", "br-", "virbr", "wg", "wire_kube"} {
			if len(name) >= len(skip) && name[:len(skip)] == skip {
				continue
			}
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
func (a *Agent) runICENegotiation(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList,
	statsByKey map[string]wireguard.PeerStats) {

	if a.relayPool == nil {
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
			// Verify the connection is still healthy.
			if !a.isDirectConnected(p, statsByKey) {
				fmt.Printf("[ice] peer %s: direct connection lost, reverting to relay\n", p.Name)
				a.revertToRelay(p)
			}
			continue

		case iceStateRelay:
			if !a.relayedPeers[p.Name] {
				continue
			}
			// Check if enough time passed since last check to retry.
			if !state.LastCheck.IsZero() && time.Since(state.LastCheck) < a.relayRetry {
				continue
			}
			a.startICECheck(ctx, p, statsByKey)

		case iceStateChecking:
			a.evaluateICECheck(ctx, p, statsByKey)

		case iceStateBirthday:
			// Birthday attack is running in a background goroutine.
			// Check if it completed (holePunch != nil).
			if state.holePunch != nil {
				a.upgradeToDirect(p, state.holePunch.ListenAddr())
			}

		case iceStateFailed:
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
// It evaluates the NAT type combination and decides the optimal strategy.
func (a *Agent) startICECheck(ctx context.Context, peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) {

	state := a.getICEState(peer.Name)
	state.State = iceStateChecking
	state.LastCheck = time.Now()
	state.CheckCount++

	// Same-NAT detection: if the peer's public IP matches ours, use the
	// peer's host candidate (internal LAN IP) for direct communication.
	if a.trySameNATDirect(peer) {
		a.setICEState(peer.Name, state)
		return
	}

	peerNAT := peer.Status.NATType
	myNAT := a.detectedNATType

	// Determine strategy based on NAT type combination.
	switch {
	case myNAT != "symmetric" && peerNAT != "symmetric":
		// Cone ↔ Cone (or Unknown): direct via STUN endpoints, high success rate.
		fmt.Printf("[ice] peer %s: cone↔cone — probing direct endpoint %s\n", peer.Name, peer.Spec.Endpoint)
		a.probeDirectEndpoint(peer)

	case myNAT != "symmetric" && peerNAT == "symmetric":
		// Cone ↔ Symmetric: peer can reach our stable STUN endpoint.
		// We set WG to peer's STUN endpoint — the peer's NAT may allow return traffic
		// if the peer's keepalive packets opened a pinhole to our IP.
		fmt.Printf("[ice] peer %s: cone↔symmetric — probing with our stable endpoint\n", peer.Name)
		a.probeDirectEndpoint(peer)

	case myNAT == "symmetric" && peerNAT != "symmetric":
		// Symmetric ↔ Cone: we can reach peer's stable endpoint.
		fmt.Printf("[ice] peer %s: symmetric↔cone — probing peer's stable endpoint\n", peer.Name)
		a.probeDirectEndpoint(peer)

	case myNAT == "symmetric" && peerNAT == "symmetric":
		// Symmetric ↔ Symmetric: birthday attack is the only option.
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

// probeDirectEndpoint sets the peer's WG endpoint to their direct address
// and lets WireGuard attempt a handshake. Result is evaluated next sync.
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
}

// evaluateICECheck examines the WireGuard handshake stats to determine
// whether a direct connectivity probe succeeded.
//
// Timing: the probe needs at least 2 sync cycles to evaluate:
//   - Cycle 1 (startICECheck): sets directProbing = true
//   - Cycle 2 (first eval): resolveEndpointForPeer returns direct endpoint,
//     WG gets configured, but stats are from BEFORE the config change.
//   - Cycle 3+ (subsequent evals): stats now reflect the direct endpoint.
//
// We use state.LastCheck to ensure we wait at least 35 seconds.
func (a *Agent) evaluateICECheck(ctx context.Context, peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) {

	state := a.getICEState(peer.Name)

	if a.directProbing[peer.Name] {
		// Wait at least 2 sync cycles (35s) before evaluating the probe result.
		// WG needs time to receive the direct endpoint config and attempt a handshake.
		if time.Since(state.LastCheck) < 35*time.Second {
			return
		}

		s, ok := stats[peer.Spec.PublicKey]
		probeOK := ok && !s.LastHandshake.IsZero() &&
			time.Since(s.LastHandshake) < 3*time.Minute &&
			s.ActualEndpoint != "" &&
			!isLocalhostEndpoint(s.ActualEndpoint)

		delete(a.directProbing, peer.Name)

		if probeOK {
			fmt.Printf("[ice] peer %s: direct probe succeeded (%s)\n", peer.Name, s.ActualEndpoint)
			a.upgradeToDirect(peer, "")
			state.State = iceStateConnected
			a.setICEState(peer.Name, state)
			return
		}

		// Probe failed. If both symmetric → try birthday attack.
		if a.detectedNATType == "symmetric" && peer.Status.NATType == "symmetric" && !state.BirthdayTried {
			fmt.Printf("[ice] peer %s: direct probe failed, trying birthday attack\n", peer.Name)
			state.State = iceStateBirthday
			state.BirthdayTried = true
			a.setICEState(peer.Name, state)
			go a.runBirthdayAttack(ctx, peer)
			return
		}

		fmt.Printf("[ice] peer %s: direct probe failed, staying on relay\n", peer.Name)
		state.State = iceStateFailed
		state.LastCheck = time.Now()
		a.setICEState(peer.Name, state)
		return
	}

	// No probe was active — timeout; mark as failed.
	if time.Since(state.LastCheck) > 90*time.Second {
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
func (a *Agent) upgradeToDirect(peer *wirekubev1alpha1.WireKubePeer, proxyAddr string) {
	a.disableRelayForPeer(peer)
	delete(a.peerFirstSeen, peer.Name)

	state := a.getICEState(peer.Name)
	state.State = iceStateConnected
	a.setICEState(peer.Name, state)

	if proxyAddr != "" {
		// Birthday attack: use the hole-punch proxy address.
		a.holePunchEndpoints[peer.Name] = proxyAddr
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

	state.State = iceStateRelay
	state.LastCheck = time.Now()
	state.BirthdayTried = false
	a.setICEState(peer.Name, state)

	// Re-enable relay for this peer.
	a.enableRelayForPeer(peer)
}

// isDirectConnected checks if a peer has a recent non-localhost handshake.
func (a *Agent) isDirectConnected(peer *wirekubev1alpha1.WireKubePeer,
	stats map[string]wireguard.PeerStats) bool {
	s, ok := stats[peer.Spec.PublicKey]
	if !ok {
		return false
	}
	return !s.LastHandshake.IsZero() &&
		time.Since(s.LastHandshake) < 3*time.Minute
}

func isLocalhostEndpoint(ep string) bool {
	return len(ep) >= 10 && ep[:10] == "127.0.0.1:"
}
