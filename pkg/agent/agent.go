package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/agent/nat"
	agentrelay "github.com/wirekube/wirekube/pkg/agent/relay"
	relayproto "github.com/wirekube/wirekube/pkg/relay"
	"github.com/wirekube/wirekube/pkg/wireguard"
)

// Agent is the per-node WireKube daemon.
// It manages the WireGuard interface and keeps peers in sync with WireKubePeer CRDs.
//
// Design:
//   - Agent creates/updates its own WireKubePeer (publicKey + endpoint auto-discovered).
//   - AllowedIPs on each WireKubePeer is defined by the user (site-to-site style).
//   - Agent syncs all WireKubePeer CRDs into WireGuard peer config + kernel routes.
//   - No IPAM, no mesh IP assignment, no kubelet modification.
type Agent struct {
	client    client.Client
	wgMgr     *wireguard.Manager
	nodeName  string
	syncEvery time.Duration

	relayPool    *agentrelay.Pool
	relayMode    string
	relayTimeout time.Duration
	relayRetry   time.Duration
	// isSymmetricNAT is set during endpoint discovery when STUN detects
	// endpoint-dependent mapping. When true, relay is preferred for symmetric peers.
	isSymmetricNAT bool
	// detectedNATType stores the exact NAT type detected during STUN discovery.
	detectedNATType string
	// peerFirstSeen tracks when we first observed a peer without handshake,
	// used to decide when to trigger relay fallback.
	peerFirstSeen map[string]time.Time
	// relayedPeers tracks which peers are currently using relay transport.
	relayedPeers map[string]bool
	// directEndpoints stores the original direct endpoint before relay override.
	directEndpoints map[string]string
	// directRetryTime tracks the last time we attempted direct connectivity for a relayed peer.
	directRetryTime map[string]time.Time
	// directProbing tracks peers currently being probed for direct connectivity.
	directProbing map[string]bool
}

// NewAgent creates a new Agent.
func NewAgent(k8sClient client.Client, wgMgr *wireguard.Manager, nodeName string) *Agent {
	return &Agent{
		client:          k8sClient,
		wgMgr:           wgMgr,
		nodeName:        nodeName,
		syncEvery:       30 * time.Second,
		peerFirstSeen:   make(map[string]time.Time),
		relayedPeers:    make(map[string]bool),
		directEndpoints: make(map[string]string),
		directRetryTime: make(map[string]time.Time),
		directProbing:   make(map[string]bool),
	}
}

// Run starts the agent loop. Blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	// Clean up stale interface from previous runs
	_ = a.wgMgr.DeleteInterface()

	if err := a.setup(ctx); err != nil {
		return fmt.Errorf("agent setup: %w", err)
	}
	defer a.cleanup()

	ticker := time.NewTicker(a.syncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.sync(ctx); err != nil {
				fmt.Printf("sync error: %v\n", err)
			}
		}
	}
}

// cleanup removes WireGuard routes and interface on shutdown.
func (a *Agent) cleanup() {
	fmt.Printf("[cleanup] removing routes and WireGuard interface %s\n", a.wgMgr.InterfaceName())
	if a.relayPool != nil {
		a.relayPool.Close()
	}
	if err := a.wgMgr.SyncRoutes(nil); err != nil {
		fmt.Printf("[cleanup] warning: flushing routes: %v\n", err)
	}
	if err := a.wgMgr.DeleteInterface(); err != nil {
		fmt.Printf("[cleanup] warning: deleting interface: %v\n", err)
	}
}

// setup performs one-time initialization:
//  1. Load or generate WireGuard key pair.
//  2. Create the WireGuard interface.
//  3. Discover public endpoint (STUN / cloud metadata / node annotation).
//  4. Create or update this node's WireKubePeer with publicKey + endpoint.
func (a *Agent) setup(ctx context.Context) error {
	kp, err := wireguard.LoadOrGenerate()
	if err != nil {
		return fmt.Errorf("key management: %w", err)
	}

	mesh, err := a.getMesh(ctx)
	if err != nil {
		return err
	}

	// Discover endpoint BEFORE creating WireGuard interface.
	// STUN needs to bind the listen port, which WireGuard will claim.
	node := &corev1.Node{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, node); err != nil {
		return fmt.Errorf("getting node: %w", err)
	}
	epResult, err := DiscoverEndpoint(ctx, node, int(mesh.Spec.ListenPort), mesh.Spec.STUNServers)
	if err != nil {
		fmt.Printf("warning: endpoint discovery failed: %v\n", err)
	}
	if epResult != nil {
		a.detectedNATType = string(epResult.NATType)
		if epResult.NATType == nat.NATSymmetric {
			a.isSymmetricNAT = true
			fmt.Printf("[setup] symmetric NAT detected — relay for symmetric peers, direct for cone/public peers\n")
		} else if epResult.NATType == nat.NATCone {
			fmt.Printf("[setup] cone NAT detected — direct P2P for all peers\n")
		}
	}

	if err := a.wgMgr.EnsureInterface(); err != nil {
		return fmt.Errorf("creating WireGuard interface: %w", err)
	}
	if err := a.wgMgr.Configure(); err != nil {
		return fmt.Errorf("configuring WireGuard interface: %w", err)
	}

	// Upsert our WireKubePeer
	peerName := "node-" + a.nodeName
	if err := a.upsertOwnPeer(ctx, peerName, kp.PublicKeyBase64(), epResult); err != nil {
		return fmt.Errorf("upserting own peer: %w", err)
	}

	// Initialize relay client if configured
	if err := a.initRelay(ctx, mesh, kp.PublicKeyBase64()); err != nil {
		fmt.Printf("warning: relay init failed (will retry): %v\n", err)
	}

	// Initial sync
	return a.sync(ctx)
}

// upsertOwnPeer creates or updates this node's WireKubePeer with publicKey and endpoint.
// AllowedIPs is intentionally NOT set here — the user defines it.
func (a *Agent) upsertOwnPeer(ctx context.Context, name, pubKey string, ep *EndpointResult) error {
	existing := &wirekubev1alpha1.WireKubePeer{}
	err := a.client.Get(ctx, client.ObjectKey{Name: name}, existing)

	endpoint := ""
	method := ""
	if ep != nil {
		endpoint = ep.Endpoint
		method = string(ep.Method)
	}

	if apierrors.IsNotFound(err) {
		peer := &wirekubev1alpha1.WireKubePeer{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"wirekube.io/node": a.nodeName,
				},
			},
			Spec: wirekubev1alpha1.WireKubePeerSpec{
				PublicKey:           pubKey,
				Endpoint:            endpoint,
				PersistentKeepalive: 25,
			},
		}
		if createErr := a.client.Create(ctx, peer); createErr != nil && !apierrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("creating own WireKubePeer: %w", createErr)
		}
		if method != "" {
			_ = a.updateDiscoveryMethod(ctx, name, method)
		}
		return nil
	}
	if err != nil {
		return err
	}

	// Update publicKey and endpoint (preserve AllowedIPs set by user)
	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec.PublicKey = pubKey
	if endpoint != "" {
		existing.Spec.Endpoint = endpoint
	}
	if patchErr := a.client.Patch(ctx, existing, patch); patchErr != nil {
		return fmt.Errorf("patching own WireKubePeer: %w", patchErr)
	}
	if method != "" {
		_ = a.updateDiscoveryMethod(ctx, name, method)
	}
	return nil
}

func (a *Agent) updateDiscoveryMethod(ctx context.Context, name, method string) error {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: name}, peer); err != nil {
		return err
	}
	patch := client.MergeFrom(peer.DeepCopy())
	peer.Status.EndpointDiscoveryMethod = method
	if a.detectedNATType != "" {
		peer.Status.NATType = a.detectedNATType
	}
	return a.client.Status().Patch(ctx, peer, patch)
}

// sync reconciles WireGuard peer config and kernel routes with current WireKubePeer CRDs.
func (a *Agent) sync(ctx context.Context) error {
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := a.client.List(ctx, peerList); err != nil {
		return fmt.Errorf("listing peers: %w", err)
	}

	myPeerName := "node-" + a.nodeName
	wgPeers := make([]wireguard.PeerConfig, 0, len(peerList.Items))
	allRoutes := []string{}
	ownAllowedIPsSet := false

	// Build stats map for relay fallback decisions
	statsByKey := make(map[string]wireguard.PeerStats)
	if a.relayPool != nil {
		if stats, err := a.wgMgr.GetStats(); err == nil {
			for _, s := range stats {
				statsByKey[s.PublicKeyB64] = s
			}
		}
	}

	remotePeerNames := []string{}

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == myPeerName {
			if len(p.Spec.AllowedIPs) > 0 {
				ownAllowedIPsSet = true
				ip, _, _ := net.ParseCIDR(p.Spec.AllowedIPs[0])
				if ip != nil {
					a.wgMgr.SetPreferredSrc(ip.String())
				}
			}
			continue
		}
		if p.Spec.PublicKey == "" {
			continue
		}

		endpoint := a.resolveEndpointForPeer(p, statsByKey)
		remotePeerNames = append(remotePeerNames, p.Name)

		wgPeers = append(wgPeers, wireguard.PeerConfig{
			PublicKeyB64:     p.Spec.PublicKey,
			Endpoint:         endpoint,
			AllowedIPs:       p.Spec.AllowedIPs,
			KeepaliveSeconds: int(p.Spec.PersistentKeepalive),
		})

		allRoutes = append(allRoutes, p.Spec.AllowedIPs...)
	}

	// When own allowedIPs is empty, this node has no identity in the mesh.
	// Remote peers will drop all packets from us (WG inbound filter).
	// Adding routes would hijack outgoing traffic (including SSH, kubelet)
	// into wire_kube where it gets silently dropped.
	if !ownAllowedIPsSet {
		allRoutes = nil
		a.wgMgr.SetPreferredSrc("")
		fmt.Printf("[sync] own allowedIPs empty — passive mode (handshake only, no routes)\n")
	}

	if err := a.wgMgr.SyncPeers(wgPeers); err != nil {
		return fmt.Errorf("syncing WireGuard peers: %w", err)
	}

	// Sync kernel routes: AllowedIPs → wg interface
	if err := a.wgMgr.SyncRoutes(allRoutes); err != nil {
		return fmt.Errorf("syncing routes: %w", err)
	}

	// Update own peer status
	if err := a.updateOwnStatus(ctx, myPeerName, remotePeerNames); err != nil {
		fmt.Printf("warning: updating own peer status: %v\n", err)
	}

	// Try upgrading relayed peers back to direct when conditions allow.
	a.tryDirectUpgrade(peerList, statsByKey)

	// Reflect NAT-mapped endpoints back to CRDs (only for direct peers)
	a.reflectNATEndpoints(ctx, peerList)

	return nil
}

// reflectNATEndpoints detects when WireGuard has learned a different endpoint
// for a peer (e.g. due to NAT port mapping) and patches the WireKubePeer CRD
// so other nodes also learn the correct endpoint.
// Skips peers using relay transport (their endpoints are local proxy addresses).
func (a *Agent) reflectNATEndpoints(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList) {
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		return
	}

	statsByKey := make(map[string]wireguard.PeerStats, len(stats))
	for _, s := range stats {
		statsByKey[s.PublicKeyB64] = s
	}

	for i := range peerList.Items {
		p := &peerList.Items[i]

		if a.relayedPeers[p.Name] {
			continue
		}

		s, ok := statsByKey[p.Spec.PublicKey]
		if !ok || s.ActualEndpoint == "" {
			continue
		}
		if time.Since(s.LastHandshake) > 3*time.Minute {
			continue
		}
		if s.ActualEndpoint == p.Spec.Endpoint {
			continue
		}
		if len(s.ActualEndpoint) > 10 && s.ActualEndpoint[:10] == "127.0.0.1:" {
			continue
		}

		crdHost, _, crdErr := net.SplitHostPort(p.Spec.Endpoint)
		actualHost, _, actualErr := net.SplitHostPort(s.ActualEndpoint)
		if crdErr == nil && actualErr == nil {
			// Same IP, different port → skip (Symmetric NAT flapping prevention)
			if crdHost == actualHost {
				continue
			}
			// Never downgrade a public IP to a private IP. The kernel may hold
			// a stale private endpoint from before the peer switched to relay.
			actualIP := net.ParseIP(actualHost)
			crdIP := net.ParseIP(crdHost)
			if actualIP != nil && crdIP != nil && !crdIP.IsPrivate() && actualIP.IsPrivate() {
				continue
			}
		}

		fmt.Printf("[nat-reflect] peer %s: CRD=%s actual=%s → patching\n",
			p.Name, p.Spec.Endpoint, s.ActualEndpoint)
		patch := client.MergeFrom(p.DeepCopy())
		p.Spec.Endpoint = s.ActualEndpoint
		if patchErr := a.client.Patch(ctx, p, patch); patchErr != nil {
			fmt.Printf("[nat-reflect] warning: patching peer %s: %v\n", p.Name, patchErr)
		}
	}
}

// updateOwnStatus reads WireGuard stats and updates this node's WireKubePeer status.
func (a *Agent) updateOwnStatus(ctx context.Context, peerName string, remotePeerNames []string) error {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return err
	}

	stats, err := a.wgMgr.GetStats()
	if err != nil {
		return err
	}

	connected := false
	var totalRx, totalTx int64
	var lastHandshake time.Time
	for _, s := range stats {
		totalRx += s.BytesReceived
		totalTx += s.BytesSent
		if !s.LastHandshake.IsZero() && s.LastHandshake.After(lastHandshake) {
			lastHandshake = s.LastHandshake
		}
		if time.Since(s.LastHandshake) < 3*time.Minute {
			connected = true
		}
	}

	patch := client.MergeFrom(peer.DeepCopy())
	peer.Status.Connected = connected
	peer.Status.BytesReceived = totalRx
	peer.Status.BytesSent = totalTx
	if !lastHandshake.IsZero() {
		t := metav1.NewTime(lastHandshake)
		peer.Status.LastHandshake = &t
	}

	// Build per-peer transport map
	peerTransports := make(map[string]string, len(remotePeerNames))
	relayedCount := 0
	for _, name := range remotePeerNames {
		if a.relayedPeers[name] {
			peerTransports[name] = "relay"
			relayedCount++
		} else {
			peerTransports[name] = "direct"
		}
	}
	peer.Status.PeerTransports = peerTransports

	// Derive aggregate mode from per-peer data
	if relayedCount == 0 {
		peer.Status.TransportMode = "direct"
	} else if len(remotePeerNames) > 0 && relayedCount >= len(remotePeerNames) {
		peer.Status.TransportMode = "relay"
	} else {
		peer.Status.TransportMode = "mixed"
	}
	return a.client.Status().Patch(ctx, peer, patch)
}

// initRelay sets up the relay client from the mesh relay configuration.
func (a *Agent) initRelay(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh, myPubKeyB64 string) error {
	if mesh.Spec.Relay == nil {
		return nil
	}

	relay := mesh.Spec.Relay
	a.relayMode = relay.Mode
	if a.relayMode == "never" {
		return nil
	}

	a.relayTimeout = time.Duration(relay.HandshakeTimeoutSeconds) * time.Second
	if a.relayTimeout == 0 {
		a.relayTimeout = 30 * time.Second
	}
	a.relayRetry = time.Duration(relay.DirectRetryIntervalSeconds) * time.Second
	if a.relayRetry == 0 {
		a.relayRetry = 120 * time.Second
	}

	var endpoint string
	switch relay.Provider {
	case "external":
		if relay.External == nil || relay.External.Endpoint == "" {
			return fmt.Errorf("external relay endpoint not configured")
		}
		endpoint = relay.External.Endpoint
	case "managed":
		port := int32(3478)
		if relay.Managed != nil && relay.Managed.Port != 0 {
			port = relay.Managed.Port
		}
		endpoint = a.discoverManagedRelay(ctx, port)
		if endpoint == "" {
			endpoint = fmt.Sprintf("wirekube-relay.wirekube-system.svc.cluster.local:%d", port)
		}
	default:
		return fmt.Errorf("unknown relay provider: %s", relay.Provider)
	}

	var pubKey [relayproto.PubKeySize]byte
	keyBytes, err := base64.StdEncoding.DecodeString(myPubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding own public key: %w", err)
	}
	copy(pubKey[:], keyBytes)

	a.relayPool = agentrelay.NewPool(endpoint, pubKey, int(mesh.Spec.ListenPort))
	if err := a.relayPool.Connect(ctx); err != nil {
		fmt.Printf("[relay] initial connect to %s failed (will retry in background): %v\n", endpoint, err)
		return nil
	}

	fmt.Printf("[relay] connected to %s (mode=%s)\n", endpoint, a.relayMode)
	return nil
}

// resolveEndpointForPeer determines the effective WireGuard endpoint for a peer,
// applying relay fallback if the peer is unreachable directly.
//
// When a relayed peer is being probed for direct upgrade, this returns the direct
// endpoint temporarily. If the probe succeeds (handshake appears), tryDirectUpgrade
// finalises the switch. Otherwise the next sync reverts to relay.
func (a *Agent) resolveEndpointForPeer(peer *wirekubev1alpha1.WireKubePeer, stats map[string]wireguard.PeerStats) string {
	if a.relayPool == nil || a.relayMode == "never" {
		return peer.Spec.Endpoint
	}

	if a.relayMode == "always" {
		return a.enableRelayForPeer(peer)
	}

	// Symmetric ↔ Symmetric: both sides change ports per destination,
	// direct P2P is impossible → relay immediately.
	if a.isSymmetricNAT && peer.Status.NATType == "symmetric" {
		return a.enableRelayForPeer(peer)
	}

	// If peer is currently being probed for direct upgrade, hand the direct
	// endpoint to WireGuard so it can attempt a handshake.
	if a.directProbing[peer.Name] {
		if ep := a.directEndpoints[peer.Name]; ep != "" {
			return ep
		}
	}

	// auto mode: check handshake freshness
	s, hasStats := stats[peer.Spec.PublicKey]
	hasRecentHandshake := hasStats && !s.LastHandshake.IsZero() && time.Since(s.LastHandshake) < 3*time.Minute

	if hasRecentHandshake {
		if a.relayedPeers[peer.Name] {
			return a.enableRelayForPeer(peer)
		}
		delete(a.peerFirstSeen, peer.Name)
		return peer.Spec.Endpoint
	}

	// No recent handshake
	firstSeen, tracked := a.peerFirstSeen[peer.Name]
	if !tracked {
		a.peerFirstSeen[peer.Name] = time.Now()
		return peer.Spec.Endpoint
	}

	if time.Since(firstSeen) < a.relayTimeout {
		return peer.Spec.Endpoint
	}

	return a.enableRelayForPeer(peer)
}

// tryDirectUpgrade periodically probes whether relayed peers can be reached
// directly again. A successful probe removes the relay proxy and lets WireGuard
// talk to the peer's real endpoint.
//
// Lifecycle per relayed peer:
//  1. Wait relayRetry since last attempt.
//  2. Set directProbing[name] = true → next sync sends WG the direct endpoint.
//  3. On the following sync, check WG stats:
//     - Handshake succeeded on non-proxy endpoint → finalise upgrade.
//     - No handshake or proxy endpoint → cancel probe, resume relay.
func (a *Agent) tryDirectUpgrade(peerList *wirekubev1alpha1.WireKubePeerList, stats map[string]wireguard.PeerStats) {
	if a.relayPool == nil {
		return
	}

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if !a.relayedPeers[p.Name] {
			continue
		}

		// Skip direct probe for Symmetric ↔ Symmetric: neither side has
		// a stable mapped port, so direct P2P is impossible.
		if a.isSymmetricNAT && p.Status.NATType == "symmetric" {
			continue
		}

		// Don't probe peers that are also Symmetric NAT — probing would fail.
		if !a.isSymmetricNAT && p.Status.NATType == "symmetric" {
			continue
		}

		directEp := a.directEndpoints[p.Name]
		if directEp == "" {
			continue
		}

		if a.directProbing[p.Name] {
			// Probe was active since last sync. Evaluate result.
			s, ok := stats[p.Spec.PublicKey]
			probeOK := ok && !s.LastHandshake.IsZero() &&
				time.Since(s.LastHandshake) < 3*time.Minute &&
				s.ActualEndpoint != "" &&
				(len(s.ActualEndpoint) < 10 || s.ActualEndpoint[:10] != "127.0.0.1:")

			delete(a.directProbing, p.Name)

			if probeOK {
				a.disableRelayForPeer(p)
				delete(a.peerFirstSeen, p.Name)
				fmt.Printf("[relay] peer %s: upgraded to direct (%s)\n", p.Name, directEp)
			} else {
				a.directRetryTime[p.Name] = time.Now()
				fmt.Printf("[relay] peer %s: direct probe failed, staying on relay\n", p.Name)
			}
			continue
		}

		// Decide whether to start a new probe.
		lastRetry := a.directRetryTime[p.Name]
		if !lastRetry.IsZero() && time.Since(lastRetry) < a.relayRetry {
			continue
		}

		a.directProbing[p.Name] = true
		fmt.Printf("[relay] peer %s: probing direct endpoint %s\n", p.Name, directEp)
	}
}

func (a *Agent) enableRelayForPeer(peer *wirekubev1alpha1.WireKubePeer) string {
	if a.relayPool == nil {
		return peer.Spec.Endpoint
	}

	if !a.relayPool.IsConnected() {
		return peer.Spec.Endpoint
	}

	var pubKey [relayproto.PubKeySize]byte
	keyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey)
	if err != nil {
		return peer.Spec.Endpoint
	}
	copy(pubKey[:], keyBytes)

	proxy, err := a.relayPool.GetOrCreateProxy(pubKey)
	if err != nil {
		fmt.Printf("[relay] failed to create proxy for %s: %v\n", peer.Name, err)
		return peer.Spec.Endpoint
	}

	if !a.relayedPeers[peer.Name] {
		a.directEndpoints[peer.Name] = peer.Spec.Endpoint
		a.relayedPeers[peer.Name] = true
		fmt.Printf("[relay] peer %s: falling back to relay via %s\n", peer.Name, proxy.ListenAddr())
	}

	return proxy.ListenAddr()
}

func (a *Agent) disableRelayForPeer(peer *wirekubev1alpha1.WireKubePeer) {
	if a.relayPool == nil {
		return
	}

	var pubKey [relayproto.PubKeySize]byte
	keyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey)
	if err != nil {
		return
	}
	copy(pubKey[:], keyBytes)

	a.relayPool.RemoveProxy(pubKey)
	delete(a.relayedPeers, peer.Name)
	delete(a.directEndpoints, peer.Name)
}

// discoverManagedRelay queries the wirekube-relay Service to find an externally
// reachable address. This avoids the chicken-and-egg problem where the ClusterIP
// is only reachable through the CNI — which might not work yet for NAT'd nodes.
//
// Priority: LoadBalancer externalIP → LoadBalancer ingress → NodePort via node public IP → "" (fallback to ClusterIP DNS).
func (a *Agent) discoverManagedRelay(ctx context.Context, port int32) string {
	svc := &corev1.Service{}
	if err := a.client.Get(ctx, client.ObjectKey{
		Name:      "wirekube-relay",
		Namespace: "wirekube-system",
	}, svc); err != nil {
		return ""
	}

	// 1. ExternalIPs (manually configured public IPs)
	for _, ip := range svc.Spec.ExternalIPs {
		parsed := net.ParseIP(ip)
		if parsed != nil && !parsed.IsPrivate() {
			ep := fmt.Sprintf("%s:%d", ip, port)
			fmt.Printf("[relay] using externalIP: %s\n", ep)
			return ep
		}
	}

	// 2. LoadBalancer Ingress (cloud-assigned external IP/hostname)
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			ep := fmt.Sprintf("%s:%d", ing.IP, port)
			fmt.Printf("[relay] using LB ingress IP: %s\n", ep)
			return ep
		}
		if ing.Hostname != "" {
			ep := fmt.Sprintf("%s:%d", ing.Hostname, port)
			fmt.Printf("[relay] using LB ingress hostname: %s\n", ep)
			return ep
		}
	}

	// 3. NodePort — find a cluster node with a public IP and use NodePort
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
		var nodePort int32
		for _, p := range svc.Spec.Ports {
			if p.Port == port && p.NodePort != 0 {
				nodePort = p.NodePort
				break
			}
		}
		if nodePort != 0 {
			nodeList := &corev1.NodeList{}
			if err := a.client.List(ctx, nodeList); err == nil {
				for _, n := range nodeList.Items {
					for _, addr := range n.Status.Addresses {
						if addr.Type == corev1.NodeExternalIP {
							ep := fmt.Sprintf("%s:%d", addr.Address, nodePort)
							fmt.Printf("[relay] using NodePort: %s\n", ep)
							return ep
						}
					}
				}
			}
		}
	}

	return ""
}

func (a *Agent) getMesh(ctx context.Context) (*wirekubev1alpha1.WireKubeMesh, error) {
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if err := a.client.List(ctx, meshList); err != nil {
		return nil, err
	}
	if len(meshList.Items) == 0 {
		return nil, fmt.Errorf("no WireKubeMesh resource found")
	}
	return &meshList.Items[0], nil
}
