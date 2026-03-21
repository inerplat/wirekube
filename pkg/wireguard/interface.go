package wireguard

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Manager manages a WireGuard interface using wgctrl (kernel WireGuard).
type Manager struct {
	ifaceName    string
	listenPort   int
	mtu          int
	kp           *KeyPair
	wgClient     *wgctrl.Client
	preferredSrc net.IP // source IP for routes in the WireKube routing table
	fwmarkClean  bool   // true after first-run duplicate iptables rule cleanup
}

// SetPreferredSrc sets the source IP used when adding routes to the WireGuard routing table.
// This ensures outgoing packets use the node's private IP as source, which must match
// the AllowedIPs filter on the receiving peer's WireGuard interface.
func (m *Manager) SetPreferredSrc(ip string) {
	m.preferredSrc = net.ParseIP(ip)
}

// NewManager creates a new WireGuard interface manager.
func NewManager(ifaceName string, listenPort, mtu int, kp *KeyPair) (*Manager, error) {
	wgc, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("opening wgctrl: %w", err)
	}
	return &Manager{
		ifaceName:  ifaceName,
		listenPort: listenPort,
		mtu:        mtu,
		kp:         kp,
		wgClient:   wgc,
	}, nil
}

// Close releases the wgctrl client.
func (m *Manager) Close() error {
	return m.wgClient.Close()
}

// InterfaceExists checks whether the WireGuard interface already exists.
func (m *Manager) InterfaceExists() bool {
	_, err := netlink.LinkByName(m.ifaceName)
	return err == nil
}

// ConfigMatchesKey returns true if the existing WireGuard interface is
// configured with the same private key as the provided KeyPair.
// Returns false when the interface does not exist or keys differ.
func (m *Manager) ConfigMatchesKey(kp *KeyPair) bool {
	dev, err := m.wgClient.Device(m.ifaceName)
	if err != nil {
		return false
	}
	return base64.StdEncoding.EncodeToString(dev.PrivateKey[:]) == kp.PrivateKeyBase64()
}

// EnsureInterface creates the WireGuard interface if it doesn't exist.
func (m *Manager) EnsureInterface() error {
	if _, err := netlink.LinkByName(m.ifaceName); err == nil {
		return nil // Already exists
	}

	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: m.ifaceName, MTU: m.mtu},
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("creating WireGuard interface %s: %w", m.ifaceName, err)
	}
	l, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}
	// Prevent IPSec/xfrm from intercepting traffic on this interface.
	// Without this, xfrm policies (e.g. site-to-site VPN) can hijack
	// packets routed through wire_kube before WireGuard encrypts them.
	m.disableXfrm()
	// Use loose reverse-path filtering so packets arriving via the WireGuard
	// interface with source IPs from remote pod CIDRs are not dropped.
	// rp_filter=2 (loose): accept if any route exists for the source IP.
	m.setRpFilter()
	// Allow relay proxy to receive WireGuard keepalives on loopback.
	// WireGuard's fwmark routing causes its UDP socket to use the node's
	// physical IP as source even when sending to 127.0.0.1 (proxy port).
	// Linux drops such packets by default (accept_local=0 on lo), so we
	// must enable it to let the proxy socket receive them.
	m.setLoAcceptLocal()
	m.AllowFwmarkLoopback()
	return nil
}

const (
	// Fixed identifiers for WireKube routing, independent of the WireGuard listen port.
	// 0x574B = "WK" in ASCII. Users may change the listen port freely via WireKubeMesh CR.
	wkFwMark     = 0x574B
	wkRouteTable = 0x574B
)

// Configure sets the WireGuard interface's private key, listen port, and fwmark.
// Routing strategy to prevent loops when AllowedIPs overlap with peer endpoints:
//   - WireGuard routes go into a dedicated routing table (not main).
//   - Fwmarked packets (WireGuard socket) → main table (no WG routes, no loop).
//   - All other packets → WireKube table (WG routes apply for tunnel traffic).
func (m *Manager) Configure() error {
	privKey, err := decodeKey(m.kp.PrivateKeyBase64())
	if err != nil {
		return err
	}
	port := m.listenPort
	fwmark := wkFwMark
	if err := m.wgClient.ConfigureDevice(m.ifaceName, wgtypes.Config{
		PrivateKey:   &privKey,
		ListenPort:   &port,
		FirewallMark: &fwmark,
	}); err != nil {
		return err
	}
	return m.ensureRoutingRules()
}

// ensureRoutingRules sets up two ip rules:
//  1. fwmark 0x574B → main table: WG socket bypasses tunnel routes
//  2. all → WireKube table (priority 200): normal traffic uses WG tunnel routes
//
// The fwmark rule priority is placed AFTER the kernel's local routing table
// rule to ensure packets to 127.0.0.0/8 (relay proxy) are delivered via
// loopback rather than the main table's default route. Some CNIs (notably
// Cilium) move the local table from its default priority 0 to higher values
// like 100; we detect the current local table priority and place our rule
// 10 positions after it (minimum 110).
func (m *Manager) ensureRoutingRules() error {
	fwPrio := m.fwmarkRulePriority()

	// Migrate: remove stale fwmark rule at the old hard-coded priority 100.
	if fwPrio != 100 {
		old := netlink.NewRule()
		old.Mark = wkFwMark
		old.Table = 254
		old.Priority = 100
		_ = netlink.RuleDel(old)
	}

	fwRule := netlink.NewRule()
	fwRule.Mark = wkFwMark
	fwRule.Table = 254
	fwRule.Priority = fwPrio
	if !m.ruleExists(fwRule) {
		if err := netlink.RuleAdd(fwRule); err != nil {
			return fmt.Errorf("adding fwmark rule: %w", err)
		}
	}

	wgRule := netlink.NewRule()
	wgRule.Table = wkRouteTable
	wgRule.Priority = 200
	if !m.ruleExists(wgRule) {
		if err := netlink.RuleAdd(wgRule); err != nil {
			return fmt.Errorf("adding wg table rule: %w", err)
		}
	}
	return nil
}

// fwmarkRulePriority returns the ip rule priority for the fwmark rule.
// It must be AFTER the local routing table rule so that packets to loopback
// (127.0.0.0/8) are routed via lo before the fwmark rule can send them to
// the main table's default route. Returns max(localPriority+10, 110),
// capped below the WireKube table rule at 200.
func (m *Manager) fwmarkRulePriority() int {
	localPrio := 0
	rules, _ := netlink.RuleList(syscall.AF_INET)
	for _, r := range rules {
		if r.Table == 255 && r.Priority > localPrio {
			localPrio = r.Priority
		}
	}
	prio := localPrio + 10
	if prio < 110 {
		prio = 110
	}
	if prio >= 200 {
		prio = 199
	}
	return prio
}

func (m *Manager) ruleExists(target *netlink.Rule) bool {
	rules, _ := netlink.RuleList(syscall.AF_INET)
	for _, r := range rules {
		if r.Mark == target.Mark && r.Table == target.Table && r.Priority == target.Priority {
			return true
		}
	}
	return false
}

// SetAddress assigns the mesh IP to the WireGuard interface.
func (m *Manager) SetAddress(meshIP string) error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", m.ifaceName, err)
	}
	ip, ipnet, err := net.ParseCIDR(meshIP)
	if err != nil {
		return fmt.Errorf("parsing mesh IP %s: %w", meshIP, err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: ipnet.Mask}}

	addrs, _ := netlink.AddrList(link, syscall.AF_INET)
	for _, a := range addrs {
		if a.IP.Equal(ip) {
			return nil
		}
	}
	return netlink.AddrAdd(link, addr)
}

// InterfaceName returns the WireGuard interface name.
func (m *Manager) InterfaceName() string {
	return m.ifaceName
}

// ListenPort returns the WireGuard UDP listen port.
func (m *Manager) ListenPort() int {
	return m.listenPort
}

// SyncPeers incrementally updates WireGuard peers.
// It preserves dynamically learned NAT endpoints for peers with recent handshakes
// to avoid disrupting active NAT traversal sessions.
func (m *Manager) SyncPeers(peers []PeerConfig) error {
	dev, err := m.wgClient.Device(m.ifaceName)
	if err != nil {
		return fmt.Errorf("reading device state: %w", err)
	}

	// Build a lookup of current active peers by public key
	activePeers := make(map[wgtypes.Key]wgtypes.Peer, len(dev.Peers))
	for _, p := range dev.Peers {
		activePeers[p.PublicKey] = p
	}

	// Build desired peer set
	desiredKeys := make(map[wgtypes.Key]struct{}, len(peers))
	wgPeers := make([]wgtypes.PeerConfig, 0, len(peers))

	for _, p := range peers {
		pubKey, err := decodeKey(p.PublicKeyB64)
		if err != nil {
			return fmt.Errorf("decoding public key for peer: %w", err)
		}
		desiredKeys[pubKey] = struct{}{}

		allowedIPs, err := parseAllowedIPs(p.AllowedIPs)
		if err != nil {
			return err
		}

		var endpoint *net.UDPAddr
		if p.Endpoint != "" {
			endpoint, err = net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return fmt.Errorf("resolving endpoint %s: %w", p.Endpoint, err)
			}
		}

		// If peer has a recent handshake, preserve the WG-learned endpoint
		// to avoid overwriting NAT-mapped addresses.
		// Exception: ForceEndpoint overrides this for ICE probing.
		if !p.ForceEndpoint {
			if existing, ok := activePeers[pubKey]; ok {
				if time.Since(existing.LastHandshakeTime) < 3*time.Minute && existing.Endpoint != nil {
					endpoint = existing.Endpoint
				}
			}
		}

		pc := wgtypes.PeerConfig{
			PublicKey:         pubKey,
			Endpoint:          endpoint,
			AllowedIPs:        allowedIPs,
			ReplaceAllowedIPs: true,
		}
		if p.KeepaliveSeconds > 0 {
			d := time.Duration(p.KeepaliveSeconds) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		wgPeers = append(wgPeers, pc)
	}

	// Remove peers no longer desired
	for key := range activePeers {
		if _, ok := desiredKeys[key]; !ok {
			wgPeers = append(wgPeers, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})
		}
	}

	return m.wgClient.ConfigureDevice(m.ifaceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        wgPeers,
	})
}

// ForceEndpoint immediately updates a single peer's endpoint in the WG
// kernel interface, bypassing the full SyncPeers cycle. Used by ICE probing
// to switch a peer from relay (localhost) to direct before the next sync.
//
// Also temporarily sets PersistentKeepaliveInterval to 1s so that WG sends
// a keepalive/handshake to the new endpoint within 1 second. Without this,
// WG reuses the existing session and waits up to the configured keepalive
// interval (25s) before sending any packet to the new endpoint, which
// exceeds the 8s probe window. The normal SyncPeers on the next cycle
// restores the original keepalive interval.
func (m *Manager) ForceEndpoint(pubKeyB64 string, endpoint string) error {
	pubKey, err := decodeKey(pubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	ep, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("resolving endpoint %s: %w", endpoint, err)
	}
	pokeKeepalive := 1 * time.Second
	return m.wgClient.ConfigureDevice(m.ifaceName, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   pubKey,
			UpdateOnly:                  true,
			Endpoint:                    ep,
			ReplaceAllowedIPs:           false,
			PersistentKeepaliveInterval: &pokeKeepalive,
		}},
	})
}

// PokeKeepalive temporarily sets PersistentKeepaliveInterval to 1s
// to trigger an immediate outgoing WG packet without changing the endpoint.
// If REKEY_AFTER_TIME has passed, this forces WG to initiate a re-handshake
// on the current endpoint. The normal SyncPeers on the next cycle restores
// the original keepalive interval.
func (m *Manager) PokeKeepalive(pubKeyB64 string) error {
	pubKey, err := decodeKey(pubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	pokeInterval := 1 * time.Second
	return m.wgClient.ConfigureDevice(m.ifaceName, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   pubKey,
			UpdateOnly:                  true,
			ReplaceAllowedIPs:           false,
			PersistentKeepaliveInterval: &pokeInterval,
		}},
	})
}

// GetStats returns per-peer handshake and byte statistics.
func (m *Manager) GetStats() ([]PeerStats, error) {
	dev, err := m.wgClient.Device(m.ifaceName)
	if err != nil {
		return nil, err
	}
	stats := make([]PeerStats, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		ps := PeerStats{
			PublicKeyB64:  base64.StdEncoding.EncodeToString(p.PublicKey[:]),
			LastHandshake: p.LastHandshakeTime,
			BytesReceived: p.ReceiveBytes,
			BytesSent:     p.TransmitBytes,
		}
		if p.Endpoint != nil {
			ps.ActualEndpoint = p.Endpoint.String()
		}
		stats = append(stats, ps)
	}
	return stats, nil
}

// DeleteInterface removes the WireGuard interface and associated routing rules.
func (m *Manager) DeleteInterface() error {
	m.removeRoutingRules()
	m.removeFwmarkLoopback()
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return nil // Already gone
	}
	return netlink.LinkDel(link)
}

func (m *Manager) removeFwmarkLoopback() {
	mark := fmt.Sprintf("0x%x", wkFwMark)
	args := []string{"-t", "filter", "-D", "KUBE-FIREWALL",
		"-m", "mark", "--mark", mark,
		"-d", "127.0.0.0/8", "-j", "ACCEPT",
		"-m", "comment", "--comment", "wirekube: allow WG relay proxy on loopback"}
	for exec.Command("iptables", args...).Run() == nil {
	}
}

// setRpFilter sets rp_filter=2 (loose mode) on the WireGuard interface.
// Loose reverse-path filtering accepts packets whose source IP is reachable
// via any interface, not just the one the packet arrived on. This is required
// when remote pod CIDRs (e.g. from Cilium hybrid nodes) arrive via the tunnel
// with source IPs that are not in the main routing table of this node.
func (m *Manager) setRpFilter() {
	paths := []string{
		fmt.Sprintf("/host/proc/sys/net/ipv4/conf/%s/rp_filter", m.ifaceName),
		fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", m.ifaceName),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("2"), 0644); err == nil {
			log.Printf("[wireguard] rp_filter=2 set on %s\n", m.ifaceName)
			return
		}
	}
	log.Printf("[wireguard] warning: could not set rp_filter on %s\n", m.ifaceName)
}

// setLoAcceptLocal enables accept_local on the loopback interface so that the
// relay proxy socket can receive WireGuard UDP packets whose source IP is the
// node's physical IP. WireGuard's fwmark routing causes its socket to choose
// the physical IP as source even for loopback-destined packets; without this
// sysctl the kernel silently drops them (local address arriving on wrong iface).
func (m *Manager) setLoAcceptLocal() {
	paths := []string{
		"/host/proc/sys/net/ipv4/conf/lo/accept_local",
		"/proc/sys/net/ipv4/conf/lo/accept_local",
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("1"), 0644); err == nil {
			log.Printf("[wireguard] accept_local=1 set on lo\n")
			return
		}
	}
	log.Printf("[wireguard] warning: could not set accept_local on lo\n")
}

// AllowFwmarkLoopback adds an iptables exception in the KUBE-FIREWALL chain
// so that WireGuard fwmark'd packets can reach the relay proxy on loopback.
// kube-proxy inserts a blanket DROP for non-loopback-source → loopback-dest
// traffic, which catches WireGuard packets because the kernel selects the
// node's physical IP as source even for loopback-destined sends.
// Safe to call repeatedly; exits immediately if the rule already exists.
func (m *Manager) AllowFwmarkLoopback() {
	mark := fmt.Sprintf("0x%x", wkFwMark)
	ruleArgs := []string{
		"-m", "mark", "--mark", mark,
		"-d", "127.0.0.0/8", "-j", "ACCEPT",
		"-m", "comment", "--comment", "wirekube: allow WG relay proxy on loopback",
	}

	if !m.fwmarkClean {
		// First call: purge all duplicates left by older agent versions whose
		// -C check omitted --comment, causing unbounded rule insertions.
		delArgs := append([]string{"-t", "filter", "-D", "KUBE-FIREWALL"}, ruleArgs...)
		for exec.Command("iptables", delArgs...).Run() == nil {
		}
		m.fwmarkClean = true
	} else {
		checkArgs := append([]string{"-t", "filter", "-C", "KUBE-FIREWALL"}, ruleArgs...)
		if exec.Command("iptables", checkArgs...).Run() == nil {
			return
		}
	}

	insArgs := append([]string{"-t", "filter", "-I", "KUBE-FIREWALL", "1"}, ruleArgs...)
	if err := exec.Command("iptables", insArgs...).Run(); err != nil {
		m.fwmarkClean = false
		return
	}
	log.Printf("[wireguard] KUBE-FIREWALL exception added for fwmark %s → loopback\n", mark)
}

func (m *Manager) disableXfrm() {
	// DaemonSet mounts host /proc/sys/net → /host/proc/sys/net.
	// disable_xfrm: prevents outbound xfrm policy matching on this interface.
	// disable_policy: prevents inbound xfrm policy matching (replies would be
	// dropped if an IPSec policy requires ESP for the src/dst CIDR pair).
	for _, sysctl := range []string{"disable_xfrm", "disable_policy"} {
		paths := []string{
			fmt.Sprintf("/host/proc/sys/net/ipv4/conf/%s/%s", m.ifaceName, sysctl),
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/%s", m.ifaceName, sysctl),
		}
		set := false
		for _, path := range paths {
			if err := os.WriteFile(path, []byte("1"), 0644); err == nil {
				set = true
				break
			}
		}
		if !set {
			log.Printf("[wireguard] warning: could not set %s on %s\n", sysctl, m.ifaceName)
		}
	}
	log.Printf("[wireguard] xfrm bypass enabled on %s\n", m.ifaceName)
}

func (m *Manager) removeRoutingRules() {
	// Remove fwmark rule at the dynamically chosen priority and the legacy 100.
	for _, prio := range []int{m.fwmarkRulePriority(), 100} {
		fwRule := netlink.NewRule()
		fwRule.Mark = wkFwMark
		fwRule.Table = 254
		fwRule.Priority = prio
		_ = netlink.RuleDel(fwRule)
	}

	wgRule := netlink.NewRule()
	wgRule.Table = wkRouteTable
	wgRule.Priority = 200
	_ = netlink.RuleDel(wgRule)
}

// AddRoute adds a route for the given CIDR through the WireGuard interface
// in the WireKube routing table. This keeps WG routes out of the main table
// so fwmarked WG socket packets bypass them.
func (m *Manager) AddRoute(dst string) error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", m.ifaceName, err)
	}
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		return fmt.Errorf("parsing dst CIDR %s: %w", dst, err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipnet,
		Table:     wkRouteTable,
		Src:       m.preferredSrc,
	}
	if addErr := netlink.RouteAdd(route); addErr != nil {
		if isRouteExists(addErr) {
			return nil
		}
		return addErr
	}
	return nil
}

// SyncRoutes ensures exactly the given CIDRs are routed through the WireGuard interface.
// Routes present in the kernel but not in desired are removed.
// Routes in desired but not in kernel are added.
// Routes whose preferred source IP changed are replaced.
func (m *Manager) SyncRoutes(desired []string) error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", m.ifaceName, err)
	}

	// Build desired set
	desiredSet := make(map[string]struct{}, len(desired))
	for _, cidr := range desired {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parsing desired CIDR %s: %w", cidr, err)
		}
		desiredSet[ipnet.String()] = struct{}{}
	}

	routeFilter := &netlink.Route{Table: wkRouteTable, LinkIndex: link.Attrs().Index}
	current, err := netlink.RouteListFiltered(syscall.AF_INET, routeFilter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}

	for _, r := range current {
		if r.Dst == nil {
			continue
		}
		if _, ok := desiredSet[r.Dst.String()]; !ok {
			_ = netlink.RouteDel(&r)
			continue
		}
		if m.preferredSrc != nil && !m.preferredSrc.Equal(r.Src) {
			_ = netlink.RouteDel(&r)
		}
	}

	// Add missing routes (including those just deleted for src mismatch)
	for _, cidr := range desired {
		if err := m.AddRoute(cidr); err != nil {
			log.Printf("warning: adding route %s: %v\n", cidr, err)
		}
	}
	return nil
}

// DelRoute removes a route for the given CIDR through the WireGuard interface.
func (m *Manager) DelRoute(dst string) error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return nil
	}
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		return nil
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipnet,
		Table:     wkRouteTable,
	}
	return netlink.RouteDel(route)
}

// PeerConfig holds the configuration for a single WireGuard peer.
type PeerConfig struct {
	PublicKeyB64     string
	Endpoint         string
	AllowedIPs       []string
	KeepaliveSeconds int
	// ForceEndpoint overrides the NAT-preservation logic in SyncPeers.
	// When true, the configured endpoint is always applied even if the peer
	// has a recent handshake with a different endpoint. Used for ICE probing.
	ForceEndpoint bool
}

// PeerStats holds runtime statistics for a WireGuard peer.
type PeerStats struct {
	PublicKeyB64   string
	LastHandshake  time.Time
	BytesReceived  int64
	BytesSent      int64
	ActualEndpoint string // WireGuard-observed endpoint (may differ from configured due to NAT)
}

func decodeKey(b64 string) (wgtypes.Key, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("base64 decode: %w", err)
	}
	if len(b) != 32 {
		return wgtypes.Key{}, fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	var k wgtypes.Key
	copy(k[:], b)
	return k, nil
}

func parseAllowedIPs(cidrs []string) ([]net.IPNet, error) {
	result := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parsing allowed IP %s: %w", cidr, err)
		}
		result = append(result, *ipnet)
	}
	return result, nil
}

func isRouteExists(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "file exists"
}
