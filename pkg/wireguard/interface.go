package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
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
//  1. fwmark 0x574B → main table (priority 100): WG socket bypasses tunnel routes
//  2. all → WireKube table (priority 200): normal traffic uses WG tunnel routes
func (m *Manager) ensureRoutingRules() error {
	fwRule := netlink.NewRule()
	fwRule.Mark = wkFwMark
	fwRule.Table = 254
	fwRule.Priority = 100
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
		if existing, ok := activePeers[pubKey]; ok {
			if time.Since(existing.LastHandshakeTime) < 3*time.Minute && existing.Endpoint != nil {
				endpoint = existing.Endpoint
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
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return nil // Already gone
	}
	return netlink.LinkDel(link)
}

func (m *Manager) disableXfrm() {
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/disable_xfrm", m.ifaceName)
	if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
		fmt.Printf("[wireguard] warning: failed to disable xfrm on %s: %v\n", m.ifaceName, err)
	}
}

func (m *Manager) removeRoutingRules() {
	fwRule := netlink.NewRule()
	fwRule.Mark = wkFwMark
	fwRule.Table = 254
	fwRule.Priority = 100
	_ = netlink.RuleDel(fwRule)

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

	// Remove stale routes
	for _, r := range current {
		if r.Dst == nil {
			continue
		}
		if _, ok := desiredSet[r.Dst.String()]; !ok {
			_ = netlink.RouteDel(&r)
		}
	}

	// Add missing routes
	for _, cidr := range desired {
		if err := m.AddRoute(cidr); err != nil {
			fmt.Printf("warning: adding route %s: %v\n", cidr, err)
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
