package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Manager manages a WireGuard interface using wgctrl (kernel WireGuard).
type Manager struct {
	ifaceName  string
	listenPort int
	mtu        int
	kp         *KeyPair
	wgClient   *wgctrl.Client
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
	return netlink.LinkSetUp(l)
}

// Configure sets the WireGuard interface's private key and listen port.
func (m *Manager) Configure() error {
	privKey, err := decodeKey(m.kp.PrivateKeyBase64())
	if err != nil {
		return err
	}
	port := m.listenPort
	return m.wgClient.ConfigureDevice(m.ifaceName, wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &port,
	})
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

// SyncPeers replaces all WireGuard peers with the provided list.
func (m *Manager) SyncPeers(peers []PeerConfig) error {
	wgPeers := make([]wgtypes.PeerConfig, 0, len(peers))

	for _, p := range peers {
		pubKey, err := decodeKey(p.PublicKeyB64)
		if err != nil {
			return fmt.Errorf("decoding public key for peer: %w", err)
		}

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

	return m.wgClient.ConfigureDevice(m.ifaceName, wgtypes.Config{
		ReplacePeers: true,
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
		stats = append(stats, PeerStats{
			PublicKeyB64:  base64.StdEncoding.EncodeToString(p.PublicKey[:]),
			LastHandshake: p.LastHandshakeTime,
			BytesReceived: p.ReceiveBytes,
			BytesSent:     p.TransmitBytes,
		})
	}
	return stats, nil
}

// DeleteInterface removes the WireGuard interface.
func (m *Manager) DeleteInterface() error {
	link, err := netlink.LinkByName(m.ifaceName)
	if err != nil {
		return nil // Already gone
	}
	return netlink.LinkDel(link)
}

// AddRoute adds a route for the given CIDR through the WireGuard interface.
// Metric 200 ensures it doesn't conflict with CNI-inserted routes (typically metric 100).
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
		Priority:  200,
	}
	if addErr := netlink.RouteAdd(route); addErr != nil {
		// EEXIST is acceptable — route already there
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

	// Get current routes on the wg interface
	current, err := netlink.RouteList(link, 0 /* AF_UNSPEC = all families */)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}

	// Remove stale routes
	for _, r := range current {
		if r.Dst == nil || r.Priority != 200 {
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
		Priority:  200,
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
	PublicKeyB64  string
	LastHandshake time.Time
	BytesReceived int64
	BytesSent     int64
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
