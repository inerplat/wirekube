//go:build linux

package wireguard

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// UserspaceEngine implements WGEngine using wireguard-go. It creates a TUN
// device and runs the WireGuard protocol entirely in userspace, and installs
// fwmark/routing-table rules (see routes.go) so local WireGuard sockets bypass
// the tunnel while everything else routes through it.
type UserspaceEngine struct {
	ifaceName  string
	listenPort int
	mtu        int
	keyPair    *KeyPair

	tunDev tun.Device
	bind   *WireKubeBind
	wgDev  *device.Device

	preferredSrc net.IP
	linkIndex    int
	log          *device.Logger
}

// NewUserspaceEngine creates a new UserspaceEngine. The engine is not started
// until EnsureInterface and Configure are called.
func NewUserspaceEngine(ifaceName string, listenPort, mtu int, kp *KeyPair) *UserspaceEngine {
	return &UserspaceEngine{
		ifaceName:  ifaceName,
		listenPort: listenPort,
		mtu:        mtu,
		keyPair:    kp,
		// LogLevelError so wireguard-go only emits actual failures. The
		// Verbose level floods the log with per-routine start/stop and
		// per-handshake traces that are useful for protocol debugging but
		// useless in steady state and expensive on busy clusters.
		log: device.NewLogger(device.LogLevelError, "[wirekube-usp] "),
	}
}

// EnsureInterface creates the TUN device and wireguard-go device if they do
// not already exist. If the interface already exists (e.g. after agent restart),
// it reattaches by looking up the link index.
func (u *UserspaceEngine) EnsureInterface() error {
	// If already initialized, just verify the link still exists.
	if u.tunDev != nil {
		if _, err := netlink.LinkByName(u.ifaceName); err == nil {
			return nil
		}
		// TUN disappeared; recreate.
		u.closeDev()
	}

	// Check if an interface with the target name already exists.
	if link, err := netlink.LinkByName(u.ifaceName); err == nil {
		switch link.Type() {
		case "wireguard":
			// Kernel-mode WireGuard interface owned by wgctrl/netlink —
			// a userspace TUN cannot be opened under the same name while
			// this exists. Only this specific link type is ours to delete;
			// it is exclusively created by WireKube's previous kernel
			// engine. Recreate as a fresh userspace TUN below.
			log.Printf("[usp] %s is kernel wireguard link — deleting to migrate to userspace TUN", u.ifaceName)
			if err := netlink.LinkDel(link); err != nil {
				return fmt.Errorf("deleting kernel wireguard link %s: %w", u.ifaceName, err)
			}
		case "tun":
			u.linkIndex = link.Attrs().Index
			return u.attachExistingTUN()
		default:
			// Some foreign interface (veth / bridge / a TUN opened by
			// another process). We do NOT delete it — it does not belong
			// to us, and removing it could disrupt whatever is using it.
			// Surfacing the error lets the operator diagnose the collision
			// and either rename their interface or change
			// WireKubeMesh.spec.interfaceName.
			return fmt.Errorf("interface %s exists with link type %q, refusing to touch foreign link; rename it or set spec.interfaceName",
				u.ifaceName, link.Type())
		}
	}

	// Create a new TUN device.
	tunDev, err := tun.CreateTUN(u.ifaceName, u.mtu)
	if err != nil {
		return fmt.Errorf("creating TUN %s: %w", u.ifaceName, err)
	}
	u.tunDev = tunDev

	// Look up link for routing operations.
	link, err := netlink.LinkByName(u.ifaceName)
	if err != nil {
		u.tunDev.Close()
		u.tunDev = nil
		return fmt.Errorf("looking up TUN %s: %w", u.ifaceName, err)
	}
	u.linkIndex = link.Attrs().Index

	// Apply sysctl settings before bringing up the interface:
	// - rp_filter=2 (loose) so packets from remote subnets are not dropped
	// - xfrm bypass so IPSec policies don't intercept tunnel traffic
	setRpFilterForIface(u.ifaceName)
	disableXfrmForIface(u.ifaceName)

	// Do NOT call LinkSetUp here. wireguard-go's routineHackListener polls
	// the TUN state continuously. If the TUN is already up when NewDevice
	// starts RoutineTUNEventReader, the queued EventUp triggers device.Up()
	// which calls BindUpdate(). Configure()'s IpcSet also calls BindUpdate(),
	// creating a deadlock. Instead, let Configure() bring the device up via
	// IpcSet+Up() after the bind is properly initialized.

	// Create wireguard-go device on the TUN (link stays down until Configure).
	u.bind = NewWireKubeBind()
	u.wgDev = device.NewDevice(u.tunDev, u.bind, u.log)

	return nil
}

// attachExistingTUN reopens an existing TUN device by name and creates a new
// wireguard-go device on it.
func (u *UserspaceEngine) attachExistingTUN() error {
	tunDev, err := tun.CreateTUN(u.ifaceName, u.mtu)
	if err != nil {
		return fmt.Errorf("reattaching TUN %s: %w", u.ifaceName, err)
	}
	u.tunDev = tunDev

	u.bind = NewWireKubeBind()
	u.wgDev = device.NewDevice(u.tunDev, u.bind, u.log)
	return nil
}

// Configure sets the private key, listen port, and fwmark via UAPI, then
// ensures the routing rules are in place.
func (u *UserspaceEngine) Configure() error {
	if u.wgDev == nil {
		return fmt.Errorf("wireguard-go device not initialized; call EnsureInterface first")
	}

	// Set private key first (no BindUpdate triggered because device is Down).
	privKeyHex := keyToHex(u.keyPair.PrivateKeyBase64())
	if err := u.wgDev.IpcSet(fmt.Sprintf("private_key=%s\n", privKeyHex)); err != nil {
		return fmt.Errorf("UAPI set private_key: %w", err)
	}

	// Bring device Up. This calls BindUpdate → Open (starts ReceiveFuncs).
	// The TUN hack listener may also trigger Up concurrently via
	// RoutineTUNEventReader; since we call Up first, the concurrent call
	// sees the device already up and becomes a no-op — no deadlock.
	if err := u.wgDev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}

	// Now set listen_port and fwmark. BindUpdate will close the old bind and
	// reopen with the correct port. No deadlock risk because the device is
	// already up and RoutineTUNEventReader's Up() returns immediately.
	if err := u.wgDev.IpcSet(fmt.Sprintf("listen_port=%d\nfwmark=%d\n",
		u.listenPort, WKFwMark)); err != nil {
		return fmt.Errorf("UAPI set listen_port/fwmark: %w", err)
	}

	// Bring the TUN link up so routes can be added and traffic flows.
	// Safe to call now: the device is fully up and the RoutineTUNEventReader's
	// concurrent Up() is a no-op (device already in Up state).
	link, err := netlink.LinkByName(u.ifaceName)
	if err != nil {
		return fmt.Errorf("looking up TUN for LinkSetUp: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up TUN %s: %w", u.ifaceName, err)
	}

	return EnsureRoutingRules()
}

// DeleteInterface stops the wireguard-go device, removes the TUN, and cleans
// up routing rules.
func (u *UserspaceEngine) DeleteInterface() error {
	RemoveRoutingRules()
	u.closeDev()

	link, err := netlink.LinkByName(u.ifaceName)
	if err != nil {
		return nil // Already gone.
	}
	return netlink.LinkDel(link)
}

// Close shuts down the wireguard-go device without removing the TUN or
// routing rules.
func (u *UserspaceEngine) Close() error {
	u.closeDev()
	return nil
}

func (u *UserspaceEngine) closeDev() {
	if u.wgDev != nil {
		u.wgDev.Close()
		u.wgDev = nil
	}
	if u.tunDev != nil {
		u.tunDev.Close()
		u.tunDev = nil
	}
}

// SyncPeers updates all peers via UAPI. It removes peers not in the desired
// set and adds/updates those that are.
func (u *UserspaceEngine) SyncPeers(peers []PeerConfig) error {
	if u.wgDev == nil {
		return fmt.Errorf("device not initialized")
	}

	// Get current peers to find ones to remove.
	currentKeys, err := u.currentPeerKeys()
	if err != nil {
		return err
	}
	currentHex := make(map[string]bool, len(currentKeys))
	for _, k := range currentKeys {
		currentHex[k] = true
	}

	desiredKeys := make(map[string]struct{}, len(peers))
	var conf strings.Builder

	for _, p := range peers {
		pubHex := keyToHex(p.PublicKeyB64)
		desiredKeys[pubHex] = struct{}{}
		isNew := !currentHex[pubHex]

		fmt.Fprintf(&conf, "public_key=%s\n", pubHex)
		// Preserve wireguard-go's roamed endpoint on established peers; only
		// write endpoint= on initial registration or explicit force.
		if p.Endpoint != "" && (isNew || p.ForceEndpoint) {
			fmt.Fprintf(&conf, "endpoint=%s\n", p.Endpoint)

			if u.bind != nil {
				if addr, err := netip.ParseAddrPort(p.Endpoint); err == nil {
					existing := u.bind.GetPeerPath(p.PublicKeyB64)
					if existing == nil {
						initialMode := PathModeDirect
						if u.bind.relay != nil && u.bind.relay.IsConnected() {
							initialMode = PathModeRelay
						}
						u.bind.SetPeerPath(p.PublicKeyB64, initialMode, addr)
					} else if existing.DirectAddr != addr {
						existing.DirectAddr = addr
						u.bind.addrToPeer.Store(addr.String(), p.PublicKeyB64)
					}
				}
			}
		}
		conf.WriteString("replace_allowed_ips=true\n")
		for _, aip := range p.AllowedIPs {
			fmt.Fprintf(&conf, "allowed_ip=%s\n", aip)
		}
		if p.KeepaliveSeconds > 0 {
			fmt.Fprintf(&conf, "persistent_keepalive_interval=%d\n", p.KeepaliveSeconds)
		}
	}

	// Remove peers not in desired set.
	for _, hexKey := range currentKeys {
		if _, ok := desiredKeys[hexKey]; !ok {
			fmt.Fprintf(&conf, "public_key=%s\nremove=true\n", hexKey)
		}
	}

	if conf.Len() == 0 {
		return nil
	}
	return u.wgDev.IpcSet(conf.String())
}

// ForceEndpoint updates a single peer's endpoint and sets a 1s keepalive to
// trigger an immediate handshake attempt.
func (u *UserspaceEngine) ForceEndpoint(pubKeyB64, endpoint string) error {
	if u.wgDev == nil {
		return fmt.Errorf("device not initialized")
	}
	pubHex := keyToHex(pubKeyB64)
	conf := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\npersistent_keepalive_interval=1\n",
		pubHex, endpoint)
	return u.wgDev.IpcSet(conf)
}

// PokeKeepalive temporarily sets keepalive to 1s to trigger an immediate
// outgoing WG packet without changing the endpoint.
func (u *UserspaceEngine) PokeKeepalive(pubKeyB64 string) error {
	if u.wgDev == nil {
		return fmt.Errorf("device not initialized")
	}
	pubHex := keyToHex(pubKeyB64)
	conf := fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=1\n",
		pubHex)
	return u.wgDev.IpcSet(conf)
}

// GetStats returns per-peer statistics by parsing UAPI IpcGet output.
func (u *UserspaceEngine) GetStats() ([]PeerStats, error) {
	if u.wgDev == nil {
		return nil, fmt.Errorf("device not initialized")
	}
	output, err := u.wgDev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("UAPI get: %w", err)
	}
	stats, err := parseUAPIStats(output)
	if err != nil {
		return nil, err
	}
	// Feed wireguard-go's roamed endpoints into the bind so addrToPeer
	// disambiguates same-NAT peers and stale source-port entries are purged
	// as the NAT mapping drifts.
	if u.bind != nil {
		for _, s := range stats {
			if s.ActualEndpoint == "" || s.PublicKeyB64 == "" {
				continue
			}
			addr, err := netip.ParseAddrPort(s.ActualEndpoint)
			if err != nil {
				continue
			}
			pp := u.bind.GetPeerPath(s.PublicKeyB64)
			if pp == nil {
				continue
			}
			u.bind.updateLearnedAddr(pp, s.PublicKeyB64, addr)
		}
	}
	return stats, nil
}

// SetAddress assigns the mesh IP to the TUN device.
func (u *UserspaceEngine) SetAddress(meshIP string) error {
	link, err := netlink.LinkByName(u.ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", u.ifaceName, err)
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

// SetPreferredSrc stores the source IP for route management.
func (u *UserspaceEngine) SetPreferredSrc(ip string) {
	u.preferredSrc = net.ParseIP(ip)
}

// SyncRoutes delegates to the shared SyncRoutesForLink.
func (u *UserspaceEngine) SyncRoutes(desired []string) error {
	return SyncRoutesForLink(u.linkIndex, u.preferredSrc, desired)
}

// AddRoute delegates to the shared AddRouteForLink.
func (u *UserspaceEngine) AddRoute(dst string) error {
	return AddRouteForLink(u.linkIndex, u.preferredSrc, dst)
}

// DelRoute delegates to the shared DelRouteForLink.
func (u *UserspaceEngine) DelRoute(dst string) error {
	return DelRouteForLink(u.linkIndex, dst)
}

// InterfaceName returns the TUN device name.
func (u *UserspaceEngine) InterfaceName() string {
	return u.ifaceName
}

// ListenPort returns the configured UDP listen port.
func (u *UserspaceEngine) ListenPort() int {
	return u.listenPort
}

// InterfaceExists checks whether the TUN device exists.
func (u *UserspaceEngine) InterfaceExists() bool {
	_, err := netlink.LinkByName(u.ifaceName)
	return err == nil
}

// ConfigMatchesKey returns true if the wireguard-go device is configured with
// the same private key as the provided KeyPair.
func (u *UserspaceEngine) ConfigMatchesKey(kp *KeyPair) bool {
	if u.wgDev == nil {
		return false
	}
	output, err := u.wgDev.IpcGet()
	if err != nil {
		return false
	}
	wantHex := keyToHex(kp.PrivateKeyBase64())
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "private_key=") {
			return strings.TrimPrefix(line, "private_key=") == wantHex
		}
	}
	return false
}

// SetPeerPath updates the Bind's pathTable atomically so that Send routes
// packets according to the requested mode (direct UDP only, warm bimodal
// send, or relay only). No endpoint suspension is needed: the Bind owns
// path selection internally, and wireguard-go itself never needs to know
// which transport a given packet traveled on.
func (u *UserspaceEngine) SetPeerPath(pubKey string, mode PathMode, directAddr string) error {
	if u.bind == nil {
		return nil
	}
	var modeInt int32
	switch mode {
	case PathDirect:
		modeInt = PathModeDirect
	case PathWarm:
		modeInt = PathModeWarm
	case PathRelay:
		modeInt = PathModeRelay
	}

	var addr netip.AddrPort
	if directAddr != "" {
		var err error
		addr, err = netip.ParseAddrPort(directAddr)
		if err != nil {
			return err
		}
	}
	u.bind.SetPeerPath(pubKey, modeInt, addr)
	return nil
}

// SetRelayTransport injects relay transport into the bind layer. If the
// wireguard-go device is already running, triggers a BindUpdate to register
// the relay ReceiveFunc (since Open() only creates it when relay is set).
func (u *UserspaceEngine) SetRelayTransport(rt RelayTransport) {
	if u.bind != nil {
		u.bind.SetRelayTransport(rt)
	}
	// If the device is already up, rebind so Open() sees the relay and
	// creates the relay ReceiveFunc.
	if u.wgDev != nil {
		if err := u.wgDev.BindUpdate(); err != nil {
			log.Printf("[usp] BindUpdate after SetRelayTransport FAILED: %v", err)
		}
	}
}

// LastDirectReceive returns the unix nano timestamp of the last direct UDP
// packet received from a peer. Returns 0 if no direct packet has been received.
func (u *UserspaceEngine) LastDirectReceive(pubKey string) int64 {
	if u.bind == nil {
		return 0
	}
	pp := u.bind.GetPeerPath(pubKey)
	if pp == nil {
		return 0
	}
	return pp.DirectHealth.LastSeen.Load()
}

func (u *UserspaceEngine) LastRelayReceive(pubKey string) int64 {
	if u.bind == nil {
		return 0
	}
	pp := u.bind.GetPeerPath(pubKey)
	if pp == nil {
		return 0
	}
	return pp.RelayHealth.LastSeen.Load()
}

// DeliverRelayPacket pushes a relay-received packet into the bind's relay
// channel so wireguard-go processes it as an incoming WireGuard packet.
func (u *UserspaceEngine) DeliverRelayPacket(pkt RelayPacket) {
	if u.bind != nil {
		u.bind.DeliverRelayPacket(pkt)
	}
}

// MarkBimodalHint arms the bind's dual-send window for a peer identified by
// its raw public key bytes.
func (u *UserspaceEngine) MarkBimodalHint(srcPubKey [32]byte) {
	if u.bind != nil {
		u.bind.MarkBimodalHint(srcPubKey)
	}
}

// currentPeerKeys returns the hex-encoded public keys of all current peers.
func (u *UserspaceEngine) currentPeerKeys() ([]string, error) {
	output, err := u.wgDev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("UAPI get: %w", err)
	}
	var keys []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "public_key=") {
			keys = append(keys, strings.TrimPrefix(line, "public_key="))
		}
	}
	return keys, nil
}

// parseUAPIStats parses the UAPI IpcGet output into PeerStats.
func parseUAPIStats(output string) ([]PeerStats, error) {
	var stats []PeerStats
	var current *PeerStats

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			// Convert hex public key to base64.
			b, err := hex.DecodeString(value)
			if err != nil || len(b) != 32 {
				continue
			}
			stats = append(stats, PeerStats{
				PublicKeyB64: base64.StdEncoding.EncodeToString(b),
			})
			current = &stats[len(stats)-1]

		case "endpoint":
			if current != nil {
				current.ActualEndpoint = value
			}

		case "last_handshake_time_sec":
			if current != nil {
				sec, _ := strconv.ParseInt(value, 10, 64)
				if sec > 0 {
					current.LastHandshake = time.Unix(sec, 0)
				}
				// sec == 0 means no handshake has occurred; leave
				// LastHandshake as time.Time{} (IsZero() == true) so
				// filterRoutesForConnectedPeers correctly skips this peer.
			}

		case "last_handshake_time_nsec":
			if current != nil && !current.LastHandshake.IsZero() {
				nsec, _ := strconv.ParseInt(value, 10, 64)
				current.LastHandshake = current.LastHandshake.Add(time.Duration(nsec) * time.Nanosecond)
			}

		case "rx_bytes":
			if current != nil {
				current.BytesReceived, _ = strconv.ParseInt(value, 10, 64)
			}

		case "tx_bytes":
			if current != nil {
				current.BytesSent, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	return stats, nil
}

// keyToHex converts a base64-encoded WireGuard key to hex encoding, which is
// the format expected by the UAPI protocol.
func keyToHex(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Printf("[wireguard] warning: failed to decode base64 key: %v\n", err)
		return ""
	}
	return hex.EncodeToString(b)
}
