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
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// UserspaceEngine implements WGEngine using wireguard-go. It creates a TUN
// device and runs the WireGuard protocol entirely in userspace, and installs
// fwmark/routing-table rules (see routes.go) so local WireGuard sockets bypass
// the tunnel while everything else routes through it.
type UserspaceEngine struct {
	// preservedRoutes holds table-22347 routes captured off an adopted link
	// before it is cycled down for device creation; Configure reinstalls them
	// right after bringing the link back up. Admin-down flushes a link's
	// routes, and the whole point of adoption is that they survive.
	preservedRoutes []netlink.Route

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
		case "tun", "tuntap":
			// The kernel reports IFLA_INFO_KIND "tun"; the netlink library
			// deserializes that into its Tuntap struct, whose Type() is
			// "tuntap". Both spellings are the same device class, and
			// matching only "tun" made every adoption of a persisted TUN
			// fail as a "foreign link".
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
	persistTUN(tunDev, u.ifaceName)

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
	// wireguard-go's TUN event reader must not observe an already-up link
	// while the device is being created: the queued EventUp races
	// Configure's BindUpdate sequence (see the deadlock note in
	// EnsureInterface). The create path starts with the link down by
	// construction; adoption has to restore that invariant. Downing the link
	// flushes its routes, so they are captured first and reinstalled by
	// Configure after it brings the link back up.
	if link, err := netlink.LinkByName(u.ifaceName); err == nil {
		if link.Attrs().Flags&net.FlagUp != 0 {
			routes, listErr := netlink.RouteListFiltered(syscall.AF_INET,
				&netlink.Route{Table: WKRouteTable, LinkIndex: link.Attrs().Index},
				netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
			if listErr == nil {
				u.preservedRoutes = routes
			}
			if err := netlink.LinkSetDown(link); err != nil {
				return fmt.Errorf("downing adopted TUN %s for device creation: %w", u.ifaceName, err)
			}
			log.Printf("[usp] adopted %s cycled down for device creation; %d routes preserved for reinstall", u.ifaceName, len(u.preservedRoutes))
		}
	}

	tunDev, err := tun.CreateTUN(u.ifaceName, u.mtu)
	if err != nil {
		return fmt.Errorf("reattaching TUN %s: %w", u.ifaceName, err)
	}
	u.tunDev = tunDev
	persistTUN(tunDev, u.ifaceName)

	// Adoption is the normal restart path now, so it must reassert the same
	// sysctls the create path sets: another component may have tightened
	// rp_filter or reinstalled xfrm policies while the previous agent held
	// the device, and an agent restart is the operator's self-heal for that.
	setRpFilterForIface(u.ifaceName)
	disableXfrmForIface(u.ifaceName)

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

	// Reinstall the routes captured before the adopted link was cycled down.
	// Failures are logged, not fatal: the next sync reconciles the full set.
	if len(u.preservedRoutes) > 0 {
		restored := 0
		var firstErr error
		for i := range u.preservedRoutes {
			r := u.preservedRoutes[i]
			// Replay only the identity of the route, not the full captured
			// struct: RouteListFiltered fills kernel-owned fields whose
			// replay a fresh RTM_NEWROUTE can reject.
			clean := netlink.Route{Table: r.Table, LinkIndex: r.LinkIndex, Dst: r.Dst, Src: r.Src, Scope: r.Scope}
			err := netlink.RouteReplace(&clean)
			if err != nil {
				clean.Src = nil
				err = netlink.RouteReplace(&clean)
			}
			if err == nil {
				restored++
			} else if firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			log.Printf("[usp] preserved route restore error (first): %v", firstErr)
		}
		log.Printf("[usp] restored %d/%d preserved routes on %s", restored, len(u.preservedRoutes), u.ifaceName)
		u.preservedRoutes = nil
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
	// The same ownership rule EnsureInterface applies on creation: only TUN
	// devices and legacy kernel wireguard links are WireKube's to delete. A
	// misconfigured interface name pointed at a foreign link must fail here,
	// not take the link down — WIREKUBE_CLEAN_STATE reaches this path with no
	// prior type check.
	switch link.Type() {
	case "tun", "tuntap", "wireguard":
	default:
		return fmt.Errorf("interface %s has link type %q, refusing to delete a foreign link", u.ifaceName, link.Type())
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
					} else if existing.DirectAddr() != addr {
						// SetPeerPath rather than a direct field write: it
						// releases the claim on the old address as well as
						// recording the new one, so a peer that moves does
						// not keep claiming an address it has left.
						u.bind.SetPeerPath(p.PublicKeyB64, existing.Mode.Load(), addr)
					}
				}
			}
		}
		conf.WriteString("replace_allowed_ips=true\n")
		for _, aip := range p.AllowedIPs {
			fmt.Fprintf(&conf, "allowed_ip=%s\n", aip)
		}
		// Written on every sync, including when the desired interval is 0.
		// PokeKeepalive and ForceEndpoint arm a 1s keepalive for probing, and
		// this assignment is what disarms it again; omitting the zero case
		// would leave a probed peer emitting a packet per second for good.
		fmt.Fprintf(&conf, "persistent_keepalive_interval=%d\n", p.KeepaliveSeconds)
	}

	// Remove peers not in the desired set, from the bind as well as from the
	// device. The bind holds its own path entry and address claims per peer,
	// and a claim left behind makes that address unresolvable for whoever
	// holds it next.
	for _, hexKey := range currentKeys {
		if _, ok := desiredKeys[hexKey]; !ok {
			fmt.Fprintf(&conf, "public_key=%s\nremove=true\n", hexKey)
			if u.bind != nil {
				if b64, err := hexToKeyB64(hexKey); err == nil {
					u.bind.ForgetPeer(b64)
				} else {
					log.Printf("[usp] warning: cannot release bind state for removed peer %s: %v", hexKey, err)
				}
			}
		}
	}

	if conf.Len() == 0 {
		return nil
	}
	return u.wgDev.IpcSet(conf.String())
}

// ForceEndpoint updates a single peer's endpoint and arms a 1s keepalive so an
// outgoing packet leaves over the new endpoint immediately.
func (u *UserspaceEngine) ForceEndpoint(pubKeyB64, endpoint string) error {
	if u.wgDev == nil {
		return fmt.Errorf("device not initialized")
	}
	return u.wgDev.IpcSet(forceEndpointConf(keyToHex(pubKeyB64), endpoint))
}

// PokeKeepalive arms a 1s keepalive to trigger an immediate outgoing WG packet
// without changing the endpoint.
func (u *UserspaceEngine) PokeKeepalive(pubKeyB64 string) error {
	if u.wgDev == nil {
		return fmt.Errorf("device not initialized")
	}
	return u.wgDev.IpcSet(pokeKeepaliveConf(keyToHex(pubKeyB64)))
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
	// Feed wireguard-go's roamed endpoints back into the bind, so its address
	// claims can disambiguate same-NAT peers and stale source-port entries are
	// purged as the NAT mapping drifts.
	if u.bind != nil {
		for _, s := range stats {
			if s.ActualEndpoint == "" || s.PublicKeyB64 == "" {
				continue
			}
			addr, err := netip.ParseAddrPort(s.ActualEndpoint)
			if err != nil {
				continue
			}
			// Skip the synthetic a relay delivery leaves behind as the device
			// endpoint. Feeding it back would overwrite the peer's learned
			// direct address with a loopback that has no UDP destination and
			// close the direct leg until the next probe.
			if addr.Port() == 0 || addr.Addr().IsLoopback() {
				continue
			}
			pp := u.bind.GetPeerPath(s.PublicKeyB64)
			if pp == nil {
				continue
			}
			// The device roams an endpoint only on packets that authenticate,
			// which is what makes this address safe for the datapath to
			// follow without corroboration.
			u.bind.NoteAuthenticatedAddr(s.PublicKeyB64, addr)
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

	// The TUN is exclusively wirekube's, so every IPv4 address on it is ours
	// to reconcile. Without teardown on shutdown, a mesh CIDR change while
	// the agent was down would otherwise leave the old mesh IP alongside the
	// new one forever.
	present := false
	addrs, _ := netlink.AddrList(link, syscall.AF_INET)
	for _, existing := range addrs {
		if existing.IP.Equal(ip) {
			present = true
			continue
		}
		if err := netlink.AddrDel(link, &existing); err != nil {
			log.Printf("[usp] removing stale address %s from %s: %v", existing.IPNet, u.ifaceName, err)
		}
	}
	if present {
		return nil
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

// EnsureRoutingRules delegates to the package-level idempotent implementation.
// Called both at startup (via Configure) and on every sync tick so the ip
// rules self-heal if a co-resident component flushes them.
func (u *UserspaceEngine) EnsureRoutingRules() error {
	return EnsureRoutingRules()
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

// persistTUN marks the TUN with TUNSETPERSIST so it outlives this process.
// Addresses and routes then survive an agent restart and the next process
// reattaches instead of rebuilding the dataplane. Set on reattach as well so
// a device created by an older agent is upgraded the first time it is
// adopted. Best effort: without persistence the restart is merely cold, so
// failure is logged, not returned.
func persistTUN(dev tun.Device, name string) {
	f := dev.File()
	if f == nil {
		log.Printf("[usp] cannot persist %s: TUN exposes no file descriptor", name)
		return
	}
	// SyscallConn keeps the fd's non-blocking registration intact; File.Fd()
	// is the API the runtime documentation steers ioctl users away from, and
	// wireguard-go itself uses SyscallConn for its TUN ioctls.
	sc, err := f.SyscallConn()
	if err != nil {
		log.Printf("[usp] cannot persist %s: %v", name, err)
		return
	}
	var ioctlErr error
	if ctrlErr := sc.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetInt(int(fd), unix.TUNSETPERSIST, 1)
	}); ctrlErr != nil {
		log.Printf("[usp] TUNSETPERSIST on %s failed: %v", name, ctrlErr)
	} else if ioctlErr != nil {
		log.Printf("[usp] TUNSETPERSIST on %s failed: %v", name, ioctlErr)
	}
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

// hexToKeyB64 converts a UAPI hex key back to the base64 form the bind and the
// agent key their per-peer state by.
func hexToKeyB64(hexKey string) (string, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key is %d bytes, want 32", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
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
