// Package ipsec terminates site-to-site IPsec tunnels for WireKubeGateway
// peers. The IKE side is delegated to a strongSwan charon reached over its
// vici socket. The data plane is an XFRM interface per tunnel, so the IPsec
// policies only see traffic routed into it, or plain IPsec policies where the
// kernel cannot create XFRM interfaces.
package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/strongswan/govici/vici"
)

const (
	// ConnPrefix marks charon connections and shared secrets owned by
	// WireKube. Anything without it is left alone, so a charon shared with
	// other tooling keeps its own connections.
	ConnPrefix = "wk-"
	// InterfacePrefix marks XFRM interfaces owned by WireKube.
	InterfacePrefix = "wkx"

	DefaultIKEProposal    = "aes256-sha256-modp2048"
	DefaultESPProposal    = "aes256-sha256-modp2048"
	DefaultIKELifetime    = 28800
	DefaultESPLifetime    = 3600
	DefaultDPDDelay       = 30
	DefaultDPDAction      = "restart"
	DefaultMTU            = 1400
	DefaultPreSharedKeyID = "psk"
)

// Tunnel is the fully defaulted description of one tunnel, independent of
// the Kubernetes API types so it can be built and tested in isolation.
type Tunnel struct {
	// Name is the tunnel key, "<gateway>/<tunnel>". It names the charon
	// connection and seeds the derived interface ID.
	Name          string
	RemoteAddress string
	RemoteID      string
	LocalID       string
	PreSharedKey  string
	LocalTS       []string
	RemoteTS      []string
	IKEVersion    int
	IKEProposals  []string
	IKELifetime   int
	ESPProposals  []string
	ESPLifetime   int
	DPDDelay      int
	DPDAction     string
	ForceEncap    bool
	// RouteBased binds the CHILD_SA to the XFRM interface InterfaceID. When
	// false the CHILD_SA installs plain policies (policy-based steering).
	RouteBased  bool
	InterfaceID uint32
	MTU         int
}

// ConnName is the charon connection, CHILD_SA and shared-secret name of the
// tunnel: "wk-<key>@<first 8 hex digits of the fingerprint>". A changed
// setting yields a new name, so the agent replaces the connection and its
// SAs instead of leaving SAs with the old settings running until they rekey.
func (t *Tunnel) ConnName() string { return ConnPrefix + t.Name + "@" + t.Fingerprint()[:8] }

// KeyOfConn returns the tunnel key of a WireKube connection name and whether
// the name is one.
func KeyOfConn(conn string) (string, bool) {
	if !strings.HasPrefix(conn, ConnPrefix) {
		return "", false
	}
	key := strings.TrimPrefix(conn, ConnPrefix)
	if i := strings.LastIndex(key, "@"); i >= 0 {
		key = key[:i]
	}
	return key, key != ""
}

// DeriveInterfaceID maps a tunnel name to a stable, non-reserved XFRM
// interface ID. 0 means "no interface" to the kernel and 0xffffffff is
// reserved by strongSwan for "%unique", so both are avoided.
func DeriveInterfaceID(tunnel string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tunnel))
	id := h.Sum32()
	if id == 0 || id == 0xffffffff {
		id = 1
	}
	return id
}

// InterfaceName is the XFRM interface name for an interface ID. Eleven
// characters keeps it inside IFNAMSIZ.
func InterfaceName(id uint32) string { return fmt.Sprintf("%s%08x", InterfacePrefix, id) }

// Validate rejects a tunnel the IKE daemon or the kernel would refuse, so the
// failure lands in status with a reason instead of as a charon log line.
func (t *Tunnel) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("tunnel name is empty")
	}
	if t.RemoteAddress == "" {
		return fmt.Errorf("remoteAddress is empty")
	}
	if t.PreSharedKey == "" {
		return fmt.Errorf("pre-shared key is empty")
	}
	if len(t.LocalTS) == 0 {
		return fmt.Errorf("no local traffic selectors: set spec.localTrafficSelectors or the mesh CIDR")
	}
	if len(t.RemoteTS) == 0 {
		return fmt.Errorf("no remote traffic selectors: set spec.remoteTrafficSelectors or the gateway routes")
	}
	for _, c := range append(append([]string{}, t.LocalTS...), t.RemoteTS...) {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("traffic selector %q: %w", c, err)
		}
	}
	for _, l := range t.LocalTS {
		lp := netip.MustParsePrefix(l).Masked()
		for _, r := range t.RemoteTS {
			rp := netip.MustParsePrefix(r).Masked()
			if lp.Overlaps(rp) {
				return fmt.Errorf("local selector %s overlaps remote selector %s", l, r)
			}
		}
	}
	if t.IKEVersion != 1 && t.IKEVersion != 2 {
		return fmt.Errorf("IKE version %d is not 1 or 2", t.IKEVersion)
	}
	// Checked in both modes: the mode is chosen after validation, and an ID
	// strongSwan reads as %unique (0xffffffff) would leave a route-based SA
	// that never matches its interface.
	if t.InterfaceID == 0 || t.InterfaceID == 0xffffffff {
		return fmt.Errorf("interface ID %d is reserved", t.InterfaceID)
	}
	return nil
}

// Fingerprint changes whenever a setting of the connection changes. It
// leaves out the pre-shared key: it ends up in the logged connection name,
// where a hash of the key would let a reader test guesses of a weak key.
func (t *Tunnel) Fingerprint() string {
	h := sha256.New()
	for _, part := range []string{
		t.Name, t.RemoteAddress, t.RemoteID, t.LocalID,
		strings.Join(sortedCopy(t.LocalTS), ","), strings.Join(sortedCopy(t.RemoteTS), ","),
		strconv.Itoa(t.IKEVersion), strings.Join(t.IKEProposals, ","), strconv.Itoa(t.IKELifetime),
		strings.Join(t.ESPProposals, ","), strconv.Itoa(t.ESPLifetime),
		strconv.Itoa(t.DPDDelay), t.DPDAction, strconv.FormatBool(t.ForceEncap),
		strconv.FormatBool(t.RouteBased), strconv.FormatUint(uint64(t.InterfaceID), 10),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func (t *Tunnel) remoteID() string {
	if t.RemoteID != "" {
		return t.RemoteID
	}
	return t.RemoteAddress
}

// LoadConnMessage builds the vici load-conn request for the tunnel.
//
// When RouteBased, the CHILD_SA is bound to the tunnel's XFRM interface with
// if_id_in and if_id_out, which makes the installed policies route-based:
// they only see packets the kernel routes into that interface. Otherwise the
// policies apply to any matching packet (policy-based). start_action=start
// brings the tunnel up when it is loaded and close_action=start brings it back
// when the remote closes it, so the mesh side keeps the tunnel up whether or
// not the remote initiates.
func (t *Tunnel) LoadConnMessage() (*vici.Message, error) {
	ifID := strconv.FormatUint(uint64(t.InterfaceID), 10)

	local := vici.NewMessage()
	if err := setAll(local, kv{"auth", "psk"}); err != nil {
		return nil, err
	}
	if t.LocalID != "" {
		if err := local.Set("id", t.LocalID); err != nil {
			return nil, err
		}
	}
	remote := vici.NewMessage()
	if err := setAll(remote, kv{"auth", "psk"}, kv{"id", t.remoteID()}); err != nil {
		return nil, err
	}

	child := vici.NewMessage()
	if err := setAll(child,
		kv{"local_ts", t.LocalTS},
		kv{"remote_ts", t.RemoteTS},
		kv{"esp_proposals", t.ESPProposals},
		kv{"rekey_time", fmt.Sprintf("%ds", t.ESPLifetime)},
		kv{"dpd_action", t.DPDAction},
		kv{"start_action", "start"},
		kv{"close_action", "start"},
	); err != nil {
		return nil, err
	}
	if t.RouteBased {
		if err := setAll(child, kv{"if_id_in", ifID}, kv{"if_id_out", ifID}); err != nil {
			return nil, err
		}
	}
	children := vici.NewMessage()
	if err := children.Set(t.ConnName(), child); err != nil {
		return nil, err
	}

	encap := "no"
	if t.ForceEncap {
		encap = "yes"
	}
	conn := vici.NewMessage()
	if err := setAll(conn,
		kv{"version", strconv.Itoa(t.IKEVersion)},
		kv{"remote_addrs", []string{t.RemoteAddress}},
		kv{"proposals", t.IKEProposals},
		kv{"rekey_time", fmt.Sprintf("%ds", t.IKELifetime)},
		kv{"dpd_delay", fmt.Sprintf("%ds", t.DPDDelay)},
		kv{"encap", encap},
		// A gateway peer that moves fails over through WireKube, and many
		// VPN gateways do not support MOBIKE.
		kv{"mobike", "no"},
		kv{"local", local},
		kv{"remote", remote},
		kv{"children", children},
	); err != nil {
		return nil, err
	}

	msg := vici.NewMessage()
	if err := msg.Set(t.ConnName(), conn); err != nil {
		return nil, err
	}
	return msg, nil
}

// LoadSharedMessage builds the vici load-shared request carrying the PSK.
// The secret is scoped to the remote identity (and the local one when set)
// so tunnels with different keys cannot pick up each other's secret.
func (t *Tunnel) LoadSharedMessage() (*vici.Message, error) {
	owners := []string{t.remoteID()}
	if t.LocalID != "" {
		owners = append(owners, t.LocalID)
	}
	msg := vici.NewMessage()
	if err := setAll(msg,
		kv{"id", t.ConnName()},
		kv{"type", "IKE"},
		kv{"data", t.PreSharedKey},
		kv{"owners", owners},
	); err != nil {
		return nil, err
	}
	return msg, nil
}

type kv struct {
	k string
	v any
}

func setAll(m *vici.Message, pairs ...kv) error {
	for _, p := range pairs {
		if err := m.Set(p.k, p.v); err != nil {
			return fmt.Errorf("vici field %s: %w", p.k, err)
		}
	}
	return nil
}
