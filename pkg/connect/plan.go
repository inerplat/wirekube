// Package connect joins the local machine to a WireKube cluster as a short-lived
// external peer, routing the cluster's ranges through an in-process WireGuard
// tunnel and its domain to the cluster DNS until the session ends.
package connect

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// TunnelConfig is everything the dataplane needs to carry traffic for one
// issued external peer. It is derived from the peer's status, never its spec,
// so it tracks whatever the controller actually granted.
type TunnelConfig struct {
	Address       netip.Prefix
	MTU           int
	Endpoint      string
	PeerPublicKey string
	Routes        []netip.Prefix
}

// Equal reports whether two configs would program the dataplane identically.
func (c TunnelConfig) Equal(o TunnelConfig) bool {
	return c.Address == o.Address &&
		c.MTU == o.MTU &&
		c.Endpoint == o.Endpoint &&
		c.PeerPublicKey == o.PeerPublicKey &&
		slices.Equal(c.Routes, o.Routes)
}

// ConfigFromStatus builds the tunnel config from an Active peer's status.
func ConfigFromStatus(cr *wirekubev1alpha1.WireKubeExternalPeer) (TunnelConfig, error) {
	st := cr.Status
	serverKey := cr.ServerPublicKey()
	if st.AssignedMeshIP == "" || st.RelayEndpoint == "" || serverKey == "" {
		return TunnelConfig{}, fmt.Errorf("external peer %s status is incomplete", cr.Name)
	}
	addr, err := parsePrefixOrAddr(st.AssignedMeshIP)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("assigned mesh IP: %w", err)
	}
	allowed := st.AllowedDestinations
	if len(allowed) == 0 {
		allowed = []string{st.AssignedMeshIP}
	}
	routes := make([]netip.Prefix, 0, len(allowed))
	for _, s := range allowed {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			return TunnelConfig{}, fmt.Errorf("allowed destination %q: %w", s, err)
		}
		routes = append(routes, p.Masked())
	}
	slices.SortFunc(routes, comparePrefix)
	routes = slices.Compact(routes)

	mtu := int(st.MTU)
	if mtu == 0 {
		mtu = int(wirekubev1alpha1.DefaultExternalPeerMTU)
	}
	return TunnelConfig{
		Address:       addr,
		MTU:           mtu,
		Endpoint:      st.RelayEndpoint,
		PeerPublicKey: serverKey,
		Routes:        routes,
	}, nil
}

// CheckEndpointReachable refuses a config whose own relay endpoint would be
// routed into the tunnel. The tunnel's UDP socket follows the host routing
// table, so such a route would loop every handshake back into itself.
func CheckEndpointReachable(endpoint netip.AddrPort, routes []netip.Prefix) error {
	for _, r := range routes {
		if r.Contains(endpoint.Addr()) {
			return fmt.Errorf("relay endpoint %s falls inside routed cluster range %s; narrow the ranges with --allow or expose the relay on an address outside them", endpoint, r)
		}
	}
	return nil
}

// LocalOverlaps returns, for each route that overlaps a network the host is
// already attached to, a human-readable description of the clash.
func LocalOverlaps(routes, local []netip.Prefix) []string {
	var out []string
	for _, r := range routes {
		for _, l := range local {
			if r.Overlaps(l) {
				out = append(out, fmt.Sprintf("%s overlaps local network %s", r, l))
			}
		}
	}
	return out
}

// uapiConfig renders the wireguard-go IPC config for the tunnel's single peer.
func uapiConfig(privateKey [32]byte, cfg TunnelConfig, endpoint netip.AddrPort) (string, error) {
	peerKey, err := base64.StdEncoding.DecodeString(cfg.PeerPublicKey)
	if err != nil || len(peerKey) != 32 {
		return "", fmt.Errorf("ingress public key %q is not a WireGuard key", cfg.PeerPublicKey)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(peerKey))
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	b.WriteString("persistent_keepalive_interval=25\n")
	b.WriteString("replace_allowed_ips=true\n")
	for _, r := range cfg.Routes {
		fmt.Fprintf(&b, "allowed_ip=%s\n", r)
	}
	return b.String(), nil
}

// DefaultName derives a stable external-peer name for this user and host so a
// rerun after a crash finds and replaces its own leftover peer.
func DefaultName(user, host string) string {
	name := sanitizeName("connect-" + user + "-" + host)
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-.")
	}
	return name
}

// sanitizeName lowers s into a DNS-1123 subdomain.
func sanitizeName(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}
