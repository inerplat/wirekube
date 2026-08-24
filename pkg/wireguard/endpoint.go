package wireguard

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// Compile-time check: WireKubeEndpoint implements conn.Endpoint.
var _ conn.Endpoint = (*WireKubeEndpoint)(nil)

// WireKubeEndpoint wraps a destination address for wireguard-go's conn.Endpoint
// interface, carrying the remote address and, where it is known, the peer's
// public key.
//
// Both relay- and direct-received packets carry the key. Send resolves the peer
// from it rather than by reverse-resolving the destination address, which is
// ambiguous whenever several peers share one NAT address.
type WireKubeEndpoint struct {
	dst netip.AddrPort
	relayPeerKey
	externalSource ExternalSource
}

// NewWireKubeEndpoint creates an endpoint from an address:port pair.
func NewWireKubeEndpoint(dst netip.AddrPort) *WireKubeEndpoint {
	return &WireKubeEndpoint{dst: dst}
}

// ClearSrc is a no-op because WireKubeEndpoint does not cache source addresses.
func (e *WireKubeEndpoint) ClearSrc() {}

// SrcToString returns an empty string since no source is tracked.
func (e *WireKubeEndpoint) SrcToString() string {
	return ""
}

// DstToString returns the destination address as "ip:port" — for a
// relay-delivered packet, the synthetic it was surfaced at.
//
// It reports only the real destination, never externalSource.Addr. That string
// is whatever the relay claimed, and wireguard-go prints this value into the
// UAPI endpoint field, where the agent reads it as a statement about where the
// peer actually is. Replies to an external peer are routed from externalSource
// itself inside Send, so nothing depends on it appearing here.
func (e *WireKubeEndpoint) DstToString() string {
	return e.dst.String()
}

// DstToBytes returns the binary representation of the destination address,
// used by wireguard-go for mac2 cookie calculations.
func (e *WireKubeEndpoint) DstToBytes() []byte {
	if e.relayPeerKeySet() && !e.dst.IsValid() {
		return nil
	}
	b, _ := e.dst.MarshalBinary()
	return b
}

// DstIP returns the destination IP address.
func (e *WireKubeEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

// SrcIP returns an invalid Addr since no source is tracked.
func (e *WireKubeEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
