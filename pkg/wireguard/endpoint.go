package wireguard

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// Compile-time check: WireKubeEndpoint implements conn.Endpoint.
var _ conn.Endpoint = (*WireKubeEndpoint)(nil)

// WireKubeEndpoint wraps a destination address for wireguard-go's conn.Endpoint
// interface. It carries the remote (dst) address and an optional peer public key.
// When peerKey is set (relay-received packets), Send() uses it directly to look
// up the pathTable instead of going through the addrToPeer reverse map.
type WireKubeEndpoint struct {
	dst     netip.AddrPort
	peerKey [32]byte // set by relay ReceiveFunc; zero value means unset
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

// DstToString returns the destination address as "ip:port".
func (e *WireKubeEndpoint) DstToString() string {
	return e.dst.String()
}

// DstToBytes returns the binary representation of the destination address,
// used by wireguard-go for mac2 cookie calculations.
func (e *WireKubeEndpoint) DstToBytes() []byte {
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
