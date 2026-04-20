package wireguard

// RelayTransport abstracts the relay network for use by WireKubeBind.
// The agent's relay.Pool implements this interface.
type RelayTransport interface {
	// SendToPeer sends an encrypted WireGuard packet to a remote peer via relay.
	SendToPeer(destPubKey [32]byte, payload []byte) error
	// SendBimodalHint asks the relay to deliver a hint to destPubKey instructing
	// it to dual-send subsequent packets on both direct and relay legs. Used by
	// the Bind when the local direct-receive watermark has stalled, which
	// signals an asymmetric UDP blackhole that the remote peer cannot see
	// from its own observations.
	SendBimodalHint(destPubKey [32]byte) error
	// IsConnected returns true if at least one relay server is reachable.
	IsConnected() bool
}

// RelayPacket is a packet received from the relay network.
type RelayPacket struct {
	SrcKey  [32]byte
	Payload []byte
}
