package wireguard

// PathMode indicates how traffic should be routed for a peer.
//
// The semantics mirror Tailscale's addrForSendLocked: when the direct path
// is trusted, only the direct leg carries traffic; when trust has lapsed or
// a direct path has not yet been proven, both legs carry traffic so that a
// failure on one is invisible to WireGuard thanks to its replay-window
// deduplication; when direct is known dead, only the relay leg is used.
type PathMode int

const (
	PathDirect PathMode = iota // Send via direct UDP only
	PathWarm                   // Send via BOTH direct UDP and relay (Tailscale-style duplicate send)
	PathRelay                  // Send via relay TCP only
)

// WGEngine is the contract the agent uses to drive wireguard-go. It exists
// primarily for testability (so tests can swap in a fake) — there is a single
// real implementation, UserspaceEngine. A kernel-backed engine previously
// existed alongside this one; it was removed because wgctrl's
// single-endpoint-per-peer model cannot represent the bimodal warm-relay
// transport the custom Bind implements.
type WGEngine interface {
	// Lifecycle
	EnsureInterface() error
	Configure() error
	DeleteInterface() error
	Close() error

	// Interface info
	InterfaceName() string
	ListenPort() int
	InterfaceExists() bool
	ConfigMatchesKey(kp *KeyPair) bool

	// Peer management
	SyncPeers(peers []PeerConfig) error
	ForceEndpoint(pubKeyB64, endpoint string) error
	PokeKeepalive(pubKeyB64 string) error
	GetStats() ([]PeerStats, error)

	// Address & routing
	SetAddress(meshIP string) error
	SetPreferredSrc(ip string)
	SyncRoutes(desired []string) error
	AddRoute(dst string) error
	DelRoute(dst string) error

	// Path control for ICE negotiation.
	// SetPeerPath updates the Bind's pathTable atomically so the next Send()
	// for this peer uses the requested transport mode.
	SetPeerPath(pubKey string, mode PathMode, directAddr string) error

	// SetRelayTransport injects the relay client into the Bind so relay
	// packets are delivered through the same wireguard-go receive path as
	// direct UDP packets.
	SetRelayTransport(rt RelayTransport)

	// LastDirectReceive returns the unix nano timestamp of the last direct
	// UDP packet received from a peer. Returns 0 if no direct packet has
	// been received. Used by ICE to verify direct path connectivity.
	LastDirectReceive(pubKey string) int64

	// LastRelayReceive returns the unix nano timestamp of the last relay
	// packet received from a peer. Returns 0 if no relay packet has been
	// received. Used for observability and relay health verification.
	LastRelayReceive(pubKey string) int64

	// MarkBimodalHint arms the dual-send window for a peer in the Bind. The
	// relay pool calls this when a remote peer relays a BimodalHint frame
	// whose sender key matches the given raw public key.
	MarkBimodalHint(srcPubKey [32]byte)
}
