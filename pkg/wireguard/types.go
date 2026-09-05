package wireguard

import "time"

// PeerConfig holds the configuration for a single WireGuard peer.
type PeerConfig struct {
	PublicKeyB64     string
	Endpoint         string
	AllowedIPs       []string
	KeepaliveSeconds int
	// ForceEndpoint overrides the NAT-preservation logic in SyncPeers.
	// When true, the configured endpoint is always applied even if the peer
	// has a recent handshake with a different endpoint. Used for ICE probing.
	ForceEndpoint bool
}

// PeerStats holds runtime statistics for a WireGuard peer.
type PeerStats struct {
	PublicKeyB64   string
	LastHandshake  time.Time
	BytesReceived  int64
	BytesSent      int64
	ActualEndpoint string // WireGuard-observed endpoint (may differ from configured due to NAT)
}

// PathStats is a copyable snapshot of a peer's Bind-level path accounting.
// PeerPath itself holds a mutex and atomics and cannot be copied, so the
// engine hands this out instead.
//
// Leg counters count packets by the legs actually written after every
// override in Send, so dual / (direct_only + dual + relay_only) is the true
// dual-send share.
type PathStats struct {
	SentDirectOnly uint64
	SentDual       uint64
	SentRelayOnly  uint64
	PingsSent      uint64
	PongsRecv      uint64
	AuthFail       uint64
	ReplayDrop     uint64

	LastSendNs    int64 // last Send for this peer on any leg
	LastPongNs    int64 // last heartbeat pong (small or MTU probe)
	LastMTUPongNs int64 // last pong to an MTU-sized probe
	RTTNs         int64 // round trip measured by the last pong

	MTUStale bool // MTU probes unanswered while small pongs are fresh; forces dual-send
}
