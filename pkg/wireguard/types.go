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
