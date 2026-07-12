//go:build linux

package wireguard

type relayPeerKey struct {
	peerKey [32]byte
}

func (k relayPeerKey) relayPeerKeySet() bool {
	return k.peerKey != [32]byte{}
}
