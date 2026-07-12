//go:build !linux

package wireguard

type relayPeerKey struct{}

func (relayPeerKey) relayPeerKeySet() bool {
	return false
}
