package wireguard

import "fmt"

// keepaliveArmConf holds the two assignments that make wireguard-go emit a
// keepalive immediately. Setting the interval to 1 is not enough on its own:
// wireguard-go sends right away only when the interval was previously zero
// (device/uapi.go: "peer.pkaOn = old == 0 && secs != 0"), and peers are
// registered with a non-zero keepalive. Dropping to 0 first inside the same
// peer block turns the second assignment into that transition, so the packet
// leaves at handlePostConfig instead of waiting for the next natural packet or
// for a rekey up to RekeyAfterTime away.
const keepaliveArmConf = "persistent_keepalive_interval=0\npersistent_keepalive_interval=1\n"

// forceEndpointConf renders the UAPI block that repoints a peer at endpoint and
// arms an immediate keepalive over it.
func forceEndpointConf(pubHex, endpoint string) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n%s",
		pubHex, endpoint, keepaliveArmConf)
}

// pokeKeepaliveConf renders the UAPI block that arms an immediate keepalive
// without touching the peer's endpoint.
func pokeKeepaliveConf(pubHex string) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\n%s", pubHex, keepaliveArmConf)
}
