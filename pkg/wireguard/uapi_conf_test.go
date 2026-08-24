package wireguard

import (
	"strings"
	"testing"
)

// wireguard-go emits an immediate keepalive only on a zero -> non-zero
// transition of persistent_keepalive_interval (device/uapi.go: "peer.pkaOn =
// old == 0 && secs != 0"). Peers are registered with a non-zero keepalive, so a
// bare "=1" is silently a no-op and the probe waits for a natural packet or a
// rekey. Both conf builders must therefore drop to 0 first, in that order,
// inside the same peer block.
func TestKeepaliveArmDropsToZeroFirst(t *testing.T) {
	for name, conf := range map[string]string{
		"forceEndpoint": forceEndpointConf("abcd", "10.0.0.1:51820"),
		"poke":          pokeKeepaliveConf("abcd"),
	} {
		zero := strings.Index(conf, "persistent_keepalive_interval=0")
		one := strings.Index(conf, "persistent_keepalive_interval=1")
		if zero < 0 || one < 0 {
			t.Fatalf("%s: conf lacks the keepalive arming pair:\n%s", name, conf)
		}
		if zero > one {
			t.Fatalf("%s: keepalive set to 1 before 0, which never arms:\n%s", name, conf)
		}
		if !strings.Contains(conf, "public_key=abcd\n") {
			t.Fatalf("%s: conf lost the peer key:\n%s", name, conf)
		}
		if !strings.Contains(conf, "update_only=true\n") {
			t.Fatalf("%s: conf must not create peers:\n%s", name, conf)
		}
	}
}

func TestForceEndpointConfCarriesEndpointAndPokeDoesNot(t *testing.T) {
	force := forceEndpointConf("abcd", "10.213.103.74:51820")
	if !strings.Contains(force, "endpoint=10.213.103.74:51820\n") {
		t.Fatalf("forceEndpointConf lost the endpoint:\n%s", force)
	}
	if strings.Contains(pokeKeepaliveConf("abcd"), "endpoint=") {
		t.Fatal("pokeKeepaliveConf must not rewrite the endpoint")
	}
}
