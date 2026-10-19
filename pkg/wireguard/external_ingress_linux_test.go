//go:build linux

package wireguard

import (
	"net/netip"
	"testing"
)

func TestEngineSyncExternalIngressLifecycle(t *testing.T) {
	meshTUN := newMemTUN()
	defer meshTUN.Close()
	u := &UserspaceEngine{split: newSplitTUN(meshTUN)}
	keyA, _ := GenerateKeyPair()
	keyB, _ := GenerateKeyPair()
	client, _ := GenerateKeyPair()
	peers := []ExternalPeerConfig{{PublicKeyB64: client.PublicKeyBase64(), AllowedIP: "100.64.0.9/32"}}
	diverted := func() bool {
		d := u.split.divert.Load()
		if d == nil {
			return false
		}
		_, ok := (*d)[netip.MustParseAddr("100.64.0.9")]
		return ok
	}

	if err := u.SyncExternalIngress(&keyA.Private, peers); err != nil {
		t.Fatal(err)
	}
	first := u.ext.Load()
	if first == nil || !diverted() {
		t.Fatal("device not brought up for a served peer")
	}
	if err := u.SyncExternalIngress(&keyA.Private, peers); err != nil {
		t.Fatal(err)
	}
	if u.ext.Load() != first {
		t.Fatal("an unchanged sync recreated the device")
	}
	if err := u.SyncExternalIngress(&keyB.Private, peers); err != nil {
		t.Fatal(err)
	}
	if got := u.ext.Load(); got == first || got.key != keyB.Private {
		t.Fatal("a rotated identity did not replace the device")
	}
	if err := u.SyncExternalIngress(&keyB.Private, nil); err != nil {
		t.Fatal(err)
	}
	if u.ext.Load() != nil || diverted() {
		t.Fatal("device kept running with no peers to serve")
	}
	if err := u.SyncExternalIngress(nil, peers); err != nil {
		t.Fatal(err)
	}
	if u.ext.Load() != nil {
		t.Fatal("device brought up without an identity")
	}
}
