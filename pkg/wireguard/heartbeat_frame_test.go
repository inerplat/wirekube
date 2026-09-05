package wireguard

import (
	"bytes"
	"testing"
)

func mustKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

// Both sides must derive the same pair key from their own private key and the
// other's public key, and unrelated pairs must not share one.
func TestHeartbeatKeyDerivationIsSymmetric(t *testing.T) {
	a, b, c := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)

	ab, err := deriveHeartbeatKey(a.Private, a.Public, b.Public)
	if err != nil {
		t.Fatalf("derive a→b: %v", err)
	}
	ba, err := deriveHeartbeatKey(b.Private, b.Public, a.Public)
	if err != nil {
		t.Fatalf("derive b→a: %v", err)
	}
	if *ab != *ba {
		t.Fatal("pair key differs between the two sides")
	}
	ac, err := deriveHeartbeatKey(a.Private, a.Public, c.Public)
	if err != nil {
		t.Fatalf("derive a→c: %v", err)
	}
	if *ab == *ac {
		t.Fatal("different pairs derived the same key")
	}

	// The all-zero key is a low-order point; derivation must refuse it rather
	// than produce a key every peer could compute.
	if _, err := deriveHeartbeatKey(a.Private, a.Public, [32]byte{}); err == nil {
		t.Fatal("derivation accepted the all-zero peer key")
	}
}

// The wire layout: magic, version, type, big-endian frame_len, txid, sent_at,
// sender, MAC over the first 60 bytes, zero padding to frame_len.
func TestHeartbeatFrameEncodeDecode(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	f := heartbeatFrame{Type: heartbeatTypePing, FrameLen: 1452, SentAt: -1234567890123, TxID: [12]byte{1, 2, 3}}
	f.Sender[0], f.Sender[31] = 0xAA, 0xBB

	buf := encodeHeartbeat(f, key)
	if len(buf) != 1452 {
		t.Fatalf("len = %d, want 1452", len(buf))
	}
	if string(buf[:4]) != "WKHB" || buf[4] != 1 || buf[5] != heartbeatTypePing {
		t.Fatalf("header = % x", buf[:6])
	}
	if buf[6] != 0x05 || buf[7] != 0xAC { // 1452 big-endian
		t.Fatalf("frame_len bytes = % x, want 05 ac", buf[6:8])
	}
	if !hasHeartbeatMagic(buf) {
		t.Fatal("hasHeartbeatMagic = false")
	}
	if !verifyHeartbeatMAC(buf, key) {
		t.Fatal("MAC did not verify")
	}
	for i, p := range buf[heartbeatMinLen:] {
		if p != 0 {
			t.Fatalf("padding byte %d = %d, want 0", i, p)
		}
	}
	got, ok := decodeHeartbeatHeader(buf)
	if !ok || got != f {
		t.Fatalf("decode = %+v ok=%v, want %+v", got, ok, f)
	}

	// Any header byte flip, or the wrong key, fails the MAC.
	for _, off := range []int{0, 5, 6, 8, 20, 28, 59} {
		tampered := append([]byte(nil), buf...)
		tampered[off] ^= 0x01
		if verifyHeartbeatMAC(tampered, key) {
			t.Errorf("MAC verified after flipping byte %d", off)
		}
	}
	if verifyHeartbeatMAC(buf, bytes.Repeat([]byte{8}, 32)) {
		t.Error("MAC verified under the wrong key")
	}
	// Padding is not covered by the MAC; frame_len is what catches a size change.
	padded := append([]byte(nil), buf...)
	padded[100] = 1
	if !verifyHeartbeatMAC(padded, key) {
		t.Error("padding change failed the MAC; padding is outside the MAC by design")
	}

	// Below the minimum size or without the magic, it is not a heartbeat.
	if hasHeartbeatMagic(buf[:heartbeatMinLen-1]) {
		t.Error("short frame reported as heartbeat")
	}
	wg := append([]byte(nil), buf...)
	wg[0] = 4
	if hasHeartbeatMagic(wg) {
		t.Error("frame without magic reported as heartbeat")
	}
	// An unsupported version decodes as not-ok.
	v2 := append([]byte(nil), buf...)
	v2[4] = 2
	if _, ok := decodeHeartbeatHeader(v2); ok {
		t.Error("version 2 decoded as ok")
	}
}

func TestHeartbeatPingSizes(t *testing.T) {
	if got := heartbeatMTUProbeLen(1420); got != 1452 {
		t.Fatalf("MTU probe len for 1420 = %d, want 1452", got)
	}
	// A range, not the two exact sizes this node emits: a peer whose mesh
	// MTU differs mid-rollout must not have its probes read as forgeries.
	for _, tc := range []struct {
		n    int
		want bool
	}{
		{92, true},   // the bare frame
		{1452, true}, // this node's MTU probe
		{93, true},   // a peer with a slightly smaller MTU
		{1451, true},
		{1580, true},  // a peer with a larger MTU, within slack
		{91, false},   // shorter than a heartbeat can be
		{1581, false}, // past the slack: not reflected
	} {
		if got := heartbeatPingSizeAllowed(tc.n, 1420); got != tc.want {
			t.Errorf("size %d allowed = %v, want %v", tc.n, got, tc.want)
		}
	}
}
