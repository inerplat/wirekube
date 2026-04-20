//go:build linux

package wireguard

import (
	"testing"
	"time"
)

// Compile-time interface satisfaction check.

func TestUserspaceEngineImplementsWGEngine(t *testing.T) {
	var _ WGEngine = (*UserspaceEngine)(nil)
}

func TestPathModeConstants(t *testing.T) {
	// Verify PathMode values are distinct
	modes := []PathMode{PathDirect, PathWarm, PathRelay}
	seen := make(map[PathMode]bool)
	for _, m := range modes {
		if seen[m] {
			t.Errorf("duplicate PathMode value: %d", m)
		}
		seen[m] = true
	}
}

func TestParseUAPIStats_NoHandshake(t *testing.T) {
	// When wireguard-go reports last_handshake_time_sec=0, it means no
	// handshake has occurred. LastHandshake must remain the Go zero time
	// so IsZero() returns true and filterRoutesForConnectedPeers skips it.
	uapi := "public_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
		"endpoint=1.2.3.4:51820\n" +
		"last_handshake_time_sec=0\n" +
		"last_handshake_time_nsec=0\n" +
		"rx_bytes=0\n" +
		"tx_bytes=0\n"

	stats, err := parseUAPIStats(uapi)
	if err != nil {
		t.Fatalf("parseUAPIStats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	if !stats[0].LastHandshake.IsZero() {
		t.Errorf("LastHandshake = %v, want zero (no handshake)", stats[0].LastHandshake)
	}
}

func TestParseUAPIStats_WithHandshake(t *testing.T) {
	uapi := "public_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
		"endpoint=1.2.3.4:51820\n" +
		"last_handshake_time_sec=1700000000\n" +
		"last_handshake_time_nsec=123456789\n" +
		"rx_bytes=1024\n" +
		"tx_bytes=2048\n"

	stats, err := parseUAPIStats(uapi)
	if err != nil {
		t.Fatalf("parseUAPIStats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	if stats[0].LastHandshake.IsZero() {
		t.Error("LastHandshake is zero, want non-zero (handshake occurred)")
	}
	want := time.Unix(1700000000, 123456789)
	if !stats[0].LastHandshake.Equal(want) {
		t.Errorf("LastHandshake = %v, want %v", stats[0].LastHandshake, want)
	}
	if stats[0].BytesReceived != 1024 {
		t.Errorf("BytesReceived = %d, want 1024", stats[0].BytesReceived)
	}
	if stats[0].BytesSent != 2048 {
		t.Errorf("BytesSent = %d, want 2048", stats[0].BytesSent)
	}
}
