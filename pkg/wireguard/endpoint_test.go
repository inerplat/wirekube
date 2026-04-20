package wireguard

import (
	"net/netip"
	"testing"
)

func TestEndpointDstToString(t *testing.T) {
	ep := &WireKubeEndpoint{dst: netip.MustParseAddrPort("192.168.1.1:51820")}
	if got := ep.DstToString(); got != "192.168.1.1:51820" {
		t.Errorf("DstToString() = %q, want %q", got, "192.168.1.1:51820")
	}
}

func TestEndpointDstIP(t *testing.T) {
	ep := &WireKubeEndpoint{dst: netip.MustParseAddrPort("10.0.0.1:51820")}
	if got := ep.DstIP(); got != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("DstIP() = %v, want 10.0.0.1", got)
	}
}

func TestEndpointSrcToString(t *testing.T) {
	ep := &WireKubeEndpoint{dst: netip.MustParseAddrPort("1.2.3.4:1234")}
	if got := ep.SrcToString(); got != "" {
		t.Errorf("SrcToString() = %q, want empty", got)
	}
}

func TestEndpointClearSrc(t *testing.T) {
	ep := &WireKubeEndpoint{dst: netip.MustParseAddrPort("1.2.3.4:1234")}
	ep.ClearSrc() // Should not panic
}

func TestEndpointDstToBytes(t *testing.T) {
	ap := netip.MustParseAddrPort("192.168.1.1:51820")
	ep := &WireKubeEndpoint{dst: ap}
	b := ep.DstToBytes()
	if len(b) == 0 {
		t.Fatal("DstToBytes() returned empty slice")
	}
	// Verify round-trip: unmarshal should reproduce the original AddrPort
	var got netip.AddrPort
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if got != ap {
		t.Errorf("round-trip mismatch: got %v, want %v", got, ap)
	}
}

func TestEndpointSrcIP(t *testing.T) {
	ep := &WireKubeEndpoint{dst: netip.MustParseAddrPort("1.2.3.4:1234")}
	if ep.SrcIP().IsValid() {
		t.Errorf("SrcIP() should return invalid Addr, got %v", ep.SrcIP())
	}
}

func TestNewWireKubeEndpoint(t *testing.T) {
	ap := netip.MustParseAddrPort("10.0.0.1:51820")
	ep := NewWireKubeEndpoint(ap)
	if ep.DstToString() != "10.0.0.1:51820" {
		t.Errorf("DstToString() = %q, want %q", ep.DstToString(), "10.0.0.1:51820")
	}
}
