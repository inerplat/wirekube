//go:build linux
// +build linux

package wireguard

import (
	"net"
	"testing"
)

func TestDecodeKey_Valid(t *testing.T) {
	// Generate a real keypair and test decode
	kp, err := generateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	key, err := decodeKey(kp.PublicKeyBase64()) //nolint:staticcheck
	if err != nil {
		t.Fatalf("decodeKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestDecodeKey_InvalidBase64(t *testing.T) {
	_, err := decodeKey("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeKey_WrongLength(t *testing.T) {
	// Valid base64 but wrong length (16 bytes instead of 32)
	_, err := decodeKey("AAAAAAAAAAAAAAAAAAAAAA==")
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestParseAllowedIPs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantN   int
		wantErr bool
	}{
		{"single /32", []string{"10.0.0.1/32"}, 1, false},
		{"multiple", []string{"10.0.0.0/24", "192.168.1.0/24"}, 2, false},
		{"empty", []string{}, 0, false},
		{"invalid", []string{"not-a-cidr"}, 0, true},
		{"mixed valid/invalid", []string{"10.0.0.1/32", "bad"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowedIPs(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAllowedIPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantN {
				t.Errorf("parseAllowedIPs() returned %d nets, want %d", len(got), tt.wantN)
			}
		})
	}
}

func TestParseAllowedIPs_Correctness(t *testing.T) {
	cidrs := []string{"10.0.0.1/32", "192.168.0.0/16"}
	nets, err := parseAllowedIPs(cidrs)
	if err != nil {
		t.Fatal(err)
	}

	// Check first CIDR
	expectedIP := net.ParseIP("10.0.0.1")
	if !nets[0].IP.Equal(expectedIP) {
		t.Errorf("first IP: got %s, want %s", nets[0].IP, expectedIP)
	}

	// Check second CIDR network
	if !nets[1].Contains(net.ParseIP("192.168.1.1")) {
		t.Error("second net should contain 192.168.1.1")
	}
	if nets[1].Contains(net.ParseIP("10.0.0.1")) {
		t.Error("second net should not contain 10.0.0.1")
	}
}

func TestIsRouteExists(t *testing.T) {
	if isRouteExists(nil) {
		t.Error("nil error should return false")
	}
}

func TestPeerConfig_Fields(t *testing.T) {
	pc := PeerConfig{
		PublicKeyB64:     "dGVzdA==",
		Endpoint:         "1.2.3.4:51820",
		AllowedIPs:       []string{"10.0.0.1/32"},
		KeepaliveSeconds: 25,
		ForceEndpoint:    true,
	}

	if pc.PublicKeyB64 != "dGVzdA==" {
		t.Error("PublicKeyB64 mismatch")
	}
	if !pc.ForceEndpoint {
		t.Error("ForceEndpoint should be true")
	}
}
