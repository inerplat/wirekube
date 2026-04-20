package wireguard

import "testing"

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
