package relay

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestWriteReadFrame_Roundtrip(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{"register", MakeRegisterFrame([PubKeySize]byte{1, 2, 3})},
		{"keepalive", MakeKeepaliveFrame()},
		{"error", MakeErrorFrame("something went wrong")},
		{"data", MakeDataFrame([PubKeySize]byte{0xAA}, []byte("hello wireguard"))},
		{"empty body", Frame{Type: 0x42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tt.frame); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}

			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}

			if got.Type != tt.frame.Type {
				t.Errorf("type: got %d, want %d", got.Type, tt.frame.Type)
			}
			if !bytes.Equal(got.Body, tt.frame.Body) {
				t.Errorf("body: got %x, want %x", got.Body, tt.frame.Body)
			}
		})
	}
}

func TestWriteFrame_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	huge := Frame{Type: MsgData, Body: make([]byte, MaxFrameSize)}
	if err := WriteFrame(&buf, huge); err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadFrame_InvalidLength(t *testing.T) {
	// Length = 0 (invalid)
	data := []byte{0, 0, 0, 0, MsgKeepalive}
	_, err := ReadFrame(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for zero-length frame")
	}

	// Length exceeds MaxFrameSize
	data = []byte{0xFF, 0xFF, 0xFF, 0xFF, MsgKeepalive}
	_, err = ReadFrame(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for oversized frame length")
	}
}

func TestReadFrame_Truncated(t *testing.T) {
	// Only 3 bytes of header (need 5)
	_, err := ReadFrame(bytes.NewReader([]byte{0, 0, 1}))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}

	// Valid header claiming 10 bytes body, but only 3 available
	data := []byte{0, 0, 0, 11, MsgData, 1, 2, 3}
	_, err = ReadFrame(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for truncated body")
	}
}

func TestMakeDataFrame_ParseDataFrame_Roundtrip(t *testing.T) {
	var destKey [PubKeySize]byte
	for i := range destKey {
		destKey[i] = byte(i)
	}
	payload := []byte("test payload data")

	frame := MakeDataFrame(destKey, payload)
	if frame.Type != MsgData {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgData)
	}

	gotKey, gotPayload, err := ParseDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseDataFrame: %v", err)
	}
	if gotKey != destKey {
		t.Errorf("destKey mismatch")
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload: got %q, want %q", gotPayload, payload)
	}
}

func TestMakeExternalDataFrame_ParseExternalDataFrame_Roundtrip(t *testing.T) {
	payload := []byte("raw wireguard datagram")
	frame := MakeExternalDataFrame(42, "203.0.113.20:51820", payload)
	if frame.Type != MsgExternalData {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgExternalData)
	}

	token, addr, gotPayload, err := ParseExternalDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame: %v", err)
	}
	if token != 42 {
		t.Fatalf("token = %d, want 42", token)
	}
	if addr != "203.0.113.20:51820" {
		t.Fatalf("addr = %q", addr)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %q, want %q", gotPayload, payload)
	}
}

func TestParseExternalDataFrame_TooShort(t *testing.T) {
	if _, _, _, err := ParseExternalDataFrame([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short external data frame")
	}
}

func TestParseDataFrame_TooShort(t *testing.T) {
	_, _, err := ParseDataFrame([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short data frame")
	}
}

func TestMakeNATProbeFrame_ParseNATProbeFrame_Roundtrip(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 100)
	port := 12345

	frame := MakeNATProbeFrame(ip, port)
	if frame.Type != MsgNATProbe {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgNATProbe)
	}

	gotIP, gotPort, err := ParseNATProbeFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseNATProbeFrame: %v", err)
	}
	if !gotIP.Equal(ip) {
		t.Errorf("IP: got %s, want %s", gotIP, ip)
	}
	if gotPort != port {
		t.Errorf("port: got %d, want %d", gotPort, port)
	}
}

func TestParseNATProbeFrame_TooShort(t *testing.T) {
	_, _, err := ParseNATProbeFrame([]byte{1, 2})
	if err == nil {
		t.Fatal("expected error for short NAT probe frame")
	}
}

func TestMultipleFrames_Sequential(t *testing.T) {
	var buf bytes.Buffer
	frames := []Frame{
		MakeRegisterFrame([PubKeySize]byte{0x01}),
		MakeKeepaliveFrame(),
		MakeDataFrame([PubKeySize]byte{0x02}, []byte("data")),
		MakeErrorFrame("err"),
	}

	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("frame[%d] type: got %d, want %d", i, got.Type, want.Type)
		}
		if !bytes.Equal(got.Body, want.Body) {
			t.Errorf("frame[%d] body mismatch", i)
		}
	}
}

func TestMakeRegisterFrame(t *testing.T) {
	var key [PubKeySize]byte
	key[0] = 0xFF
	key[31] = 0x01

	frame := MakeRegisterFrame(key)
	if frame.Type != MsgRegister {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgRegister)
	}
	if len(frame.Body) != PubKeySize {
		t.Fatalf("body length: got %d, want %d", len(frame.Body), PubKeySize)
	}
	if frame.Body[0] != 0xFF || frame.Body[31] != 0x01 {
		t.Error("key content mismatch")
	}
}

func TestMakeRelayProbeFrame_ParseRelayProbeFrame_Roundtrip(t *testing.T) {
	const token uint64 = 0x0102030405060708
	frame := MakeRelayProbeFrame(token)
	if frame.Type != MsgRelayProbe {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgRelayProbe)
	}
	got, err := ParseRelayProbeFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseRelayProbeFrame: %v", err)
	}
	if got != token {
		t.Fatalf("token = %#x, want %#x", got, token)
	}
}

func TestParseRelayProbeFrame_TooShort(t *testing.T) {
	if _, err := ParseRelayProbeFrame([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short relay probe frame")
	}
}

func TestMakeForwarderRegisterFrame_ParseForwarderRegisterFrame_Roundtrip(t *testing.T) {
	var ingressKey, externalKey [PubKeySize]byte
	for i := range ingressKey {
		ingressKey[i] = byte(i)
		externalKey[i] = byte(0xFF - i)
	}
	const port uint16 = 53042

	frame := MakeForwarderRegisterFrame(port, ingressKey, externalKey)
	if frame.Type != MsgForwarderRegister {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgForwarderRegister)
	}

	gotPort, gotIngress, gotExt, err := ParseForwarderRegisterFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseForwarderRegisterFrame: %v", err)
	}
	if gotPort != port {
		t.Errorf("port: got %d, want %d", gotPort, port)
	}
	if gotIngress != ingressKey {
		t.Errorf("ingress pubkey mismatch")
	}
	if gotExt != externalKey {
		t.Errorf("external pubkey mismatch")
	}

	// Roundtrip through wire framing as well.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != MsgForwarderRegister {
		t.Errorf("wire type: got %d, want %d", got.Type, MsgForwarderRegister)
	}
	if !bytes.Equal(got.Body, frame.Body) {
		t.Errorf("wire body mismatch")
	}
}

func TestParseForwarderRegisterFrame_TooShort(t *testing.T) {
	// 2 bytes port + 32 bytes ingress pubkey, missing the external pubkey.
	body := make([]byte, 2+PubKeySize)
	if _, _, _, err := ParseForwarderRegisterFrame(body); err == nil {
		t.Fatal("expected error for short forwarder register frame")
	}
}

func TestMakeForwarderUnregisterFrame_ParseForwarderUnregisterFrame_Roundtrip(t *testing.T) {
	const port uint16 = 40000

	frame := MakeForwarderUnregisterFrame(port)
	if frame.Type != MsgForwarderUnregister {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgForwarderUnregister)
	}

	gotPort, err := ParseForwarderUnregisterFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseForwarderUnregisterFrame: %v", err)
	}
	if gotPort != port {
		t.Errorf("port: got %d, want %d", gotPort, port)
	}
}

func TestParseForwarderUnregisterFrame_TooShort(t *testing.T) {
	if _, err := ParseForwarderUnregisterFrame([]byte{0x42}); err == nil {
		t.Fatal("expected error for short forwarder unregister frame")
	}
}

func TestMakeForwarderStatsRequestFrame_ParseForwarderStatsRequestFrame_Roundtrip(t *testing.T) {
	const port uint16 = 32768

	frame := MakeForwarderStatsRequestFrame(port)
	if frame.Type != MsgForwarderStats {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgForwarderStats)
	}

	gotPort, err := ParseForwarderStatsRequestFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseForwarderStatsRequestFrame: %v", err)
	}
	if gotPort != port {
		t.Errorf("port: got %d, want %d", gotPort, port)
	}
}

func TestParseForwarderStatsRequestFrame_TooShort(t *testing.T) {
	if _, err := ParseForwarderStatsRequestFrame(nil); err == nil {
		t.Fatal("expected error for empty forwarder stats request frame")
	}
}

func TestMakeForwarderStatsResponseFrame_ParseForwarderStatsResponseFrame_Roundtrip(t *testing.T) {
	const (
		port               uint16 = 36123
		bytesIn            uint64 = 0xDEADBEEFCAFEBABE
		bytesOut           uint64 = 0x0123456789ABCDEF
		lastPacketUnixNano int64  = 1714281600123456789
	)

	frame := MakeForwarderStatsResponseFrame(port, bytesIn, bytesOut, lastPacketUnixNano)
	if frame.Type != MsgForwarderStats {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgForwarderStats)
	}

	gotPort, gotIn, gotOut, gotLast, err := ParseForwarderStatsResponseFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseForwarderStatsResponseFrame: %v", err)
	}
	if gotPort != port {
		t.Errorf("port: got %d, want %d", gotPort, port)
	}
	if gotIn != bytesIn {
		t.Errorf("bytesIn: got %d, want %d", gotIn, bytesIn)
	}
	if gotOut != bytesOut {
		t.Errorf("bytesOut: got %d, want %d", gotOut, bytesOut)
	}
	if gotLast != lastPacketUnixNano {
		t.Errorf("lastPacketUnixNano: got %d, want %d", gotLast, lastPacketUnixNano)
	}

	// Roundtrip through wire framing as well.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != MsgForwarderStats {
		t.Errorf("wire type: got %d, want %d", got.Type, MsgForwarderStats)
	}
	if !bytes.Equal(got.Body, frame.Body) {
		t.Errorf("wire body mismatch")
	}
}

func TestParseForwarderStatsResponseFrame_TooShort(t *testing.T) {
	// One byte short of the full 26-byte body.
	body := make([]byte, 25)
	if _, _, _, _, err := ParseForwarderStatsResponseFrame(body); err == nil {
		t.Fatal("expected error for short forwarder stats response frame")
	}
}

func TestMakeIngressProbeRequestFrame_ParseIngressProbeRequestFrame_Roundtrip(t *testing.T) {
	keys := [][PubKeySize]byte{pubkey(0x10), pubkey(0x20)}
	frame := MakeIngressProbeRequestFrame(keys)
	if frame.Type != MsgIngressProbe {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgIngressProbe)
	}
	got, err := ParseIngressProbeRequestFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseIngressProbeRequestFrame: %v", err)
	}
	if len(got) != len(keys) {
		t.Fatalf("len = %d, want %d", len(got), len(keys))
	}
	for i := range keys {
		if got[i] != keys[i] {
			t.Fatalf("key[%d] mismatch", i)
		}
	}
}

func TestParseIngressProbeRequestFrame_TooShort(t *testing.T) {
	body := []byte{0, 2}
	body = append(body, make([]byte, PubKeySize)...)
	if _, err := ParseIngressProbeRequestFrame(body); err == nil {
		t.Fatal("expected error for truncated ingress probe request")
	}
}

func TestMakeIngressProbeResponseFrame_ParseIngressProbeResponseFrame_Roundtrip(t *testing.T) {
	results := []IngressProbeResult{
		{PubKey: pubkey(0x10), RTT: 12 * time.Millisecond},
		{PubKey: pubkey(0x20), RTT: 3450 * time.Microsecond},
	}
	frame := MakeIngressProbeResponseFrame(results)
	if frame.Type != MsgIngressProbe {
		t.Fatalf("type: got %d, want %d", frame.Type, MsgIngressProbe)
	}
	got, err := ParseIngressProbeResponseFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseIngressProbeResponseFrame: %v", err)
	}
	if len(got) != len(results) {
		t.Fatalf("len = %d, want %d", len(got), len(results))
	}
	for i := range results {
		if got[i] != results[i] {
			t.Fatalf("result[%d] = %+v, want %+v", i, got[i], results[i])
		}
	}
}

func TestParseIngressProbeResponseFrame_TooShort(t *testing.T) {
	body := []byte{0, 1}
	body = append(body, make([]byte, PubKeySize)...)
	if _, err := ParseIngressProbeResponseFrame(body); err == nil {
		t.Fatal("expected error for truncated ingress probe response")
	}
}

func TestForwarderFrames_DistinguishedByLength(t *testing.T) {
	// MsgForwarderStats is overloaded for request and response. Verify the
	// two body sizes are distinct so a receiver can disambiguate by length.
	req := MakeForwarderStatsRequestFrame(1234)
	resp := MakeForwarderStatsResponseFrame(1234, 1, 2, 3)
	if len(req.Body) == len(resp.Body) {
		t.Fatalf("request and response bodies have identical length %d; receiver cannot disambiguate", len(req.Body))
	}
}
