package relay

import (
	"bytes"
	"net"
	"testing"
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
