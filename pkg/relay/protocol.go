package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Wire protocol for WireKube relay.
//
// Frame layout (big-endian):
//   [4 bytes] total payload length (N)
//   [1 byte]  message type
//   [N-1 bytes] message body
//
// Message types:
//   0x01 = Register: body = [32 bytes WG public key]
//   0x02 = Data:     body = [32 bytes dest public key] + [UDP payload]
//   0x03 = Keepalive: body = empty
//   0x04 = NATProbe: body = [4 bytes IPv4][2 bytes port]
//   0x05 = BimodalHint: body = [32 bytes dest public key]
//   0xFF = Error:    body = UTF-8 error string
//
// BimodalHint is sent by a peer that suspects its inbound direct path is
// blocked (direct-receive watermark stale). The relay forwards the hint to
// the destination peer, which then dual-sends every subsequent packet on
// both direct and relay legs for a short window. Without this signal,
// asymmetric (one-way) UDP drops would stall for ~30s until the local FSM
// demotes the path; hints collapse the blackout to a single trust window.

const (
	MsgRegister    byte = 0x01
	MsgData        byte = 0x02
	MsgKeepalive   byte = 0x03
	MsgNATProbe    byte = 0x04
	MsgBimodalHint byte = 0x05
	MsgError       byte = 0xFF

	MaxFrameSize = 65536
	PubKeySize   = 32
)

type Frame struct {
	Type byte
	Body []byte
}

func WriteFrame(w io.Writer, f Frame) error {
	length := uint32(1 + len(f.Body))
	if length > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", length)
	}
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[:4], length)
	header[4] = f.Type
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(f.Body) > 0 {
		_, err := w.Write(f.Body)
		return err
	}
	return nil
}

func ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(header[:4])
	if length == 0 || length > MaxFrameSize {
		return Frame{}, fmt.Errorf("invalid frame length: %d", length)
	}
	msgType := header[4]
	bodyLen := length - 1
	var body []byte
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: msgType, Body: body}, nil
}

func MakeRegisterFrame(pubKey [PubKeySize]byte) Frame {
	return Frame{Type: MsgRegister, Body: pubKey[:]}
}

func MakeDataFrame(destPubKey [PubKeySize]byte, payload []byte) Frame {
	body := make([]byte, PubKeySize+len(payload))
	copy(body[:PubKeySize], destPubKey[:])
	copy(body[PubKeySize:], payload)
	return Frame{Type: MsgData, Body: body}
}

func MakeKeepaliveFrame() Frame {
	return Frame{Type: MsgKeepalive}
}

func MakeErrorFrame(msg string) Frame {
	return Frame{Type: MsgError, Body: []byte(msg)}
}

func ParseDataFrame(body []byte) (destPubKey [PubKeySize]byte, payload []byte, err error) {
	if len(body) < PubKeySize {
		return destPubKey, nil, fmt.Errorf("data frame too short: %d", len(body))
	}
	copy(destPubKey[:], body[:PubKeySize])
	payload = body[PubKeySize:]
	return
}

// MakeNATProbeFrame creates a frame requesting the relay to send a UDP probe
// to the specified endpoint from a different source port. Used by agents to
// detect port-restricted cone NAT: if the agent receives the probe, it is NOT
// port-restricted; if it doesn't, it IS port-restricted.
// Body layout: [4 bytes IPv4][2 bytes port big-endian]
func MakeNATProbeFrame(ip net.IP, port int) Frame {
	body := make([]byte, 6)
	copy(body[:4], ip.To4())
	binary.BigEndian.PutUint16(body[4:], uint16(port))
	return Frame{Type: MsgNATProbe, Body: body}
}

// ParseNATProbeFrame extracts the target IP and port from a NATProbe frame body.
func ParseNATProbeFrame(body []byte) (net.IP, int, error) {
	if len(body) < 6 {
		return nil, 0, fmt.Errorf("NAT probe frame too short: %d", len(body))
	}
	ip := net.IPv4(body[0], body[1], body[2], body[3])
	port := int(binary.BigEndian.Uint16(body[4:]))
	return ip, port, nil
}

// MakeBimodalHintFrame creates a hint requesting the destination peer to
// dual-send on both legs. Body is just the destination public key; the
// sender is identified by the relay connection it arrives on.
func MakeBimodalHintFrame(destPubKey [PubKeySize]byte) Frame {
	return Frame{Type: MsgBimodalHint, Body: destPubKey[:]}
}

// ParseBimodalHintFrame extracts the destination public key from a hint body.
func ParseBimodalHintFrame(body []byte) (destPubKey [PubKeySize]byte, err error) {
	if len(body) < PubKeySize {
		return destPubKey, fmt.Errorf("bimodal hint frame too short: %d", len(body))
	}
	copy(destPubKey[:], body[:PubKeySize])
	return
}
