package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
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
//   0x06 = RelayProbe: body = [8 bytes probe token]
//   0x10 = ForwarderRegister: body = [2 bytes UDP port][32 bytes ingress pubkey][32 bytes external pubkey]
//   0x11 = ForwarderUnregister: body = [2 bytes UDP port]
//   0x12 = ForwarderStats: request body = [2 bytes UDP port]
//                          response body = [2 bytes UDP port][8 bytes bytesIn][8 bytes bytesOut][8 bytes lastPacketUnixNano]
//   0x13 = IngressProbe: request body = [2 bytes count][32 bytes ingress pubkey]...
//                         response body = [2 bytes count]([32 bytes ingress pubkey][8 bytes RTT ns])...
//   0x20 = ExternalData: body = [8 bytes source token][2 bytes source addr length][source addr string][WG payload]
//   0xFF = Error:    body = UTF-8 error string
//
// BimodalHint is sent by a peer that suspects its inbound direct path is
// blocked (direct-receive watermark stale). The relay forwards the hint to
// the destination peer, which then dual-sends every subsequent packet on
// both direct and relay legs for a short window. Without this signal,
// asymmetric (one-way) UDP drops would stall for ~30s until the local FSM
// demotes the path; hints collapse the blackout to a single trust window.

const (
	MsgRegister            byte = 0x01
	MsgData                byte = 0x02
	MsgKeepalive           byte = 0x03
	MsgNATProbe            byte = 0x04
	MsgBimodalHint         byte = 0x05
	MsgRelayProbe          byte = 0x06
	MsgForwarderRegister   byte = 0x10
	MsgForwarderUnregister byte = 0x11
	MsgForwarderStats      byte = 0x12
	MsgIngressProbe        byte = 0x13
	MsgExternalData        byte = 0x20
	MsgError               byte = 0xFF

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

func MakeRelayProbeFrame(token uint64) Frame {
	body := make([]byte, 8)
	binary.BigEndian.PutUint64(body, token)
	return Frame{Type: MsgRelayProbe, Body: body}
}

func ParseRelayProbeFrame(body []byte) (uint64, error) {
	if len(body) < 8 {
		return 0, fmt.Errorf("relay probe frame too short: %d", len(body))
	}
	return binary.BigEndian.Uint64(body[:8]), nil
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

// MakeForwarderRegisterFrame requests the relay to allocate a per-external-peer
// UDP forwarder bound to udpPort that maps inbound external traffic to the
// given ingress peer. externalPubkey identifies the WireGuard peer the
// ingress peer expects on the inner tunnel.
// Body layout: [2 bytes UDP port][32 bytes ingress pubkey][32 bytes external pubkey]
func MakeForwarderRegisterFrame(udpPort uint16, ingressPubkey, externalPubkey [PubKeySize]byte) Frame {
	body := make([]byte, 2+PubKeySize+PubKeySize)
	binary.BigEndian.PutUint16(body[:2], udpPort)
	copy(body[2:2+PubKeySize], ingressPubkey[:])
	copy(body[2+PubKeySize:], externalPubkey[:])
	return Frame{Type: MsgForwarderRegister, Body: body}
}

// ParseForwarderRegisterFrame extracts the UDP port and pubkeys from a
// ForwarderRegister frame body.
func ParseForwarderRegisterFrame(body []byte) (udpPort uint16, ingressPubkey, externalPubkey [PubKeySize]byte, err error) {
	if len(body) < 2+PubKeySize+PubKeySize {
		return 0, ingressPubkey, externalPubkey, fmt.Errorf("forwarder register frame too short: %d", len(body))
	}
	udpPort = binary.BigEndian.Uint16(body[:2])
	copy(ingressPubkey[:], body[2:2+PubKeySize])
	copy(externalPubkey[:], body[2+PubKeySize:2+PubKeySize+PubKeySize])
	return
}

// MakeForwarderUnregisterFrame requests the relay to tear down the forwarder
// previously allocated for udpPort.
// Body layout: [2 bytes UDP port]
func MakeForwarderUnregisterFrame(udpPort uint16) Frame {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body[:2], udpPort)
	return Frame{Type: MsgForwarderUnregister, Body: body}
}

// ParseForwarderUnregisterFrame extracts the UDP port from a
// ForwarderUnregister frame body.
func ParseForwarderUnregisterFrame(body []byte) (udpPort uint16, err error) {
	if len(body) < 2 {
		return 0, fmt.Errorf("forwarder unregister frame too short: %d", len(body))
	}
	udpPort = binary.BigEndian.Uint16(body[:2])
	return
}

// MakeForwarderStatsRequestFrame asks the relay for traffic counters on the
// forwarder bound to udpPort. The relay responds with another ForwarderStats
// frame whose body matches the response layout below.
// Body layout: [2 bytes UDP port]
func MakeForwarderStatsRequestFrame(udpPort uint16) Frame {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body[:2], udpPort)
	return Frame{Type: MsgForwarderStats, Body: body}
}

// ParseForwarderStatsRequestFrame extracts the UDP port from a
// ForwarderStats request body.
func ParseForwarderStatsRequestFrame(body []byte) (udpPort uint16, err error) {
	if len(body) < 2 {
		return 0, fmt.Errorf("forwarder stats request frame too short: %d", len(body))
	}
	udpPort = binary.BigEndian.Uint16(body[:2])
	return
}

// MakeForwarderStatsResponseFrame carries traffic counters and the most recent
// packet timestamp (UnixNano) for the forwarder bound to udpPort.
// Body layout: [2 bytes UDP port][8 bytes bytesIn][8 bytes bytesOut][8 bytes lastPacketUnixNano]
func MakeForwarderStatsResponseFrame(udpPort uint16, bytesIn, bytesOut uint64, lastPacketUnixNano int64) Frame {
	body := make([]byte, 2+8+8+8)
	binary.BigEndian.PutUint16(body[:2], udpPort)
	binary.BigEndian.PutUint64(body[2:10], bytesIn)
	binary.BigEndian.PutUint64(body[10:18], bytesOut)
	binary.BigEndian.PutUint64(body[18:26], uint64(lastPacketUnixNano))
	return Frame{Type: MsgForwarderStats, Body: body}
}

// ParseForwarderStatsResponseFrame extracts the UDP port, byte counters, and
// last-packet timestamp from a ForwarderStats response body.
func ParseForwarderStatsResponseFrame(body []byte) (udpPort uint16, bytesIn, bytesOut uint64, lastPacketUnixNano int64, err error) {
	if len(body) < 2+8+8+8 {
		return 0, 0, 0, 0, fmt.Errorf("forwarder stats response frame too short: %d", len(body))
	}
	udpPort = binary.BigEndian.Uint16(body[:2])
	bytesIn = binary.BigEndian.Uint64(body[2:10])
	bytesOut = binary.BigEndian.Uint64(body[10:18])
	lastPacketUnixNano = int64(binary.BigEndian.Uint64(body[18:26]))
	return
}

type IngressProbeResult struct {
	PubKey [PubKeySize]byte
	RTT    time.Duration
}

func MakeIngressProbeRequestFrame(pubKeys [][PubKeySize]byte) Frame {
	body := make([]byte, 2+len(pubKeys)*PubKeySize)
	binary.BigEndian.PutUint16(body[:2], uint16(len(pubKeys)))
	off := 2
	for _, key := range pubKeys {
		copy(body[off:off+PubKeySize], key[:])
		off += PubKeySize
	}
	return Frame{Type: MsgIngressProbe, Body: body}
}

func ParseIngressProbeRequestFrame(body []byte) ([][PubKeySize]byte, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("ingress probe request frame too short: %d", len(body))
	}
	count := int(binary.BigEndian.Uint16(body[:2]))
	want := 2 + count*PubKeySize
	if len(body) < want {
		return nil, fmt.Errorf("ingress probe request truncated: have %d want %d", len(body), want)
	}
	out := make([][PubKeySize]byte, count)
	off := 2
	for i := range out {
		copy(out[i][:], body[off:off+PubKeySize])
		off += PubKeySize
	}
	return out, nil
}

func MakeIngressProbeResponseFrame(results []IngressProbeResult) Frame {
	const entrySize = PubKeySize + 8
	body := make([]byte, 2+len(results)*entrySize)
	binary.BigEndian.PutUint16(body[:2], uint16(len(results)))
	off := 2
	for _, result := range results {
		copy(body[off:off+PubKeySize], result.PubKey[:])
		off += PubKeySize
		binary.BigEndian.PutUint64(body[off:off+8], uint64(result.RTT))
		off += 8
	}
	return Frame{Type: MsgIngressProbe, Body: body}
}

func ParseIngressProbeResponseFrame(body []byte) ([]IngressProbeResult, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("ingress probe response frame too short: %d", len(body))
	}
	const entrySize = PubKeySize + 8
	count := int(binary.BigEndian.Uint16(body[:2]))
	want := 2 + count*entrySize
	if len(body) < want {
		return nil, fmt.Errorf("ingress probe response truncated: have %d want %d", len(body), want)
	}
	out := make([]IngressProbeResult, count)
	off := 2
	for i := range out {
		copy(out[i].PubKey[:], body[off:off+PubKeySize])
		off += PubKeySize
		out[i].RTT = time.Duration(int64(binary.BigEndian.Uint64(body[off : off+8])))
		off += 8
	}
	return out, nil
}

// MakeExternalDataFrame carries a raw WireGuard UDP datagram for the shared
// external-peer listener. Relay → ingress frames include sourceAddr so the
// ingress bind can expose a stable endpoint to wireguard-go. Ingress → relay
// response frames may leave sourceAddr empty; the relay routes by sourceToken.
//
// Body layout: [8 bytes source token][2 bytes source addr length][source addr string][payload]
func MakeExternalDataFrame(sourceToken uint64, sourceAddr string, payload []byte) Frame {
	addrLen := len(sourceAddr)
	body := make([]byte, 8+2+addrLen+len(payload))
	binary.BigEndian.PutUint64(body[:8], sourceToken)
	binary.BigEndian.PutUint16(body[8:10], uint16(addrLen))
	copy(body[10:10+addrLen], sourceAddr)
	copy(body[10+addrLen:], payload)
	return Frame{Type: MsgExternalData, Body: body}
}

// ParseExternalDataFrame extracts the source token, optional source address,
// and raw WireGuard payload from an ExternalData frame.
func ParseExternalDataFrame(body []byte) (sourceToken uint64, sourceAddr string, payload []byte, err error) {
	if len(body) < 10 {
		return 0, "", nil, fmt.Errorf("external data frame too short: %d", len(body))
	}
	sourceToken = binary.BigEndian.Uint64(body[:8])
	addrLen := int(binary.BigEndian.Uint16(body[8:10]))
	if len(body) < 10+addrLen {
		return 0, "", nil, fmt.Errorf("external data frame source addr truncated: have %d want %d", len(body)-10, addrLen)
	}
	sourceAddr = string(body[10 : 10+addrLen])
	payload = body[10+addrLen:]
	return sourceToken, sourceAddr, payload, nil
}
