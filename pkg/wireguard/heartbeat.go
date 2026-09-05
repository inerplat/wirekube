package wireguard

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Heartbeat control frames travel on the Bind's direct UDP socket alongside
// WireGuard's own packets and never reach wireguard-go: the receive path
// checks the magic before the peer lookup and consumes the frame. A pong is
// the Bind's evidence that a frame of the probed size made a UDP round trip
// to the probed address; it says nothing about the WireGuard session above.
//
//	offset  size  field
//	0       4     magic "WKHB". wireguard-go reads the first 4 bytes as a
//	              little-endian uint32 message type; 0x42484B57 matches none of 1..4.
//	4       1     version = 1
//	5       1     type: 1 = ping, 2 = pong
//	6       2     frame_len, big-endian, total datagram length including padding
//	8       12    txid (random for ping; echoed for pong)
//	20      8     sent_at, unix nanoseconds at the ping sender, big-endian (echoed)
//	28      32    sender WireGuard public key
//	60      32    mac = HMAC-SHA256(k_pair, bytes[0:60])
//	92      pad   zero padding up to frame_len; not covered by the MAC, but
//	              frame_len is, so truncation or extension is detected
const (
	heartbeatMagic     = "WKHB"
	heartbeatVersion   = 1
	heartbeatTypePing  = 1
	heartbeatTypePong  = 2
	heartbeatMACOffset = 60
	heartbeatMinLen    = heartbeatMACOffset + sha256.Size // 92: a frame with no padding
	heartbeatKeyInfo   = "wirekube heartbeat v1"
)

// heartbeatFrame is the decoded fixed header of a heartbeat datagram.
type heartbeatFrame struct {
	Type     uint8
	FrameLen uint16
	TxID     [12]byte
	SentAt   int64
	Sender   [32]byte
}

// hasHeartbeatMagic reports whether a datagram is long enough to be a
// heartbeat frame and starts with the heartbeat magic. Anything else takes
// the normal WireGuard receive path.
func hasHeartbeatMagic(b []byte) bool {
	return len(b) >= heartbeatMinLen && string(b[:4]) == heartbeatMagic
}

// encodeHeartbeat serialises f into a datagram of f.FrameLen bytes, sealed
// with HMAC-SHA256 under key. Padding beyond the MAC is zero.
func encodeHeartbeat(f heartbeatFrame, key []byte) []byte {
	if f.FrameLen < heartbeatMinLen {
		f.FrameLen = heartbeatMinLen
	}
	buf := make([]byte, int(f.FrameLen))
	copy(buf[0:4], heartbeatMagic)
	buf[4] = heartbeatVersion
	buf[5] = f.Type
	binary.BigEndian.PutUint16(buf[6:8], f.FrameLen)
	copy(buf[8:20], f.TxID[:])
	binary.BigEndian.PutUint64(buf[20:28], uint64(f.SentAt))
	copy(buf[28:60], f.Sender[:])
	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:heartbeatMACOffset])
	mac.Sum(buf[heartbeatMACOffset:heartbeatMACOffset])
	return buf
}

// decodeHeartbeatHeader parses the fixed header of a datagram that already
// passed hasHeartbeatMagic. It performs no authentication. The second result
// is false for an unsupported version; the fields are still filled so the
// caller can attribute the drop to the claimed sender.
func decodeHeartbeatHeader(b []byte) (heartbeatFrame, bool) {
	var f heartbeatFrame
	f.Type = b[5]
	f.FrameLen = binary.BigEndian.Uint16(b[6:8])
	copy(f.TxID[:], b[8:20])
	f.SentAt = int64(binary.BigEndian.Uint64(b[20:28]))
	copy(f.Sender[:], b[28:60])
	return f, b[4] == heartbeatVersion
}

// verifyHeartbeatMAC checks the frame's MAC over bytes[0:60] in constant time.
func verifyHeartbeatMAC(b []byte, key []byte) bool {
	if len(b) < heartbeatMinLen {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:heartbeatMACOffset])
	return hmac.Equal(mac.Sum(nil), b[heartbeatMACOffset:heartbeatMinLen])
}

// deriveHeartbeatKey computes the pair key both sides agree on:
//
//	k_pair = HKDF-SHA256(ikm = X25519(our_priv, peer_pub), salt = "",
//	                     info = "wirekube heartbeat v1" || sort(our_pub, peer_pub))
//
// The key is static per pair and provides authentication only; a static-key
// compromise is already a full WireGuard compromise, so no forward secrecy is
// lost. An error means the peer key is not a valid X25519 point (for example
// all zeros); the caller leaves heartbeats disabled for that peer.
func deriveHeartbeatKey(ourPriv, ourPub, peerPub [32]byte) (*[32]byte, error) {
	shared, err := curve25519.X25519(ourPriv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	info := make([]byte, 0, len(heartbeatKeyInfo)+64)
	info = append(info, heartbeatKeyInfo...)
	if bytes.Compare(ourPub[:], peerPub[:]) <= 0 {
		info = append(info, ourPub[:]...)
		info = append(info, peerPub[:]...)
	} else {
		info = append(info, peerPub[:]...)
		info = append(info, ourPub[:]...)
	}
	var key [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, info), key[:]); err != nil {
		return nil, err
	}
	return &key, nil
}

// heartbeatMTUProbeLen is the size of the MTU probe: the WireGuard outer
// transport frame for a full-size inner packet (16-byte transport header +
// 16-byte Poly1305 tag), 1452 for the default 1420. Both go through the same
// socket as WireGuard data, so mark, DF, and PMTU-cache handling are identical.
// heartbeatSizeSlack is how far above this node's own MTU probe an inbound
// ping may be and still be reflected, covering a peer configured with a
// larger mesh MTU mid-rollout.
const heartbeatSizeSlack = 128

func heartbeatMTUProbeLen(mtu int) int {
	return mtu + 32
}

// heartbeatPingSizeAllowed reports whether an inbound ping is a size this
// node is willing to reflect. A range rather than the two exact sizes the
// local scheduler emits: the sender's probe size comes from *its* mesh MTU,
// and during an MTU change the two nodes disagree for a rolling restart. With
// an exact match that window turns legitimate probes into authentication
// failures on the receiver and latches the sender's MTU-stale veto, which is
// a worse outcome than reflecting a frame a few bytes off. The reflection
// ratio stays exactly 1.0 either way because the pong mirrors frame_len, and
// the upper bound keeps the reflected volume tied to this node's own MTU.
func heartbeatPingSizeAllowed(frameLen int, mtu int) bool {
	return frameLen >= heartbeatMinLen && frameLen <= heartbeatMTUProbeLen(mtu)+heartbeatSizeSlack
}
