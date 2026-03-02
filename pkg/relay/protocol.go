package relay

import (
	"encoding/binary"
	"fmt"
	"io"
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
//   0xFF = Error:    body = UTF-8 error string

const (
	MsgRegister  byte = 0x01
	MsgData      byte = 0x02
	MsgKeepalive byte = 0x03
	MsgError     byte = 0xFF

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
