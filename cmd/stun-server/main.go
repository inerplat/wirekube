// Package main implements a minimal STUN server (RFC 5389 / RFC 8489) for
// testing WireKube NAT type detection in controlled environments such as kind
// clusters. It responds to Binding Requests with the client's observed address
// using XOR-MAPPED-ADDRESS, which is sufficient for NAT type classification.
//
// Usage:
//
//	wirekube-stun [addr]    (default: :3478)
package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/pion/stun/v3"
)

func main() {
	addr := ":3478"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Fatalf("stun-server: listen %s: %v", addr, err)
	}
	defer conn.Close()

	fmt.Printf("stun-server: listening on %s\n", conn.LocalAddr())

	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			// Listener was closed (e.g. test teardown).
			return
		}

		var req stun.Message
		req.Raw = make([]byte, n)
		copy(req.Raw, buf[:n])
		if err := req.Decode(); err != nil {
			// Not a STUN message — ignore silently.
			continue
		}
		if req.Type != stun.BindingRequest {
			continue
		}

		udpFrom, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}

		if err := respond(conn, from, udpFrom, &req); err != nil {
			log.Printf("stun-server: respond to %s: %v", from, err)
		}
	}
}

// transactionIDSetter echoes the request's transaction ID into the response
// so the client can match the response to its original request.
// stun.Message.TransactionID is [12]byte (stun.TransactionIDSize = 12).
type transactionIDSetter [12]byte

func (t transactionIDSetter) AddTo(m *stun.Message) error {
	copy(m.TransactionID[:], t[:])
	return nil
}

func respond(conn net.PacketConn, to net.Addr, observed *net.UDPAddr, req *stun.Message) error {
	ip := observed.IP.To4()
	if ip == nil {
		ip = observed.IP
	}

	res, err := stun.Build(
		stun.BindingSuccess,
		transactionIDSetter(req.TransactionID),
		&stun.XORMappedAddress{
			IP:   ip,
			Port: observed.Port,
		},
	)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}

	_, err = conn.WriteTo(res.Raw, to)
	return err
}
