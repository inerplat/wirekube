package relay

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

// UDPProxy bridges between kernel WireGuard and the relay TCP connection
// for a single peer. Uses a connected UDP socket (DialUDP) for port
// consistency. Writing adaptively selects between Go's conn.Write and raw
// syscall.Write — the latter bypasses Cilium's cgroup BPF sendmsg hook
// (cil_sock4_sendmsg) which returns EPERM in some container environments.
type UDPProxy struct {
	peerPubKey [relayproto.PubKeySize]byte
	client     *Client
	wgPort     int

	conn     *net.UDPConn
	writeFD  int          // dup'd fd for raw syscall.Write fallback
	rawMode  atomic.Bool  // true after EPERM detected → use syscall.Write
	stopOnce sync.Once
	stopCh   chan struct{}
}

func NewUDPProxy(peerPubKey [relayproto.PubKeySize]byte, client *Client, wgPort int) (*UDPProxy, error) {
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort}

	conn, err := net.DialUDP("udp4", localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	// Pre-dup the fd for potential raw syscall.Write fallback.
	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("getting raw conn: %w", err)
	}
	var writeFD int
	var fdErr error
	if err := rawConn.Control(func(fd uintptr) {
		writeFD, fdErr = syscall.Dup(int(fd))
	}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("control: %w", err)
	}
	if fdErr != nil {
		conn.Close()
		return nil, fmt.Errorf("dup fd: %w", fdErr)
	}

	return &UDPProxy{
		peerPubKey: peerPubKey,
		client:     client,
		wgPort:     wgPort,
		conn:       conn,
		writeFD:    writeFD,
		stopCh:     make(chan struct{}),
	}, nil
}

func (p *UDPProxy) ListenAddr() string {
	return p.conn.LocalAddr().String()
}

func (p *UDPProxy) Run() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		n, err := p.conn.Read(buf)
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
				log.Printf("relay-proxy: read from wg: %v", err)
			}
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		if err := p.client.SendToPeer(p.peerPubKey, payload); err != nil {
			log.Printf("relay-proxy: send to relay: %v", err)
		}
	}
}

// DeliverToWireGuard sends a relay packet to the local WireGuard interface.
// Adaptively uses conn.Write (standard) or syscall.Write (raw fd) based on
// whether cgroup BPF EPERM has been detected.
func (p *UDPProxy) DeliverToWireGuard(payload []byte) {
	if p.rawMode.Load() {
		if _, err := syscall.Write(p.writeFD, payload); err != nil {
			log.Printf("relay-proxy: raw write to wg: %v", err)
		}
		return
	}

	_, err := p.conn.Write(payload)
	if err == nil {
		return
	}

	// Detect EPERM from cgroup BPF (Cilium cil_sock4_sendmsg or similar).
	// Switch to raw syscall.Write which uses write(2) on a connected socket,
	// bypassing BPF_CGROUP_UDP4_SENDMSG (only triggered by sendto/sendmsg
	// with msg_name set).
	if errors.Is(err, syscall.EPERM) {
		log.Printf("relay-proxy: EPERM detected, switching to raw syscall.Write mode")
		p.rawMode.Store(true)
		if _, werr := syscall.Write(p.writeFD, payload); werr != nil {
			log.Printf("relay-proxy: raw write to wg: %v", werr)
		}
		return
	}

	log.Printf("relay-proxy: write to wg: %v", err)
}

func (p *UDPProxy) Close() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.conn.Close()
		syscall.Close(p.writeFD)
	})
}
