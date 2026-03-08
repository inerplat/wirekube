package relay

import (
	"errors"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

// Sender can deliver a UDP payload to a remote peer via the relay network.
// Both Client and Pool implement this interface.
type Sender interface {
	SendToPeer(destPubKey [relayproto.PubKeySize]byte, payload []byte) error
}

// UDPProxy bridges between kernel WireGuard and the relay TCP connection
// for a single peer. Uses an unconnected UDP socket (ListenUDP) so that it
// accepts packets regardless of source IP — necessary because WireGuard's
// fwmark routing may cause outgoing packets to use the node's physical IP
// as source even when the destination is loopback.
type UDPProxy struct {
	peerPubKey [relayproto.PubKeySize]byte
	sender     Sender
	wgPort     int
	wgAddr     *net.UDPAddr

	connMu       sync.RWMutex
	conn         *net.UDPConn
	recreateOnce sync.Once
	stopOnce     sync.Once
	stopCh       chan struct{}
}

func NewUDPProxy(peerPubKey [relayproto.PubKeySize]byte, sender Sender, wgPort int) (*UDPProxy, error) {
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, err
	}

	return &UDPProxy{
		peerPubKey: peerPubKey,
		sender:     sender,
		wgPort:     wgPort,
		wgAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort},
		conn:       conn,
		stopCh:     make(chan struct{}),
	}, nil
}

func (p *UDPProxy) ListenAddr() string {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
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

		p.connMu.RLock()
		conn := p.conn
		p.connMu.RUnlock()

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
			}
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		if err := p.sender.SendToPeer(p.peerPubKey, payload); err != nil {
			log.Printf("relay-proxy: send to relay: %v", err)
		}
	}
}

// DeliverToWireGuard sends a relay packet to the local WireGuard interface.
//
// Cilium's cgroup BPF sendmsg hook may reject sendto() with EPERM on sockets
// created during a brief window after pod restart (before Cilium finishes
// endpoint registration). The EPERM is bound to the socket, not the cgroup —
// new sockets created after the window work fine.  On EPERM we wait 3 seconds
// for the BPF state to settle, then close the tainted socket and bind a fresh
// one on the same port.  WireGuard's retransmissions cover the gap.
func (p *UDPProxy) DeliverToWireGuard(payload []byte) {
	p.connMu.RLock()
	conn := p.conn
	p.connMu.RUnlock()

	_, err := conn.WriteTo(payload, p.wgAddr)
	if err == nil {
		return
	}

	if errors.Is(err, syscall.EPERM) {
		log.Printf("relay-proxy: EPERM on port %d, scheduling socket recreation", p.wgPort)
		go p.recreateConn(payload)
		return
	}

	log.Printf("relay-proxy: write to wg port %d: %v", p.wgPort, err)
}

// recreateConn replaces the tainted UDP socket with a fresh one.
// Binds to the same local port so that the WireGuard peer endpoint
// remains valid without requiring a config resync.
func (p *UDPProxy) recreateConn(firstPayload []byte) {
	p.recreateOnce.Do(func() {
		select {
		case <-p.stopCh:
			return
		case <-time.After(3 * time.Second):
		}

		p.connMu.Lock()
		oldAddr := p.conn.LocalAddr().(*net.UDPAddr)
		p.conn.Close()

		newConn, err := net.ListenUDP("udp4", oldAddr)
		if err != nil {
			fallback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
			newConn, err = net.ListenUDP("udp4", fallback)
			if err != nil {
				log.Printf("relay-proxy: socket recreation failed: %v", err)
				p.connMu.Unlock()
				return
			}
			log.Printf("relay-proxy: bound to new port %s (original %s unavailable)", newConn.LocalAddr(), oldAddr)
		}

		p.conn = newConn
		p.connMu.Unlock()

		if _, err := newConn.WriteTo(firstPayload, p.wgAddr); err != nil {
			log.Printf("relay-proxy: write after recreation on port %d: %v", p.wgPort, err)
		} else {
			log.Printf("relay-proxy: EPERM resolved on port %d, listen %s", p.wgPort, newConn.LocalAddr())
		}
	})
}

func (p *UDPProxy) Close() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.connMu.RLock()
		p.conn.Close()
		p.connMu.RUnlock()
	})
}
