package relay

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Server is a WireKube relay server that forwards WireGuard UDP packets
// between agents connected over TCP. Agents register with their WireGuard
// public key; the server routes Data frames by destination public key.
type Server struct {
	mu    sync.RWMutex
	peers map[[PubKeySize]byte]*clientConn

	// probeConn is a UDP socket bound to the relay's listen port for sending
	// NAT verification probes. Agents open their NAT filter for this port,
	// so a probe from here distinguishes "firewall blocked" from "NAT blocked".
	probeConn *net.UDPConn

	// probeSem limits concurrent NAT probe goroutines to prevent unbounded
	// goroutine creation from rapid probe requests.
	probeSem chan struct{}
}

type clientConn struct {
	pubKey [PubKeySize]byte
	conn   net.Conn
	writer *bufio.Writer
	mu     sync.Mutex
}

func NewServer() *Server {
	return &Server{
		peers:    make(map[[PubKeySize]byte]*clientConn),
		probeSem: make(chan struct{}, 16),
	}
}

func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	// Bind a UDP socket on the same port for NAT verification probes.
	// Agents send a UDP packet to this port to open their NAT filter,
	// then we probe back from THIS socket as a verification that the
	// path is reachable (distinguishes firewall from NAT restriction).
	tcpAddr := ln.Addr().(*net.TCPAddr)
	udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}
	s.probeConn, err = net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Printf("relay: warning: UDP probe listener on %s failed: %v (verification probes disabled)", udpAddr, err)
	} else {
		log.Printf("relay: UDP probe listener on %s", udpAddr)
		defer s.probeConn.Close()
	}

	log.Printf("relay: listening on %s", addr)

	var acceptBackoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("relay: accept error: %v", err)
			if acceptBackoff == 0 {
				acceptBackoff = 5 * time.Millisecond
			} else {
				acceptBackoff *= 2
				if acceptBackoff > time.Second {
					acceptBackoff = time.Second
				}
			}
			time.Sleep(acceptBackoff)
			continue
		}
		acceptBackoff = 0
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) //nolint:errcheck
	}
	reader := bufio.NewReader(conn)

	frame, err := ReadFrame(reader)
	if err != nil {
		// TCP health probes (kubelet liveness/readiness) connect and immediately
		// close without sending data — suppress the noisy EOF log for these.
		if err.Error() != "EOF" {
			log.Printf("relay: read register frame: %v", err)
		}
		return
	}
	if frame.Type != MsgRegister {
		log.Printf("relay: expected register, got type %d", frame.Type)
		return
	}
	if len(frame.Body) != PubKeySize {
		log.Printf("relay: invalid pubkey length %d", len(frame.Body))
		return
	}

	var pubKey [PubKeySize]byte
	copy(pubKey[:], frame.Body)

	cc := &clientConn{
		pubKey: pubKey,
		conn:   conn,
		writer: bufio.NewWriterSize(conn, 64*1024),
	}

	s.mu.Lock()
	old, exists := s.peers[pubKey]
	s.peers[pubKey] = cc
	s.mu.Unlock()

	if exists {
		old.conn.Close()
	}

	log.Printf("relay: peer registered: %x", pubKey[:8])
	defer func() {
		s.mu.Lock()
		if s.peers[pubKey] == cc {
			delete(s.peers, pubKey)
		}
		s.mu.Unlock()
		log.Printf("relay: peer disconnected: %x", pubKey[:8])
	}()

	for {
		frame, err := ReadFrame(reader)
		if err != nil {
			return
		}

		switch frame.Type {
		case MsgData:
			destKey, payload, err := ParseDataFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad data frame: %v", err)
				continue
			}

			s.mu.RLock()
			dest, ok := s.peers[destKey]
			s.mu.RUnlock()

			if !ok {
				log.Printf("relay: data from %x to %x: dest not found", pubKey[:8], destKey[:8])
				continue
			}

			outFrame := MakeDataFrame(pubKey, payload)
			dest.mu.Lock()
			err = WriteFrame(dest.writer, outFrame)
			if err == nil {
				err = dest.writer.Flush()
			}
			dest.mu.Unlock()

			if err != nil {
				log.Printf("relay: forward error to %x: %v", destKey[:8], err)
			}

		case MsgNATProbe:
			ip, port, err := ParseNATProbeFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad NAT probe frame from %x: %v", pubKey[:8], err)
				continue
			}
			select {
			case s.probeSem <- struct{}{}:
				go func() {
					defer func() { <-s.probeSem }()
					s.sendNATProbe(ip, port, pubKey)
				}()
			default:
				log.Printf("relay: NAT probe dropped for %x (concurrency limit reached)", pubKey[:8])
			}

		case MsgKeepalive:
			// no-op

		default:
			log.Printf("relay: unknown frame type %d from %x", frame.Type, pubKey[:8])
		}
	}
}

// sendNATProbe sends two UDP probes to the specified endpoint:
//
//  1. Verification probe from the relay's bound UDP port (same port the agent
//     sent its NAT-opening packet to). This tests basic reachability.
//  2. Test probe from a random ephemeral port. This tests port restriction.
//
// The agent evaluates the combination:
//   - Both received   → cone (address-restricted or full)
//   - Only verify     → port-restricted cone
//   - Neither         → firewall blocking (not NAT) → remains cone
func (s *Server) sendNATProbe(ip net.IP, port int, requester [PubKeySize]byte) {
	addr := &net.UDPAddr{IP: ip, Port: port}

	// Probe 1: verification from the bound UDP port (agent opened NAT for this).
	if s.probeConn != nil {
		verify := []byte("WIREKUBE_NAT_VERIFY")
		if _, err := s.probeConn.WriteToUDP(verify, addr); err != nil {
			log.Printf("relay: NAT verify probe to %s failed: %v", addr, err)
		} else {
			log.Printf("relay: NAT verify probe sent to %s for %x (from bound port)", addr, requester[:8])
		}
	}

	// Probe 2: test from a random ephemeral port.
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		log.Printf("relay: NAT test probe dial %s failed: %v", addr, err)
		return
	}
	defer conn.Close()

	probe := []byte("WIREKUBE_NAT_PROBE")
	if _, err := conn.Write(probe); err != nil {
		log.Printf("relay: NAT test probe send to %s failed: %v", addr, err)
		return
	}
	log.Printf("relay: NAT test probe sent to %s for %x (from ephemeral port)", addr, requester[:8])
}

// ConnectedPeers returns the number of currently connected peers.
func (s *Server) ConnectedPeers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}
