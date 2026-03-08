package relay

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
)

// Server is a WireKube relay server that forwards WireGuard UDP packets
// between agents connected over TCP. Agents register with their WireGuard
// public key; the server routes Data frames by destination public key.
type Server struct {
	mu    sync.RWMutex
	peers map[[PubKeySize]byte]*clientConn
}

type clientConn struct {
	pubKey [PubKeySize]byte
	conn   net.Conn
	writer *bufio.Writer
	mu     sync.Mutex
}

func NewServer() *Server {
	return &Server{
		peers: make(map[[PubKeySize]byte]*clientConn),
	}
}

func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	log.Printf("relay: listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("relay: accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
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

			log.Printf("relay: forwarding %d bytes from %x to %x", len(payload), pubKey[:8], destKey[:8])
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

		case MsgKeepalive:
			// no-op

		default:
			log.Printf("relay: unknown frame type %d from %x", frame.Type, pubKey[:8])
		}
	}
}

// ConnectedPeers returns the number of currently connected peers.
func (s *Server) ConnectedPeers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}
