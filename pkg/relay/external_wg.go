package relay

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// ExternalWGListener accepts raw WireGuard UDP datagrams from official
// WireGuard clients on one shared public port. It does not inspect or decrypt
// WireGuard. Instead it assigns the external source address an opaque token,
// forwards the raw payload to one configured ingress peer over the relay TCP
// session, and routes ingress responses back to the original UDP source by
// token.
type ExternalWGListener struct {
	server       *Server
	conn         *net.UDPConn
	fixedIngress [PubKeySize]byte

	mu             sync.Mutex
	next           uint64
	byToken        map[uint64]netip.AddrPort
	bySource       map[netip.AddrPort]uint64
	byTokenIngress map[uint64][PubKeySize]byte
	lastSeen       map[uint64]time.Time
}

const (
	externalWGSourceTTL = 5 * time.Minute
	externalWGMaxSource = 16384
)

// EnableExternalWGListener starts the shared raw-WireGuard UDP listener. The
// optional ingress peer pins all external traffic to one in-cluster WireKube
// agent. When ingress is the zero key, the listener fans out a new source's
// first packet to all connected agents, then learns the ingress from the first
// response and sends later packets from that source only to the learned agent.
// In both modes the relay does not inspect or decrypt WireGuard payloads; the
// selected agent's wireguard-go device authenticates the actual external peer.
func (s *Server) EnableExternalWGListener(addr string, ingress [PubKeySize]byte) error {
	if s.externalWG != nil {
		return fmt.Errorf("relay: external WG listener already enabled")
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("resolve external WG addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("listen external WG UDP %s: %w", addr, err)
	}
	l := &ExternalWGListener{
		server:         s,
		conn:           conn,
		fixedIngress:   ingress,
		next:           1,
		byToken:        make(map[uint64]netip.AddrPort),
		bySource:       make(map[netip.AddrPort]uint64),
		byTokenIngress: make(map[uint64][PubKeySize]byte),
		lastSeen:       make(map[uint64]time.Time),
	}
	s.externalWG = l
	go l.run()
	if ingress == ([PubKeySize]byte{}) {
		log.Printf("relay: external WG listener on %s ingress=dynamic", conn.LocalAddr())
	} else {
		log.Printf("relay: external WG listener on %s ingress=%x", conn.LocalAddr(), ingress[:8])
	}
	return nil
}

func (l *ExternalWGListener) Close() error {
	return l.conn.Close()
}

func (l *ExternalWGListener) run() {
	buf := make([]byte, MaxFrameSize)
	for {
		n, src, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if bytes.HasPrefix(buf[:n], []byte("WIREKUBE_NAT_")) {
			continue
		}
		token := l.tokenForSource(src)
		payload := append([]byte(nil), buf[:n]...)
		if err := l.forwardToIngress(token, src, payload); err != nil {
			log.Printf("relay: external WG forward src=%s token=%d failed: %v", src, token, err)
		}
	}
}

func (l *ExternalWGListener) tokenForSource(src netip.AddrPort) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if token, ok := l.bySource[src]; ok {
		l.lastSeen[token] = now
		return token
	}
	if len(l.byToken) >= externalWGMaxSource {
		l.pruneLocked(now)
		if len(l.byToken) >= externalWGMaxSource {
			l.evictOldestLocked()
		}
	}
	token := l.next
	l.next++
	l.bySource[src] = token
	l.byToken[token] = src
	l.lastSeen[token] = now
	return token
}

func (l *ExternalWGListener) pruneLocked(now time.Time) {
	for token, last := range l.lastSeen {
		if now.Sub(last) <= externalWGSourceTTL {
			continue
		}
		l.deleteTokenLocked(token)
	}
}

func (l *ExternalWGListener) evictOldestLocked() {
	var oldestToken uint64
	var oldest time.Time
	for token, last := range l.lastSeen {
		if oldestToken == 0 || last.Before(oldest) {
			oldestToken = token
			oldest = last
		}
	}
	if oldestToken != 0 {
		l.deleteTokenLocked(oldestToken)
	}
}

func (l *ExternalWGListener) deleteTokenLocked(token uint64) {
	if src, ok := l.byToken[token]; ok {
		delete(l.bySource, src)
	}
	delete(l.byToken, token)
	delete(l.byTokenIngress, token)
	delete(l.lastSeen, token)
}

func (l *ExternalWGListener) forwardToIngress(token uint64, src netip.AddrPort, payload []byte) error {
	if l.fixedIngress != ([PubKeySize]byte{}) {
		return l.writeToIngress(l.fixedIngress, token, src, payload)
	}

	l.mu.Lock()
	learned, learnedOK := l.byTokenIngress[token]
	l.mu.Unlock()
	if learnedOK {
		if err := l.writeToIngress(learned, token, src, payload); err == nil {
			return nil
		}
	}

	l.server.mu.RLock()
	keys := make([][PubKeySize]byte, 0, len(l.server.peers))
	for key := range l.server.peers {
		keys = append(keys, key)
	}
	l.server.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})

	if len(keys) == 0 {
		return fmt.Errorf("no connected ingress peers")
	}

	var lastErr error
	for _, key := range keys {
		if err := l.writeToIngress(key, token, src, payload); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (l *ExternalWGListener) writeToIngress(ingressKey [PubKeySize]byte, token uint64, src netip.AddrPort, payload []byte) error {
	l.server.mu.RLock()
	ingress, ok := l.server.peers[ingressKey]
	l.server.mu.RUnlock()
	if !ok {
		return fmt.Errorf("ingress peer %x not connected", ingressKey[:8])
	}
	frame := MakeExternalDataFrame(token, src.String(), payload)
	ingress.mu.Lock()
	defer ingress.mu.Unlock()
	if err := WriteFrame(ingress.writer, frame); err != nil {
		return err
	}
	return ingress.writer.Flush()
}

func (l *ExternalWGListener) AllowsIngress(ingress [PubKeySize]byte) bool {
	return l.fixedIngress == ([PubKeySize]byte{}) || l.fixedIngress == ingress
}

func (l *ExternalWGListener) BindTokenIngress(token uint64, ingress [PubKeySize]byte) {
	if l.fixedIngress != ([PubKeySize]byte{}) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.byToken[token]; !ok {
		return
	}
	l.byTokenIngress[token] = ingress
}

// SendToExternal writes a raw WireGuard response packet back to the UDP source
// associated with token.
func (l *ExternalWGListener) SendToExternal(token uint64, payload []byte) error {
	l.mu.Lock()
	dst, ok := l.byToken[token]
	if ok {
		l.lastSeen[token] = time.Now()
	}
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown external source token %d", token)
	}
	udpAddr := net.UDPAddrFromAddrPort(dst)
	_, err := l.conn.WriteToUDP(payload, udpAddr)
	return err
}
