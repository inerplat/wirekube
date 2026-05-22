package relay

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Transparent UDP forwarder for external (always-relay) WireGuard peers.
//
// External peers run the official WireGuard client and use this relay's
// per-peer UDP port as their tunnel Endpoint. The forwarder receives raw
// UDP datagrams from the external peer, looks up the bound cluster
// ingress peer by the configured pubkey mapping, and dispatches the
// payload onto the existing relay control plane (which delivers it to
// the ingress peer as a Data frame).
//
// The reverse leg (ingress -> external) is wired in pkg/relay/server.go. The
// Forwarder only handles the external -> ingress direction.
//
// Each registered port owns one *net.UDPConn and one read goroutine.

// IngressDispatcher abstracts delivery of an inbound external-peer datagram
// to the cluster-side ingress peer. The relay server.Server is the
// production implementation (it owns the registered TCP connection to the
// ingress agent and writes a Data frame). Tests provide a stub. Keeping
// this interface free of K8s/relay-server concerns lets the Forwarder be
// unit tested without spinning up a full server.
type IngressDispatcher interface {
	// Dispatch is called once per inbound UDP datagram from the external
	// peer. Implementations are responsible for any framing/encapsulation.
	// fromExternal carries the source address of the datagram on the wire,
	// useful for stats and for rebinding the reverse-path mapping. The
	// external pubkey is included so production dispatchers can build a
	// Data frame whose sender field identifies which external peer this
	// datagram came from (the ingress peer's bind keys its peer table by
	// sender pubkey, not by source IP).
	//
	// Returning an error causes the forwarder to log and drop the datagram;
	// it does not unregister the mapping.
	Dispatch(ingress, external [PubKeySize]byte, payload []byte, fromExternal netip.AddrPort) error
}

// noopDispatcher discards every datagram. Used by tests that only care
// about plumbing or by callers that want to exercise the listen path
// without a real backend.
type noopDispatcher struct{}

// Dispatch implements IngressDispatcher.
func (noopDispatcher) Dispatch(_, _ [PubKeySize]byte, _ []byte, _ netip.AddrPort) error {
	return nil
}

// Stats holds per-mapping forwarder counters. Returned from
// (*Forwarder).Stats; safe to read from any goroutine because the values
// are loaded atomically.
type Stats struct {
	// BytesIn counts payload bytes received from the external peer
	// (excludes UDP/IP headers).
	BytesIn uint64
	// BytesOut is reserved for the reverse path. The external -> ingress
	// forwarder does not increment it.
	BytesOut uint64
	// LastPacket is the wall-clock time the most recent inbound datagram
	// was observed. Zero value means no traffic yet.
	LastPacket time.Time
	// ExternalAddr is the source AddrPort of the most recent inbound
	// datagram. Reset on each packet so it always reflects the live peer.
	// Zero value means no traffic yet.
	ExternalAddr netip.AddrPort
	// Truncated counts inbound datagrams whose length equalled the read
	// buffer (readBufferSize). UDP silently drops the tail of an oversized
	// datagram, so a non-zero counter means at least one packet may have
	// been corrupted on the wire and the buffer is undersized for the
	// observed traffic.
	Truncated uint64
}

// readBufferSize bounds the per-read buffer. WireGuard's largest datagram
// is around 1500 bytes; 2 KiB leaves comfortable headroom for any
// underlying encapsulation.
const readBufferSize = 2048

// ErrPortInUse is returned by Register if the port is already mapped.
var ErrPortInUse = errors.New("forwarder: port already registered")

// ErrUnknownPort is returned by Unregister and Stats for ports the
// forwarder is not currently tracking.
var ErrUnknownPort = errors.New("forwarder: port not registered")

// Forwarder owns a set of per-port UDP listeners that translate external
// peer datagrams into Dispatch calls. It is safe for concurrent use.
type Forwarder struct {
	dispatcher IngressDispatcher

	mu       sync.Mutex
	mappings map[uint16]*forwarderEntry
	// byExternal indexes the same entries by external pubkey so reverse-path
	// (ingress → external) lookups don't have to scan the map. Updated under
	// mu in lockstep with mappings.
	byExternal map[[PubKeySize]byte]*forwarderEntry
}

// forwarderEntry holds one registered mapping. Counters use atomics so
// the read goroutine can update without contending the Forwarder mutex.
type forwarderEntry struct {
	port     uint16
	ingress  [PubKeySize]byte
	external [PubKeySize]byte

	conn *net.UDPConn
	done chan struct{} // closed when the read loop has exited

	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	truncated atomic.Uint64

	statsMu      sync.Mutex
	lastPacket   time.Time
	externalAddr netip.AddrPort
}

// NewForwarder constructs a Forwarder backed by the given dispatcher.
// A nil dispatcher is replaced with noopDispatcher so callers (tests,
// dry-run modes) can construct a Forwarder without wiring a real backend.
func NewForwarder(dispatcher IngressDispatcher) *Forwarder {
	if dispatcher == nil {
		dispatcher = noopDispatcher{}
	}
	return &Forwarder{
		dispatcher: dispatcher,
		mappings:   make(map[uint16]*forwarderEntry),
		byExternal: make(map[[PubKeySize]byte]*forwarderEntry),
	}
}

// Register opens a UDP listen socket on the given port (all interfaces,
// IPv4) and starts a read loop that forwards inbound datagrams to the
// configured IngressDispatcher.
//
// Returns ErrPortInUse if the port is already registered. Returns a
// wrapped error if the bind fails (e.g. EADDRINUSE outside of this
// forwarder's tracking).
func (f *Forwarder) Register(port uint16, ingressPubKey [PubKeySize]byte, externalPubKey [PubKeySize]byte) error {
	f.mu.Lock()
	if existing, exists := f.mappings[port]; exists {
		f.mu.Unlock()
		if existing.ingress == ingressPubKey && existing.external == externalPubKey {
			return nil
		}
		return ErrPortInUse
	}

	udpAddr := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		f.mu.Unlock()
		return fmt.Errorf("forwarder: bind udp4 :%d: %w", port, err)
	}

	entry := &forwarderEntry{
		port:     port,
		ingress:  ingressPubKey,
		external: externalPubKey,
		conn:     conn,
		done:     make(chan struct{}),
	}
	f.mappings[port] = entry
	f.byExternal[externalPubKey] = entry
	f.mu.Unlock()

	go f.readLoop(entry)

	log.Printf("relay forwarder: registered port %d for ingress %x (external %x)",
		port, ingressPubKey[:8], externalPubKey[:8])
	return nil
}

// Unregister closes the listener for the given port and removes the
// mapping. The read goroutine exits before this call returns.
func (f *Forwarder) Unregister(port uint16) error {
	f.mu.Lock()
	entry, ok := f.mappings[port]
	if !ok {
		f.mu.Unlock()
		return ErrUnknownPort
	}
	delete(f.mappings, port)
	delete(f.byExternal, entry.external)
	f.mu.Unlock()

	// Closing the conn unblocks ReadFromUDP, which exits the loop and
	// closes entry.done.
	_ = entry.conn.Close()
	<-entry.done

	log.Printf("relay forwarder: unregistered port %d (ingress %x)",
		port, entry.ingress[:8])
	return nil
}

// Stats returns the live counters for the given port. Returns
// ErrUnknownPort if the port is not registered.
func (f *Forwarder) Stats(port uint16) (Stats, error) {
	f.mu.Lock()
	entry, ok := f.mappings[port]
	f.mu.Unlock()
	if !ok {
		return Stats{}, ErrUnknownPort
	}

	entry.statsMu.Lock()
	last := entry.lastPacket
	addr := entry.externalAddr
	entry.statsMu.Unlock()

	return Stats{
		BytesIn:      entry.bytesIn.Load(),
		BytesOut:     entry.bytesOut.Load(),
		LastPacket:   last,
		ExternalAddr: addr,
		Truncated:    entry.truncated.Load(),
	}, nil
}

// Close tears down all registered listeners. After Close the Forwarder
// must not be reused. Safe to call multiple times.
func (f *Forwarder) Close() {
	f.mu.Lock()
	entries := make([]*forwarderEntry, 0, len(f.mappings))
	for _, e := range f.mappings {
		entries = append(entries, e)
	}
	f.mappings = make(map[uint16]*forwarderEntry)
	f.byExternal = make(map[[PubKeySize]byte]*forwarderEntry)
	f.mu.Unlock()

	for _, e := range entries {
		_ = e.conn.Close()
		<-e.done
	}
}

// SendToExternal writes a payload to the last-known UDP source address
// observed for the given external pubkey. Used by the relay server to
// route ingress → external replies (Data frames whose destPubKey matches
// no TCP-registered peer but does match a forwarder mapping).
//
// Returns ErrUnknownPort if the external pubkey has no registered
// mapping, or a transient I/O error if the UDP write fails. Returns
// nil with no write attempt if the external peer has not yet sent any
// inbound traffic — its source addr is unknown and silently dropping
// the reply is correct (the external peer must initiate first to open
// the path; no addr means there is nothing to reply to yet).
func (f *Forwarder) SendToExternal(externalPubKey [PubKeySize]byte, payload []byte) error {
	f.mu.Lock()
	entry, ok := f.byExternal[externalPubKey]
	f.mu.Unlock()
	if !ok {
		return ErrUnknownPort
	}
	entry.statsMu.Lock()
	addr := entry.externalAddr
	entry.statsMu.Unlock()
	if !addr.IsValid() {
		return nil
	}
	dst := net.UDPAddrFromAddrPort(addr)
	n, err := entry.conn.WriteToUDP(payload, dst)
	if err != nil {
		return err
	}
	entry.bytesOut.Add(uint64(n))
	return nil
}

// readLoop owns one *forwarderEntry. It exits when the underlying conn
// is closed by Unregister or Close.
func (f *Forwarder) readLoop(entry *forwarderEntry) {
	defer close(entry.done)
	buf := make([]byte, readBufferSize)
	for {
		n, src, err := entry.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			// A closed conn is the normal exit path on Unregister/Close.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Other errors are likely transient (interrupt, buffer); log and
			// continue. If the conn is unrecoverable, the next read will
			// also error and we'll loop again — the caller is expected to
			// Unregister to break out in that case.
			log.Printf("relay forwarder: read on port %d: %v", entry.port, err)
			continue
		}
		if n == 0 {
			continue
		}

		// A full-buffer read on a connected UDP socket means the kernel
		// truncated the tail of the datagram. WireGuard's max payload sits
		// well under readBufferSize, but record the symptom so undersized
		// buffers are detectable in production rather than corrupting the
		// inner WG framing silently.
		if n == len(buf) {
			entry.truncated.Add(1)
			log.Printf("relay forwarder: truncated datagram on port %d (n=%d, buf=%d, src=%s)",
				entry.port, n, len(buf), src)
		}

		// Snapshot before dispatching to keep stats consistent with what
		// the dispatcher saw.
		entry.bytesIn.Add(uint64(n))
		entry.statsMu.Lock()
		entry.lastPacket = time.Now()
		entry.externalAddr = src
		entry.statsMu.Unlock()

		// Copy the payload because buf is reused on the next iteration.
		payload := make([]byte, n)
		copy(payload, buf[:n])

		if err := f.dispatcher.Dispatch(entry.ingress, entry.external, payload, src); err != nil {
			log.Printf("relay forwarder: dispatch on port %d to ingress %x: %v",
				entry.port, entry.ingress[:8], err)
		}
	}
}
