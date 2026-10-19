package wireguard

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Peers that roam between ingress nodes use one shared identity, which needs a
// wireguard-go device of its own. It shares the mesh TUN: splitTUN diverts the
// packets for its peers' /32s to it, and it writes what it decrypts back into
// the same TUN, so kernel routing needs nothing extra.

// ExternalPeerConfig is one external peer served under the shared identity.
type ExternalPeerConfig struct {
	PublicKeyB64 string
	// AllowedIP is the peer's mesh address, a single-address prefix.
	AllowedIP string
}

// splitTUN is the mesh device's view of the mesh TUN. Reads skip packets
// addressed to a diverted address and queue them for the external ingress
// device instead.
type splitTUN struct {
	tun.Device
	divert atomic.Pointer[map[netip.Addr]struct{}]
	// out carries diverted packets to the external ingress device. Nil until
	// one attaches.
	out atomic.Pointer[chan []byte]
}

func newSplitTUN(dev tun.Device) *splitTUN { return &splitTUN{Device: dev} }

func (s *splitTUN) setDivert(addrs map[netip.Addr]struct{}) {
	if len(addrs) == 0 {
		s.divert.Store(nil)
		return
	}
	s.divert.Store(&addrs)
}

func (s *splitTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := s.Device.Read(bufs, sizes, offset)
		divert := s.divert.Load()
		if n == 0 || divert == nil {
			return n, err
		}
		out := s.out.Load()
		kept := 0
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			if dst, ok := packetDst(pkt); ok {
				if _, hit := (*divert)[dst]; hit {
					if out != nil {
						select {
						case *out <- append([]byte(nil), pkt...):
						default: // the external device is behind; drop like a full queue would
						}
					}
					continue
				}
			}
			// The device reads packet i out of bufs[i], each backed by its
			// own pooled element, so the survivors are moved down by copy;
			// swapping the slices would hand one element another's buffer.
			if kept != i {
				copy(bufs[kept][offset:], pkt)
				sizes[kept] = sizes[i]
			}
			kept++
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}

// packetDst returns an IP packet's destination address.
func packetDst(pkt []byte) (netip.Addr, bool) {
	if len(pkt) == 0 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}

// extTUN is the external ingress device's TUN: it reads what splitTUN
// diverted and writes into the real mesh TUN.
type extTUN struct {
	real      tun.Device
	in        chan []byte
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newExtTUN(real tun.Device) *extTUN {
	t := &extTUN{
		real:   real,
		in:     make(chan []byte, 1024),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *extTUN) File() *os.File { return nil }

func (t *extTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.in:
		sizes[0] = copy(bufs[0][offset:], pkt)
	case <-t.closed:
		return 0, os.ErrClosed
	}
	n := 1
	for n < len(bufs) {
		select {
		case pkt := <-t.in:
			sizes[n] = copy(bufs[n][offset:], pkt)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

// Write hands decrypted packets to the kernel through the mesh TUN, which
// serializes its own writes.
func (t *extTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	return t.real.Write(bufs, offset)
}

func (t *extTUN) MTU() (int, error)        { return t.real.MTU() }
func (t *extTUN) Name() (string, error)    { return t.real.Name() }
func (t *extTUN) Events() <-chan tun.Event { return t.events }
func (t *extTUN) BatchSize() int           { return t.real.BatchSize() }
func (t *extTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// externalEndpoint is where a shared-identity external peer was last heard
// from: a source token on one relay's shared listener.
type externalEndpoint struct{ src ExternalSource }

func (e *externalEndpoint) ClearSrc()           {}
func (e *externalEndpoint) SrcToString() string { return "" }
func (e *externalEndpoint) DstToString() string {
	return fmt.Sprintf("%s#%d", e.src.RelayAddr, e.src.Token)
}

// DstToBytes keys wireguard-go's cookie MACs; the relay and token are what
// identify the source here.
func (e *externalEndpoint) DstToBytes() []byte {
	b := binary.BigEndian.AppendUint64(nil, e.src.Token)
	return append(b, e.src.RelayAddr...)
}
func (e *externalEndpoint) DstIP() netip.Addr { return netip.Addr{} }
func (e *externalEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// externalBind carries the external ingress device's traffic over the relay
// only: it receives what the relay's shared listener delivers and answers
// through the token that delivered it.
type externalBind struct {
	relay func() RelayTransport
	in    chan RelayPacket

	mu     sync.Mutex
	closed chan struct{}
}

func newExternalBind(relay func() RelayTransport) *externalBind {
	return &externalBind{relay: relay, in: make(chan RelayPacket, 1024)}
}

func (b *externalBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	closed := make(chan struct{})
	b.closed = closed
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-b.in:
			sizes[0] = copy(packets[0], pkt.Payload)
			eps[0] = &externalEndpoint{src: pkt.ExternalSource}
			return 1, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *externalBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != nil {
		close(b.closed)
		b.closed = nil
	}
	return nil
}

func (b *externalBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*externalEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	relay := b.relay()
	if relay == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if err := relay.SendToExternal(e.src.RelayAddr, e.src.Token, buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *externalBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, errors.New("external ingress peers have no configured endpoint")
}
func (b *externalBind) SetMark(uint32) error { return nil }
func (b *externalBind) BatchSize() int       { return 1 }

// deliver queues a relay-delivered external packet, dropping it when the
// device is not keeping up rather than stalling the relay reader.
func (b *externalBind) deliver(pkt RelayPacket) {
	select {
	case b.in <- pkt:
	default:
	}
}

// ExternalIngress is the shared-identity device on one node.
type ExternalIngress struct {
	split *splitTUN
	tun   *extTUN
	bind  *externalBind
	dev   *device.Device
	key   [32]byte
}

func newExternalIngress(split *splitTUN, relay func() RelayTransport, key [32]byte) (*ExternalIngress, error) {
	e := &ExternalIngress{
		split: split,
		tun:   newExtTUN(split.Device),
		bind:  newExternalBind(relay),
		key:   key,
	}
	e.dev = device.NewDevice(e.tun, e.bind, device.NewLogger(device.LogLevelError, "[wirekube-ext] "))
	if err := e.dev.IpcSet("private_key=" + hex.EncodeToString(key[:]) + "\n"); err != nil {
		e.dev.Close()
		return nil, fmt.Errorf("set external ingress key: %w", err)
	}
	if err := e.dev.Up(); err != nil {
		e.dev.Close()
		return nil, fmt.Errorf("bring external ingress device up: %w", err)
	}
	split.out.Store(&e.tun.in)
	return e, nil
}

// SyncPeers makes peers the device's whole peer set and diverts their
// addresses to it. Peers that stay keep their sessions.
func (e *ExternalIngress) SyncPeers(peers []ExternalPeerConfig) error {
	current, err := e.peerKeys()
	if err != nil {
		return err
	}
	divert := make(map[netip.Addr]struct{}, len(peers))
	want := make(map[string]bool, len(peers))
	var b strings.Builder
	for _, p := range peers {
		key, err := base64.StdEncoding.DecodeString(p.PublicKeyB64)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("external peer key %q is not a WireGuard key", p.PublicKeyB64)
		}
		prefix, err := netip.ParsePrefix(p.AllowedIP)
		if err != nil || !prefix.IsSingleIP() {
			return fmt.Errorf("external peer %s address %q is not a single address", p.PublicKeyB64, p.AllowedIP)
		}
		hexKey := hex.EncodeToString(key)
		want[hexKey] = true
		divert[prefix.Addr()] = struct{}{}
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", hexKey, prefix)
	}
	for hexKey := range current {
		if !want[hexKey] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hexKey)
		}
	}
	if b.Len() > 0 {
		if err := e.dev.IpcSet(b.String()); err != nil {
			return fmt.Errorf("configure external ingress peers: %w", err)
		}
	}
	e.split.setDivert(divert)
	return nil
}

func (e *ExternalIngress) peerKeys() (map[string]bool, error) {
	out, err := e.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "public_key="); ok {
			keys[v] = true
		}
	}
	return keys, nil
}

// Deliver hands the device an external packet from the relay.
func (e *ExternalIngress) Deliver(pkt RelayPacket) { e.bind.deliver(pkt) }

// Close detaches the device from the mesh TUN and stops it.
func (e *ExternalIngress) Close() {
	e.split.setDivert(nil)
	e.split.out.Store(nil)
	e.tun.Close()
	e.dev.Close()
}
