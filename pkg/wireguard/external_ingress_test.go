package wireguard

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// memTUN is an in-memory TUN: fromKernel feeds Read, Write lands in toKernel.
type memTUN struct {
	fromKernel chan []byte
	toKernel   chan []byte
	events     chan tun.Event
	closeOnce  sync.Once
	closed     chan struct{}
}

func newMemTUN() *memTUN {
	t := &memTUN{
		fromKernel: make(chan []byte, 64),
		toKernel:   make(chan []byte, 64),
		events:     make(chan tun.Event, 1),
		closed:     make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *memTUN) File() *os.File { return nil }
func (t *memTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-t.fromKernel:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}
func (t *memTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		t.toKernel <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}
func (t *memTUN) MTU() (int, error)        { return 1420, nil }
func (t *memTUN) Name() (string, error)    { return "mem", nil }
func (t *memTUN) Events() <-chan tun.Event { return t.events }
func (t *memTUN) BatchSize() int           { return 1 }
func (t *memTUN) Close() error {
	t.closeOnce.Do(func() { close(t.closed); close(t.events) })
	return nil
}

// loopRelay plays the relay between one external client and the node: the
// node's replies go to the client's bind.
type loopRelay struct{ toClient chan []byte }

func (r *loopRelay) SendToPeer([32]byte, []byte) error { return nil }
func (r *loopRelay) SendToExternal(relayAddr string, token uint64, payload []byte) error {
	if relayAddr != "relay-a" || token != 7 {
		return net.ErrClosed
	}
	r.toClient <- append([]byte(nil), payload...)
	return nil
}
func (r *loopRelay) SendBimodalHint([32]byte) error { return nil }
func (r *loopRelay) IsConnected() bool              { return true }

// clientBind is the external client's socket: whatever it sends arrives at
// the node as if the relay's shared listener had forwarded it.
type clientBind struct {
	deliver  func(RelayPacket)
	fromNode chan []byte
	closed   chan struct{}
}

type clientEndpoint struct{}

func (clientEndpoint) ClearSrc()           {}
func (clientEndpoint) SrcToString() string { return "" }
func (clientEndpoint) DstToString() string { return "relay" }
func (clientEndpoint) DstToBytes() []byte  { return []byte("relay") }
func (clientEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (clientEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *clientBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closed = make(chan struct{})
	closed := b.closed
	return []conn.ReceiveFunc{func(p [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-b.fromNode:
			sizes[0] = copy(p[0], pkt)
			eps[0] = clientEndpoint{}
			return 1, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	}}, port, nil
}
func (b *clientBind) Close() error {
	if b.closed != nil {
		close(b.closed)
		b.closed = nil
	}
	return nil
}
func (b *clientBind) SetMark(uint32) error { return nil }
func (b *clientBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		b.deliver(RelayPacket{
			ExternalSource: ExternalSource{Valid: true, RelayAddr: "relay-a", Token: 7},
			Payload:        append([]byte(nil), buf...),
		})
	}
	return nil
}
func (b *clientBind) ParseEndpoint(string) (conn.Endpoint, error) { return clientEndpoint{}, nil }
func (b *clientBind) BatchSize() int                              { return 1 }

// ipv4Packet builds a minimal IPv4 packet; WireGuard only reads the
// addresses and the length.
func ipv4Packet(src, dst string) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[3] = 28
	p[8] = 64
	p[9] = 17
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

func recvPacket(t *testing.T, ch chan []byte, what string) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func TestExternalIngressCarriesTrafficBothWays(t *testing.T) {
	shared, _ := GenerateKeyPair()
	clientKey, _ := GenerateKeyPair()

	// The node: a mesh TUN behind splitTUN, with a goroutine standing in for
	// the mesh device's reader.
	meshTUN := newMemTUN()
	split := newSplitTUN(meshTUN)
	meshBound := make(chan []byte, 16)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		for {
			n, err := split.Read(bufs, sizes, 16)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				meshBound <- append([]byte(nil), bufs[i][16:16+sizes[i]]...)
			}
		}
	}()
	defer meshTUN.Close()

	relay := &loopRelay{toClient: make(chan []byte, 64)}
	ext, err := newExternalIngress(split, func() RelayTransport { return relay }, shared.Private)
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	if err := ext.SyncPeers([]ExternalPeerConfig{{PublicKeyB64: clientKey.PublicKeyBase64(), AllowedIP: "100.64.0.9/32"}}); err != nil {
		t.Fatal(err)
	}

	// The external client, configured with the shared identity as its server.
	clientTUN := newMemTUN()
	cb := &clientBind{deliver: ext.Deliver, fromNode: relay.toClient}
	client := device.NewDevice(clientTUN, cb, device.NewLogger(device.LogLevelError, "[client] "))
	defer client.Close()
	if err := client.IpcSet("private_key=" + hex.EncodeToString(clientKey.Private[:]) + "\n" +
		"public_key=" + hex.EncodeToString(shared.Public[:]) + "\n" +
		"endpoint=relay:1\nallowed_ip=10.0.0.0/8\n"); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}

	// Client to cluster: decrypted and written into the mesh TUN.
	out := ipv4Packet("100.64.0.9", "10.1.2.3")
	clientTUN.fromKernel <- out
	if got := recvPacket(t, meshTUN.toKernel, "the client's packet in the kernel"); string(got) != string(out) {
		t.Fatalf("kernel got %x, want %x", got, out)
	}

	// Cluster to client: diverted away from the mesh device.
	back := ipv4Packet("10.1.2.3", "100.64.0.9")
	meshTUN.fromKernel <- back
	if got := recvPacket(t, clientTUN.toKernel, "the reply at the client"); string(got) != string(back) {
		t.Fatalf("client got %x, want %x", got, back)
	}

	// Anything else still reaches the mesh device.
	other := ipv4Packet("10.1.2.3", "100.64.0.10")
	meshTUN.fromKernel <- other
	if got := recvPacket(t, meshBound, "a non-diverted packet on the mesh path"); string(got) != string(other) {
		t.Fatalf("mesh device got %x, want %x", got, other)
	}
	select {
	case p := <-meshBound:
		t.Fatalf("a diverted packet leaked to the mesh device: %x", p)
	default:
	}

	// Once the peer leaves, its address is no longer diverted.
	if err := ext.SyncPeers(nil); err != nil {
		t.Fatal(err)
	}
	meshTUN.fromKernel <- back
	if got := recvPacket(t, meshBound, "a packet for a removed peer on the mesh path"); string(got) != string(back) {
		t.Fatalf("mesh device got %x", got)
	}
}

func TestSplitTUNCompactsSurvivors(t *testing.T) {
	src := &batchTUN{pkts: [][]byte{
		ipv4Packet("10.0.0.1", "100.64.0.9"),
		ipv4Packet("10.0.0.1", "10.0.0.2"),
		ipv4Packet("10.0.0.1", "100.64.0.9"),
		ipv4Packet("10.0.0.1", "10.0.0.3"),
	}}
	split := newSplitTUN(src)
	out := make(chan []byte, 8)
	split.out.Store(&out)
	split.setDivert(map[netip.Addr]struct{}{netip.MustParseAddr("100.64.0.9"): {}})

	bufs := make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, 128)
	}
	sizes := make([]int, 4)
	n, err := split.Read(bufs, sizes, 16)
	if err != nil || n != 2 {
		t.Fatalf("Read = %d, %v; want the 2 survivors", n, err)
	}
	for i, want := range []string{"10.0.0.2", "10.0.0.3"} {
		dst, _ := packetDst(bufs[i][16 : 16+sizes[i]])
		if dst.String() != want {
			t.Fatalf("survivor %d goes to %s, want %s", i, dst, want)
		}
	}
	if len(out) != 2 {
		t.Fatalf("%d packets diverted, want 2", len(out))
	}
}

// batchTUN returns all its packets in one Read.
type batchTUN struct {
	memTUN
	pkts [][]byte
}

func (b *batchTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, p := range b.pkts {
		sizes[i] = copy(bufs[i][offset:], p)
	}
	return len(b.pkts), nil
}
