package relay

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// memRegistryStore stands in for the apiserver: one shared directory that
// every replica's registry reads and writes.
type memRegistryStore struct {
	mu       sync.Mutex
	peers    map[[PubKeySize]byte]string
	replicas []string
}

type memRegistry struct {
	store *memRegistryStore
	self  string
}

func (m *memRegistry) PublishPeer(k [PubKeySize]byte) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	m.store.peers[k] = m.self
}

func (m *memRegistry) WithdrawPeer(k [PubKeySize]byte) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	if m.store.peers[k] == m.self {
		delete(m.store.peers, k)
	}
}

func (m *memRegistry) LookupPeer(k [PubKeySize]byte) (string, bool) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	addr, ok := m.store.peers[k]
	return addr, ok
}

func (m *memRegistry) Replicas() []string {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	return append([]string(nil), m.store.replicas...)
}

func (m *memRegistry) SelfAddr() string { return m.self }

// clusterPair boots two servers joined through a shared in-memory registry,
// each with a real TCP cluster listener on loopback.
func clusterPair(t *testing.T) (*Server, *Server) {
	t.Helper()
	store := &memRegistryStore{peers: make(map[[PubKeySize]byte]string)}

	newHalf := func() (*Server, *Cluster, string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("cluster listener: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		s := NewServer()
		c := NewCluster(&memRegistry{store: store, self: ln.Addr().String()})
		s.EnableCluster(c)
		t.Cleanup(c.Close)
		go c.ServeListener(ln)
		return s, c, ln.Addr().String()
	}

	s1, _, addr1 := newHalf()
	s2, _, addr2 := newHalf()
	store.replicas = []string{addr1, addr2}
	return s1, s2
}

// connectPeer registers a peer on a server through an in-memory pipe and
// returns the client side. It blocks until the registration is visible in
// the server's peer table: frames sent cross-replica right after connecting
// would otherwise race the register goroutine and be dropped as not-local.
func connectPeer(t *testing.T, s *Server, key [PubKeySize]byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go s.handleConn(server)
	if err := WriteFrame(client, MakeRegisterFrame(key)); err != nil {
		t.Fatalf("register: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.RLock()
		_, ok := s.peers[key]
		s.mu.RUnlock()
		if ok {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer %x never registered", key[:4])
		}
		time.Sleep(time.Millisecond)
	}
}

func readFrameWithin(t *testing.T, conn net.Conn, d time.Duration) Frame {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	frame, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	return frame
}

// The incident this feature addresses: two peers behind one LB whose TCP
// sessions land on different replicas could not exchange a single frame —
// every packet died as "dest not found" on the sender's replica.
func TestClusterForwardsDataAcrossReplicas(t *testing.T) {
	s1, s2 := clusterPair(t)
	keyA, keyB := pubkey(1), pubkey(2)
	connA := connectPeer(t, s1, keyA)
	connB := connectPeer(t, s2, keyB)

	payload := []byte("wg-packet")
	if err := WriteFrame(connA, MakeDataFrame(keyB, payload)); err != nil {
		t.Fatalf("send data: %v", err)
	}

	frame := readFrameWithin(t, connB, 5*time.Second)
	if frame.Type != MsgData {
		t.Fatalf("frame type = %#x, want MsgData", frame.Type)
	}
	src, got, err := ParseDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseDataFrame: %v", err)
	}
	if src != keyA {
		t.Fatalf("src = %x, want %x", src[:4], keyA[:4])
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestClusterForwardsBimodalHintAcrossReplicas(t *testing.T) {
	s1, s2 := clusterPair(t)
	keyA, keyB := pubkey(3), pubkey(4)
	connA := connectPeer(t, s1, keyA)
	connB := connectPeer(t, s2, keyB)

	if err := WriteFrame(connA, MakeBimodalHintFrame(keyB)); err != nil {
		t.Fatalf("send hint: %v", err)
	}

	frame := readFrameWithin(t, connB, 5*time.Second)
	if frame.Type != MsgBimodalHint {
		t.Fatalf("frame type = %#x, want MsgBimodalHint", frame.Type)
	}
	if string(frame.Body) != string(keyA[:]) {
		t.Fatalf("hint sender = %x, want %x", frame.Body[:4], keyA[:4])
	}
}

// Full external round trip with the flow and the ingress agent on different
// replicas: UDP lands on S1, the only agent lives on S2. The request must
// reach the agent via the cluster fanout, and the agent's reply must come
// back out of S1's UDP socket — the one the client's NAT/conntrack state
// points at.
func TestClusterExternalFlowAcrossReplicas(t *testing.T) {
	s1, s2 := clusterPair(t)
	if err := s1.EnableExternalWGListener("127.0.0.1:0", [PubKeySize]byte{}); err != nil {
		t.Fatalf("EnableExternalWGListener: %v", err)
	}
	t.Cleanup(func() { _ = s1.externalWG.Close() })

	agentKey := pubkey(5)
	agentConn := connectPeer(t, s2, agentKey)

	client, err := net.DialUDP("udp4", nil, s1.externalWG.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial external UDP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if _, err := client.Write([]byte("wg-initiation")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// The agent on S2 receives the fanned-out packet with S1's token.
	frame := readFrameWithin(t, agentConn, 5*time.Second)
	if frame.Type != MsgExternalData {
		t.Fatalf("frame type = %#x, want MsgExternalData", frame.Type)
	}
	token, _, payload, err := ParseExternalDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame: %v", err)
	}
	if string(payload) != "wg-initiation" {
		t.Fatalf("payload = %q", payload)
	}
	// S2 runs without an external listener here, so check the tag directly:
	// the token must carry S1's (non-zero) origin tag for the reply to find
	// its way home.
	if clusterTokenTag(token) == 0 {
		t.Fatalf("token %d carries no origin tag", token)
	}

	// Agent replies through its own replica; the response must surface on
	// the client's original UDP socket.
	if err := WriteFrame(agentConn, MakeExternalDataFrame(token, "", []byte("wg-response"))); err != nil {
		t.Fatalf("agent reply: %v", err)
	}
	buf := make([]byte, 256)
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "wg-response" {
		t.Fatalf("client got %q, want wg-response", buf[:n])
	}

	// The reply also pins the flow: the next packet from the same source
	// must go straight to the answering agent instead of fanning out.
	if _, err := client.Write([]byte("wg-data-2")); err != nil {
		t.Fatalf("client write 2: %v", err)
	}
	frame = readFrameWithin(t, agentConn, 5*time.Second)
	if frame.Type != MsgExternalData {
		t.Fatalf("frame 2 type = %#x, want MsgExternalData", frame.Type)
	}
	_, _, payload, err = ParseExternalDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame 2: %v", err)
	}
	if string(payload) != "wg-data-2" {
		t.Fatalf("payload 2 = %q", payload)
	}
}

func TestClusterEnvelopeNeverReforwards(t *testing.T) {
	// An envelope for a peer that is not local must be dropped, not chased
	// through the registry again — that is the loop-prevention invariant.
	s1, _ := clusterPair(t)
	env := makeClusterEnvelope(pubkey(9), MakeDataFrame(pubkey(8), []byte("x")))
	if s1.deliverLocal(pubkey(9), env) {
		t.Fatal("deliverLocal claimed success for a peer that is not connected")
	}
}

func TestKubeRegistryPublishLookup(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctx := context.Background()

	r1 := NewKubeRegistry(cs, "wirekube-system", "relay-1", "10.244.0.1:3479")
	r2 := NewKubeRegistry(cs, "wirekube-system", "relay-2", "10.244.0.2:3479")
	r1.spawn = func(f func()) { f() }
	r2.spawn = func(f func()) { f() }

	key := pubkey(7)
	r1.PublishPeer(key)
	r1.syncOnce(ctx)
	r2.syncOnce(ctx)

	if addr, ok := r2.LookupPeer(key); !ok || addr != "10.244.0.1:3479" {
		t.Fatalf("LookupPeer = %q,%v; want 10.244.0.1:3479,true", addr, ok)
	}

	replicas := r2.Replicas()
	if len(replicas) != 2 {
		t.Fatalf("Replicas = %v, want both replica addrs", replicas)
	}

	// Withdraw propagates on the next refresh.
	r1.WithdrawPeer(key)
	r2.syncOnce(ctx)
	if addr, ok := r2.LookupPeer(key); ok {
		t.Fatalf("peer still resolvable after withdraw: %q", addr)
	}
}

func TestKubeRegistrySkipsStaleLeases(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctx := context.Background()

	stale := NewKubeRegistry(cs, "ns", "relay-old", "10.0.0.9:3479")
	stale.spawn = func(f func()) { f() }
	stale.PublishPeer(pubkey(6))
	stale.syncOnce(ctx)

	// Age every lease past the staleness horizon by rewriting renewTime.
	leases, err := cs.CoordinationV1().Leases("ns").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	for i := range leases.Items {
		l := leases.Items[i]
		old := metav1.NewMicroTime(time.Now().Add(-2 * registryStaleAfter))
		l.Spec.RenewTime = &old
		if _, err := cs.CoordinationV1().Leases("ns").Update(ctx, &l, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("age lease: %v", err)
		}
	}

	fresh := NewKubeRegistry(cs, "ns", "relay-new", "10.0.0.10:3479")
	fresh.syncOnce(ctx)

	if addr, ok := fresh.LookupPeer(pubkey(6)); ok {
		t.Fatalf("stale peer lease resolved to %q; want miss", addr)
	}
	for _, addr := range fresh.Replicas() {
		if addr == "10.0.0.9:3479" {
			t.Fatal("stale replica lease still listed")
		}
	}
}
