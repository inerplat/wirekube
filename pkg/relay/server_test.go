package relay

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientConnWriteFrameTimesOut(t *testing.T) {
	oldTimeout := relayClientWriteTimeout
	relayClientWriteTimeout = 20 * time.Millisecond
	defer func() { relayClientWriteTimeout = oldTimeout }()

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	cc := &clientConn{
		pubKey: pubkey(1),
		conn:   serverSide,
		writer: bufio.NewWriter(serverSide),
	}

	start := time.Now()
	err := cc.writeFrame(MakeKeepaliveFrame())
	if err == nil {
		t.Fatal("writeFrame succeeded; want timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("writeFrame blocked for %s; want bounded timeout", elapsed)
	}
}

func TestServer_ExplicitForwarderRegisterReservesPort(t *testing.T) {
	port := freeUDPPort(t)
	s := NewServer()
	if err := s.EnableForwarder(port, port); err != nil {
		t.Fatalf("EnableForwarder: %v", err)
	}
	defer s.forwarder.Close()

	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleForwarderRegister(server, MakeForwarderRegisterFrame(port, pubkey(1), pubkey(2)))
		_ = server.Close()
	}()

	resp, err := ReadFrame(client)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if resp.Type != MsgForwarderRegister {
		t.Fatalf("response type = %#x, want MsgForwarderRegister body=%q", resp.Type, string(resp.Body))
	}
	gotPort, _, _, err := ParseForwarderRegisterFrame(resp.Body)
	if err != nil {
		t.Fatalf("ParseForwarderRegisterFrame: %v", err)
	}
	if gotPort != port {
		t.Fatalf("registered port = %d, want %d", gotPort, port)
	}
	<-done

	if got := s.alloc.InUse(); len(got) != 1 || got[0] != port {
		t.Fatalf("alloc.InUse = %v, want [%d]", got, port)
	}
}

func TestServer_ExternalWGListenerForwardsBySourceToken(t *testing.T) {
	s := NewServer()
	ingressKey := pubkey(9)
	if err := s.EnableExternalWGListener("127.0.0.1:0", ingressKey); err != nil {
		t.Fatalf("EnableExternalWGListener: %v", err)
	}
	defer s.externalWG.Close()

	ingressClient, relaySide := net.Pipe()
	defer ingressClient.Close()
	go s.handleConn(relaySide)
	if err := WriteFrame(ingressClient, MakeRegisterFrame(ingressKey)); err != nil {
		t.Fatalf("WriteFrame register: %v", err)
	}

	external, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP external: %v", err)
	}
	defer external.Close()

	if _, err := external.WriteToUDP([]byte("wg-init"), s.externalWG.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("external WriteToUDP: %v", err)
	}

	if err := ingressClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	frame, err := ReadFrame(ingressClient)
	if err != nil {
		t.Fatalf("ReadFrame ingress: %v", err)
	}
	if frame.Type != MsgExternalData {
		t.Fatalf("frame type = %#x, want MsgExternalData", frame.Type)
	}
	token, sourceAddr, payload, err := ParseExternalDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame: %v", err)
	}
	if token == 0 {
		t.Fatal("source token is zero")
	}
	if sourceAddr != external.LocalAddr().String() {
		t.Fatalf("sourceAddr = %q, want %q", sourceAddr, external.LocalAddr().String())
	}
	if string(payload) != "wg-init" {
		t.Fatalf("payload = %q", string(payload))
	}

	if err := WriteFrame(ingressClient, MakeExternalDataFrame(token, "", []byte("wg-response"))); err != nil {
		t.Fatalf("WriteFrame external response: %v", err)
	}
	buf := make([]byte, 128)
	if err := external.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("external SetReadDeadline: %v", err)
	}
	n, err := external.Read(buf)
	if err != nil {
		t.Fatalf("external Read: %v", err)
	}
	if string(buf[:n]) != "wg-response" {
		t.Fatalf("external response = %q", string(buf[:n]))
	}
}

func TestServer_ExternalWGListenerLearnsDynamicIngress(t *testing.T) {
	s := NewServer()
	if err := s.EnableExternalWGListener("127.0.0.1:0", [PubKeySize]byte{}); err != nil {
		t.Fatalf("EnableExternalWGListener: %v", err)
	}
	defer s.externalWG.Close()

	ingressAKey := pubkey(9)
	ingressBKey := pubkey(10)
	ingressA, relayA := net.Pipe()
	defer ingressA.Close()
	go s.handleConn(relayA)
	if err := WriteFrame(ingressA, MakeRegisterFrame(ingressAKey)); err != nil {
		t.Fatalf("WriteFrame register A: %v", err)
	}
	ingressB, relayB := net.Pipe()
	defer ingressB.Close()
	go s.handleConn(relayB)
	if err := WriteFrame(ingressB, MakeRegisterFrame(ingressBKey)); err != nil {
		t.Fatalf("WriteFrame register B: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for s.ConnectedPeers() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("registered ingress peers did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	external, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP external: %v", err)
	}
	defer external.Close()

	if _, err := external.WriteToUDP([]byte("wg-init"), s.externalWG.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("external WriteToUDP init: %v", err)
	}
	frameA := readFrameWithDeadline(t, ingressA)
	frameB := readFrameWithDeadline(t, ingressB)
	tokenA, _, payloadA, err := ParseExternalDataFrame(frameA.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame A: %v", err)
	}
	tokenB, _, payloadB, err := ParseExternalDataFrame(frameB.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame B: %v", err)
	}
	if frameA.Type != MsgExternalData || frameB.Type != MsgExternalData {
		t.Fatalf("frame types = %#x/%#x, want MsgExternalData", frameA.Type, frameB.Type)
	}
	if tokenA == 0 || tokenA != tokenB {
		t.Fatalf("tokens = %d/%d, want same non-zero token", tokenA, tokenB)
	}
	if string(payloadA) != "wg-init" || string(payloadB) != "wg-init" {
		t.Fatalf("payloads = %q/%q, want wg-init", string(payloadA), string(payloadB))
	}

	if err := WriteFrame(ingressB, MakeExternalDataFrame(tokenB, "", []byte("wg-response"))); err != nil {
		t.Fatalf("WriteFrame external response: %v", err)
	}
	buf := make([]byte, 128)
	if err := external.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("external SetReadDeadline: %v", err)
	}
	n, err := external.Read(buf)
	if err != nil {
		t.Fatalf("external Read: %v", err)
	}
	if string(buf[:n]) != "wg-response" {
		t.Fatalf("external response = %q", string(buf[:n]))
	}

	if _, err := external.WriteToUDP([]byte("wg-data"), s.externalWG.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("external WriteToUDP data: %v", err)
	}
	nextB := readFrameWithDeadline(t, ingressB)
	_, _, payload, err := ParseExternalDataFrame(nextB.Body)
	if err != nil {
		t.Fatalf("ParseExternalDataFrame learned B: %v", err)
	}
	if string(payload) != "wg-data" {
		t.Fatalf("learned payload = %q, want wg-data", string(payload))
	}
	if err := ingressA.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline A: %v", err)
	}
	if frame, err := ReadFrame(ingressA); err == nil {
		t.Fatalf("unexpected frame on unlearned ingress A: %#x", frame.Type)
	}
}

func TestServer_IngressProbeMeasuresRegisteredPeer(t *testing.T) {
	s := NewServer()
	port := freeUDPPort(t)
	if err := s.EnableForwarder(port, port); err != nil {
		t.Fatalf("EnableForwarder: %v", err)
	}
	defer s.forwarder.Close()
	ingressKey := pubkey(9)
	missingKey := pubkey(8)

	ingressClient, relaySide := net.Pipe()
	defer ingressClient.Close()
	go s.handleConn(relaySide)
	if err := WriteFrame(ingressClient, MakeRegisterFrame(ingressKey)); err != nil {
		t.Fatalf("WriteFrame register: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for s.ConnectedPeers() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("registered ingress peer did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	echoDone := make(chan struct{})
	if err := ingressClient.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline ingress: %v", err)
	}
	go func() {
		defer close(echoDone)
		frame, err := ReadFrame(ingressClient)
		if err != nil {
			return
		}
		if frame.Type != MsgRelayProbe {
			return
		}
		_ = WriteFrame(ingressClient, frame)
	}()

	controlClient, controlServer := net.Pipe()
	defer controlClient.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleIngressProbe(controlServer, MakeIngressProbeRequestFrame([][PubKeySize]byte{ingressKey, missingKey}))
		_ = controlServer.Close()
	}()

	if err := controlClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline control: %v", err)
	}
	resp, err := ReadFrame(controlClient)
	if err != nil {
		t.Fatalf("ReadFrame control: %v", err)
	}
	if resp.Type != MsgIngressProbe {
		t.Fatalf("response type = %#x, want MsgIngressProbe", resp.Type)
	}
	results, err := ParseIngressProbeResponseFrame(resp.Body)
	if err != nil {
		t.Fatalf("ParseIngressProbeResponseFrame: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].PubKey != ingressKey {
		t.Fatalf("result pubkey = %x, want %x", results[0].PubKey[:8], ingressKey[:8])
	}
	if results[0].RTT <= 0 {
		t.Fatalf("RTT = %v, want > 0", results[0].RTT)
	}
	select {
	case <-echoDone:
	case <-time.After(time.Second):
		t.Fatal("relay probe echo did not finish")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ingress probe control request did not finish")
	}
}

func TestServer_IngressProbeRejectedWhenControlDisabled(t *testing.T) {
	s := NewServer()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleConn(server)
	}()

	if err := WriteFrame(client, MakeIngressProbeRequestFrame([][PubKeySize]byte{pubkey(9)})); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	resp, err := ReadFrame(client)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if resp.Type != MsgError {
		t.Fatalf("response type = %#x, want MsgError", resp.Type)
	}
	if !strings.Contains(string(resp.Body), "relay control disabled") {
		t.Fatalf("response body = %q, want relay control disabled", string(resp.Body))
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control-disabled request did not finish")
	}
}

func readFrameWithDeadline(t *testing.T, c net.Conn) Frame {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	frame, err := ReadFrame(c)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	return frame
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestValidateProbeTarget(t *testing.T) {
	cases := []struct {
		name    string
		target  net.IP
		port    int
		wantErr bool
	}{
		{"public global-unicast", net.IPv4(203, 0, 113, 7), 3478, false},
		{"private RFC1918 (intra-VPC)", net.IPv4(10, 1, 2, 3), 3478, false},
		// Deliberately allowed: CGNAT addresses real intra-cluster node ranges
		// (EKS/GKE), same rationale as RFC1918. Pinned so a future tightening
		// cannot silently regress the intra-cluster path.
		{"CGNAT 100.64/10 (intra-cluster)", net.IPv4(100, 64, 1, 1), 3478, false},
		{"cloud metadata link-local", net.IPv4(169, 254, 169, 254), 3478, true},
		{"loopback", net.IPv4(127, 0, 0, 1), 3478, true},
		{"unspecified", net.IPv4zero, 3478, true},
		{"multicast", net.IPv4(224, 0, 0, 1), 3478, true},
		{"limited broadcast", net.IPv4bcast, 3478, true},
		{"nil", nil, 3478, true},
		{"zero port", net.IPv4(203, 0, 113, 7), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateProbeTarget(tc.target, tc.port); tc.wantErr != (err != nil) {
				t.Fatalf("validateProbeTarget(%v, %d) err = %v, wantErr = %v", tc.target, tc.port, err, tc.wantErr)
			}
		})
	}
}

func TestProbeLimiterBoundsRate(t *testing.T) {
	s := NewServer()
	// Drain the burst, then confirm the limiter starts denying — proving the
	// relay cannot be driven as an unbounded UDP reflector.
	allowed := 0
	for range probeRateBurst + 50 {
		if s.probeLimiter.Allow() {
			allowed++
		}
	}
	if allowed > probeRateBurst {
		t.Fatalf("allowed %d probes, want <= burst %d", allowed, probeRateBurst)
	}
	if s.probeLimiter.Allow() {
		t.Fatal("limiter still allowing after burst exhausted")
	}
}
