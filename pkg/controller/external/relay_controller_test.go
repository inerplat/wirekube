package external

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/inerplat/wirekube/pkg/relay"
	"github.com/inerplat/wirekube/pkg/relay/portalloc"
)

// pickRange returns a small allocator range that does not collide with
// privileged or commonly bound ports on dev machines. The reconciler does
// not care about the specific value; we just need ports that ListenUDP
// can bind to.
func pickRange(t *testing.T) (uint16, uint16) {
	t.Helper()
	// Use a small ephemeral-style window. The forwarder binds 0.0.0.0:port
	// which can collide with anything; tests requiring a real bind run
	// across a small window so failure is loud rather than silently
	// reusing the wrong port.
	return 41000, 41015
}

// newLocalForTest constructs a LocalRelayController with a fresh
// allocator and forwarder backed by a noop dispatcher.
func newLocalForTest(t *testing.T) (*LocalRelayController, func()) {
	t.Helper()
	min, max := pickRange(t)
	alloc, err := portalloc.New(min, max)
	if err != nil {
		t.Fatalf("portalloc.New: %v", err)
	}
	fw := relay.NewForwarder(nil) // noopDispatcher inside the package
	c := NewLocalRelayController(alloc, fw, "relay.example.com")
	return c, func() { fw.Close() }
}

func TestLocalRelayController_RegisterUnregisterRoundtrip(t *testing.T) {
	c, cleanup := newLocalForTest(t)
	defer cleanup()

	var ingress, ext [32]byte
	for i := range ingress {
		ingress[i] = 0xAA
		ext[i] = 0x55
	}

	port, err := c.RegisterForwarder(context.Background(), ingress, ext)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if port == 0 {
		t.Fatal("Register returned port 0")
	}

	// The allocator should now report exactly one port in use.
	if got := c.alloc.InUse(); len(got) != 1 || got[0] != port {
		t.Fatalf("alloc.InUse = %v, want [%d]", got, port)
	}

	if err := c.UnregisterForwarder(context.Background(), port); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	// Allocator pool should be empty again.
	if got := c.alloc.InUse(); len(got) != 0 {
		t.Fatalf("alloc.InUse after unregister = %v, want []", got)
	}
}

func TestLocalRelayController_DoubleRegisterFreshKeysAllocatesNewPort(t *testing.T) {
	c, cleanup := newLocalForTest(t)
	defer cleanup()

	var ingress1, ext1, ingress2, ext2 [32]byte
	ingress1[0] = 1
	ext1[0] = 2
	ingress2[0] = 3
	ext2[0] = 4

	first, err := c.RegisterForwarder(context.Background(), ingress1, ext1)
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	second, err := c.RegisterForwarder(context.Background(), ingress2, ext2)
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if first == second {
		t.Fatalf("expected distinct ports, got %d twice", first)
	}

	// Free the first mapping; the allocator's cursor should not hand the
	// same port back immediately, but freeing the second mapping should
	// also work.
	if err := c.UnregisterForwarder(context.Background(), first); err != nil {
		t.Fatalf("Unregister first: %v", err)
	}
	if err := c.UnregisterForwarder(context.Background(), second); err != nil {
		t.Fatalf("Unregister second: %v", err)
	}
	if got := c.alloc.InUse(); len(got) != 0 {
		t.Fatalf("InUse after both unregistered = %v", got)
	}
}

func TestLocalRelayController_UnregisterUnknownPortIsIdempotent(t *testing.T) {
	c, cleanup := newLocalForTest(t)
	defer cleanup()

	if err := c.UnregisterForwarder(context.Background(), 9999); err != nil {
		t.Fatalf("unknown port should be idempotent, got %v", err)
	}
}

func TestNoopRelayController_AlwaysErrNotImplemented(t *testing.T) {
	c := NewNoopRelayController("relay.example.com")

	if c.RelayEndpoint() != "relay.example.com" {
		t.Fatalf("RelayEndpoint = %q", c.RelayEndpoint())
	}

	var ingress, ext [32]byte
	if _, err := c.RegisterForwarder(context.Background(), ingress, ext); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RegisterForwarder err = %v, want ErrNotImplemented", err)
	}
	if err := c.UnregisterForwarder(context.Background(), 1234); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("UnregisterForwarder err = %v, want ErrNotImplemented", err)
	}
}

func TestFanoutRelayController_RegisterSamePortOnAllReplicas(t *testing.T) {
	first := startFakeRelayControl(t, 53042)
	second := startFakeRelayControl(t, 61000)
	defer first.Close()
	defer second.Close()

	c := &FanoutRelayController{
		controlAddr: "",
		endpoint:    "relay.example.com",
	}
	c.controllersFn = func() []*RemoteRelayController {
		return []*RemoteRelayController{
			NewRemoteRelayController(first.Addr(), c.endpoint),
			NewRemoteRelayController(second.Addr(), c.endpoint),
		}
	}

	var ingress, ext [32]byte
	ingress[0] = 1
	ext[0] = 2
	port, err := c.RegisterForwarder(context.Background(), ingress, ext)
	if err != nil {
		t.Fatalf("RegisterForwarder: %v", err)
	}
	if port != 53042 {
		t.Fatalf("port = %d, want 53042", port)
	}

	firstRegs := first.Registers()
	secondRegs := second.Registers()
	if len(firstRegs) != 1 || firstRegs[0].RequestedPort != 0 || firstRegs[0].ResponsePort != 53042 {
		t.Fatalf("first registers = %+v, want request=0 response=53042", firstRegs)
	}
	if len(secondRegs) != 1 || secondRegs[0].RequestedPort != 53042 || secondRegs[0].ResponsePort != 53042 {
		t.Fatalf("second registers = %+v, want request=response=53042", secondRegs)
	}

	if err := c.UnregisterForwarder(context.Background(), port); err != nil {
		t.Fatalf("UnregisterForwarder: %v", err)
	}
	if got := first.Unregisters(); len(got) != 1 || got[0] != 53042 {
		t.Fatalf("first unregisters = %v, want [53042]", got)
	}
	if got := second.Unregisters(); len(got) != 1 || got[0] != 53042 {
		t.Fatalf("second unregisters = %v, want [53042]", got)
	}
}

func TestFanoutRelayController_RollsBackOnReplicaFailure(t *testing.T) {
	first := startFakeRelayControl(t, 53042)
	second := startFakeRelayControl(t, 61000)
	second.failRegister = true
	defer first.Close()
	defer second.Close()

	c := &FanoutRelayController{endpoint: "relay.example.com"}
	c.controllersFn = func() []*RemoteRelayController {
		return []*RemoteRelayController{
			NewRemoteRelayController(first.Addr(), c.endpoint),
			NewRemoteRelayController(second.Addr(), c.endpoint),
		}
	}

	var ingress, ext [32]byte
	if _, err := c.RegisterForwarder(context.Background(), ingress, ext); err == nil {
		t.Fatal("RegisterForwarder succeeded, want error")
	}
	if got := first.Unregisters(); len(got) != 1 || got[0] != 53042 {
		t.Fatalf("rollback unregisters on first = %v, want [53042]", got)
	}
}

func TestFanoutRelayController_EnsureForwarderRegistersAllReplicasAtExistingPort(t *testing.T) {
	first := startFakeRelayControl(t, 53042)
	second := startFakeRelayControl(t, 61000)
	defer first.Close()
	defer second.Close()

	c := &FanoutRelayController{endpoint: "relay.example.com"}
	c.controllersFn = func() []*RemoteRelayController {
		return []*RemoteRelayController{
			NewRemoteRelayController(first.Addr(), c.endpoint),
			NewRemoteRelayController(second.Addr(), c.endpoint),
		}
	}

	var ingress, ext [32]byte
	if err := c.EnsureForwarder(context.Background(), 53042, ingress, ext); err != nil {
		t.Fatalf("EnsureForwarder: %v", err)
	}
	for name, regs := range map[string][]fakeRelayRegister{
		"first":  first.Registers(),
		"second": second.Registers(),
	} {
		if len(regs) != 1 || regs[0].RequestedPort != 53042 || regs[0].ResponsePort != 53042 {
			t.Fatalf("%s registers = %+v, want request=response=53042", name, regs)
		}
	}
}

func TestFanoutRelayController_ProbeIngressLatencyRequiresEveryReplica(t *testing.T) {
	first := startFakeRelayControl(t, 53042)
	second := startFakeRelayControl(t, 61000)
	defer first.Close()
	defer second.Close()

	var keyA, keyB [32]byte
	keyA[0] = 1
	keyB[0] = 2
	first.SetProbeLatencies(map[[32]byte]time.Duration{
		keyA: 10 * time.Millisecond,
		keyB: 20 * time.Millisecond,
	})
	second.SetProbeLatencies(map[[32]byte]time.Duration{
		keyA: 15 * time.Millisecond,
	})

	c := &FanoutRelayController{endpoint: "relay.example.com"}
	c.controllersFn = func() []*RemoteRelayController {
		return []*RemoteRelayController{
			NewRemoteRelayController(first.Addr(), c.endpoint),
			NewRemoteRelayController(second.Addr(), c.endpoint),
		}
	}

	got, err := c.ProbeIngressLatency(context.Background(), [][32]byte{keyA, keyB})
	if err != nil {
		t.Fatalf("ProbeIngressLatency: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("latency result len = %d, want 1: %v", len(got), got)
	}
	if got[keyA] != 15*time.Millisecond {
		t.Fatalf("keyA RTT = %v, want 15ms", got[keyA])
	}
	if _, ok := got[keyB]; ok {
		t.Fatal("keyB should be omitted because it was not reachable from every replica")
	}
	if len(first.ProbeRequests()) != 1 || len(second.ProbeRequests()) != 1 {
		t.Fatalf("probe requests first=%d second=%d, want 1 each", len(first.ProbeRequests()), len(second.ProbeRequests()))
	}
}

func TestRemoteRelayController_ProbeIngressLatencyDisabled(t *testing.T) {
	server := startFakeRelayControl(t, 53042)
	defer server.Close()
	server.SetProbeError("relay control disabled")

	var key [32]byte
	_, err := NewRemoteRelayController(server.Addr(), "relay.example.com").ProbeIngressLatency(context.Background(), [][32]byte{key})
	if !errors.Is(err, ErrIngressProbeDisabled) {
		t.Fatalf("ProbeIngressLatency error = %v, want ErrIngressProbeDisabled", err)
	}
}

func TestFanoutRelayController_ProbeIngressLatencyDisabledFallsBack(t *testing.T) {
	first := startFakeRelayControl(t, 53042)
	second := startFakeRelayControl(t, 61000)
	defer first.Close()
	defer second.Close()
	first.SetProbeError("relay control disabled")
	second.SetProbeError("relay control disabled")

	var key [32]byte
	c := &FanoutRelayController{endpoint: "relay.example.com"}
	c.controllersFn = func() []*RemoteRelayController {
		return []*RemoteRelayController{
			NewRemoteRelayController(first.Addr(), c.endpoint),
			NewRemoteRelayController(second.Addr(), c.endpoint),
		}
	}

	_, err := c.ProbeIngressLatency(context.Background(), [][32]byte{key})
	if !errors.Is(err, ErrIngressProbeDisabled) {
		t.Fatalf("ProbeIngressLatency error = %v, want ErrIngressProbeDisabled", err)
	}
}

type fakeRelayControl struct {
	ln net.Listener

	mu           sync.Mutex
	nextPort     uint16
	failRegister bool
	registers    []fakeRelayRegister
	unregisters  []uint16
	probeRTTs    map[[32]byte]time.Duration
	probeErr     string
	probeReqs    [][][32]byte
}

type fakeRelayRegister struct {
	RequestedPort uint16
	ResponsePort  uint16
}

func startFakeRelayControl(t *testing.T, nextPort uint16) *fakeRelayControl {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	f := &fakeRelayControl{ln: ln, nextPort: nextPort}
	go f.serve()
	return f
}

func (f *fakeRelayControl) Addr() string {
	return f.ln.Addr().String()
}

func (f *fakeRelayControl) Close() {
	_ = f.ln.Close()
}

func (f *fakeRelayControl) Registers() []fakeRelayRegister {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeRelayRegister, len(f.registers))
	copy(out, f.registers)
	return out
}

func (f *fakeRelayControl) Unregisters() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint16, len(f.unregisters))
	copy(out, f.unregisters)
	return out
}

func (f *fakeRelayControl) SetProbeLatencies(latencies map[[32]byte]time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeRTTs = make(map[[32]byte]time.Duration, len(latencies))
	for key, rtt := range latencies {
		f.probeRTTs[key] = rtt
	}
}

func (f *fakeRelayControl) SetProbeError(message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeErr = message
}

func (f *fakeRelayControl) ProbeRequests() [][][32]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][][32]byte, len(f.probeReqs))
	for i := range f.probeReqs {
		out[i] = append([][32]byte(nil), f.probeReqs[i]...)
	}
	return out
}

func (f *fakeRelayControl) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeRelayControl) handle(conn net.Conn) {
	defer conn.Close()
	frame, err := relay.ReadFrame(conn)
	if err != nil {
		return
	}
	switch frame.Type {
	case relay.MsgForwarderRegister:
		port, ingress, ext, err := relay.ParseForwarderRegisterFrame(frame.Body)
		if err != nil {
			_ = relay.WriteFrame(conn, relay.MakeErrorFrame(err.Error()))
			return
		}
		if f.failRegister {
			_ = relay.WriteFrame(conn, relay.MakeErrorFrame("synthetic register failure"))
			return
		}
		respPort := port
		f.mu.Lock()
		if respPort == 0 {
			respPort = f.nextPort
			f.nextPort++
		}
		f.registers = append(f.registers, fakeRelayRegister{RequestedPort: port, ResponsePort: respPort})
		f.mu.Unlock()
		_ = relay.WriteFrame(conn, relay.MakeForwarderRegisterFrame(respPort, ingress, ext))
	case relay.MsgForwarderUnregister:
		port, err := relay.ParseForwarderUnregisterFrame(frame.Body)
		if err != nil {
			_ = relay.WriteFrame(conn, relay.MakeErrorFrame(err.Error()))
			return
		}
		f.mu.Lock()
		f.unregisters = append(f.unregisters, port)
		f.mu.Unlock()
		_ = relay.WriteFrame(conn, relay.MakeForwarderUnregisterFrame(port))
	case relay.MsgIngressProbe:
		keys, err := relay.ParseIngressProbeRequestFrame(frame.Body)
		if err != nil {
			_ = relay.WriteFrame(conn, relay.MakeErrorFrame(err.Error()))
			return
		}
		f.mu.Lock()
		if f.probeErr != "" {
			probeErr := f.probeErr
			f.mu.Unlock()
			_ = relay.WriteFrame(conn, relay.MakeErrorFrame(probeErr))
			return
		}
		f.probeReqs = append(f.probeReqs, append([][32]byte(nil), keys...))
		results := make([]relay.IngressProbeResult, 0, len(keys))
		for _, key := range keys {
			if rtt, ok := f.probeRTTs[key]; ok {
				results = append(results, relay.IngressProbeResult{PubKey: key, RTT: rtt})
			}
		}
		f.mu.Unlock()
		_ = relay.WriteFrame(conn, relay.MakeIngressProbeResponseFrame(results))
	default:
		_ = relay.WriteFrame(conn, relay.MakeErrorFrame(fmt.Sprintf("unexpected type %#x", frame.Type)))
	}
}
