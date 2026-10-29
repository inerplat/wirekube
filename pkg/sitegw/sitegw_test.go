package sitegw

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

type fakeCharon struct {
	conns     map[string]*ipsec.Tunnel
	sa        ipsec.SAState
	initiated int
	listErr   error
}

func (f *fakeCharon) LoadShared(*ipsec.Tunnel) error { return nil }
func (f *fakeCharon) UnloadShared(string) error      { return nil }
func (f *fakeCharon) LoadConn(t *ipsec.Tunnel) error { f.conns[t.ConnName()] = t; return nil }
func (f *fakeCharon) UnloadConn(n string) error      { delete(f.conns, n); return nil }
func (f *fakeCharon) ListConns() ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []string
	for n := range f.conns {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
func (f *fakeCharon) SA(string) (ipsec.SAState, error) { return f.sa, nil }
func (f *fakeCharon) Initiate(string) error            { f.initiated++; return nil }

type fakeDataplane struct{ guarded []ipsec.SelectorPair }

func (*fakeDataplane) EnsureRule() error                                  { return nil }
func (*fakeDataplane) RemoveRule()                                        {}
func (*fakeDataplane) EnsureInterface(string, uint32, int) error          { return errors.New("unsupported") }
func (*fakeDataplane) DeleteInterface(string) error                       { return nil }
func (*fakeDataplane) ListInterfaces() ([]string, error)                  { return nil, nil }
func (*fakeDataplane) SyncRoutes(map[string][]string, net.IP) error       { return nil }
func (*fakeDataplane) IsUnsupported(error) bool                           { return true }
func (f *fakeDataplane) SyncGuard(p []ipsec.SelectorPair) error           { f.guarded = p; return nil }
func (*fakeDataplane) GuardDrops() (map[ipsec.SelectorPair]uint64, error) { return nil, nil }
func (*fakeDataplane) XFRMInterfaceBlocker() string                       { return "ipv6.disable=1" }

const testConfig = `{
  "name": "vpn-a",
  "connectionUID": "uid-1",
  "localTrafficSelectors": ["192.168.10.0/24"],
  "localID": "203.0.113.1",
  "routeSource": "192.168.10.254",
  "tunnels": [
    {"name": "t1", "remoteAddress": "198.51.100.10", "remoteTrafficSelectors": ["10.20.0.0/16"], "preSharedKeyRef": {"name": "unused", "key": "t1"}}
  ]
}`

func gatewayFixture(t *testing.T, config string) (*Runner, *fakeCharon, *fakeDataplane, string) {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "t1"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	ch := &fakeCharon{conns: map[string]*ipsec.Tunnel{}}
	dp := &fakeDataplane{}
	r := &Runner{
		Engine:     NewEngine(ch, dp, nil, testr.New(t)),
		Publisher:  NewPublisher("pod-1", ""),
		ConfigPath: path,
		KeyDir:     keys,
		Interval:   10 * time.Second,
		Log:        testr.New(t),
	}
	return r, ch, dp, path
}

func TestStandaloneGatewayLoadsTheConfigWithoutTheMesh(t *testing.T) {
	r, ch, dp, _ := gatewayFixture(t, testConfig)
	r.Sync()
	if len(ch.conns) != 1 {
		t.Fatalf("conns = %v", ch.conns)
	}
	for _, tu := range ch.conns {
		if tu.Name != "vpn-a/t1" || tu.PreSharedKey != "s3cret" || tu.LocalID != "203.0.113.1" ||
			strings.Join(tu.LocalTS, ",") != "192.168.10.0/24" || tu.RouteBased {
			t.Fatalf("tunnel = %+v", tu)
		}
	}
	if len(dp.guarded) != 1 || dp.guarded[0] != (ipsec.SelectorPair{Local: "192.168.10.0/24", Remote: "10.20.0.0/16"}) {
		t.Fatalf("guard = %v", dp.guarded)
	}
	snap := r.Publisher.Current()
	if snap.ConnectionUID != "uid-1" || snap.PodUID != "pod-1" || !snap.CharonReachable || snap.AppliedConfigHash == "" ||
		len(snap.Tunnels) != 1 || snap.Tunnels[0].Phase != wirekubev1alpha1.IPsecTunnelPhaseConnecting ||
		snap.Tunnels[0].Dataplane != wirekubev1alpha1.IPsecDataplanePolicy {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestSnapshotSeqMovesOnlyOnWorthyChanges(t *testing.T) {
	r, ch, _, _ := gatewayFixture(t, testConfig)
	r.Sync()
	r.Sync()
	seq := r.Publisher.Current().Seq
	for _, state := range []string{"CONNECTING", "", "CONNECTING"} {
		ch.sa = ipsec.SAState{IKEState: state}
		r.Sync()
	}
	if got := r.Publisher.Current().Seq; got != seq {
		t.Fatalf("seq %d -> %d while only the IKE_SA state changed", seq, got)
	}
	if ch.initiated == 0 {
		t.Fatal("a connection without an IKE_SA was not initiated again")
	}
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	r.Sync()
	snap := r.Publisher.Current()
	if snap.Seq != seq+1 || snap.Tunnels[0].Phase != wirekubev1alpha1.IPsecTunnelPhaseEstablished || snap.Tunnels[0].LastTransitionTime == nil {
		t.Fatalf("snapshot after the tunnel came up = %+v", snap)
	}
}

func TestBadConfigKeepsTheLastGoodTunnels(t *testing.T) {
	r, ch, _, path := gatewayFixture(t, testConfig)
	r.Sync()
	if err := os.WriteFile(path, []byte(`{"name": "vpn-a", "tunels": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Sync()
	snap := r.Publisher.Current()
	if len(ch.conns) != 1 || snap.ConfigError == "" || len(snap.Tunnels) != 1 {
		t.Fatalf("a bad config edit changed the tunnels: conns=%v snapshot=%+v", ch.conns, snap)
	}
}

func TestHealthFollowsTheSyncLoopAndCharon(t *testing.T) {
	r, ch, _, _ := gatewayFixture(t, testConfig)
	now := time.Now()
	r.Now = func() time.Time { return now }
	health := func() int {
		rec := httptest.NewRecorder()
		r.ServeHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Code
	}
	if health() != http.StatusServiceUnavailable {
		t.Fatal("healthy before the first sync")
	}
	r.Sync()
	if health() != http.StatusOK {
		t.Fatal("unhealthy after a good sync")
	}
	now = now.Add(time.Minute)
	if health() != http.StatusServiceUnavailable {
		t.Fatal("healthy with a stalled sync loop")
	}
	ch.listErr = errors.New("dial unix: no such file")
	r.Sync()
	if health() != http.StatusServiceUnavailable || r.Publisher.Current().CharonReachable {
		t.Fatal("healthy without charon")
	}
}

func TestLongPollAnswersOnChangeOrTimeout(t *testing.T) {
	r, ch, _, _ := gatewayFixture(t, testConfig)
	r.Sync()
	seq := r.Publisher.Current().Seq
	boot := r.Publisher.Current().BootID

	get := func(q string) Snapshot {
		rec := httptest.NewRecorder()
		r.Publisher.ServeStatus(rec, httptest.NewRequest(http.MethodGet, "/v1/status?"+q, nil))
		var s Snapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	start := time.Now()
	if s := get("since=" + itoa(seq) + "&wait=50ms&bootID=" + boot); s.Seq != seq || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("an unchanged snapshot came back early or wrong: %+v", s)
	}
	done := make(chan Snapshot)
	go func() { done <- get("since=" + itoa(seq) + "&wait=5s&bootID=" + boot) }()
	time.Sleep(20 * time.Millisecond)
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	r.Sync()
	select {
	case s := <-done:
		if s.Seq != seq+1 {
			t.Fatalf("seq = %d", s.Seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the long poll did not return on a change")
	}
	start = time.Now()
	if s := get("since=999&wait=5s&bootID=another-boot"); s.BootID != boot || time.Since(start) > time.Second {
		t.Fatal("a reader holding another boot's seq waited")
	}
}

func itoa(n uint64) string { b, _ := json.Marshal(n); return string(b) }

func TestConfigRefusesUnknownFieldsAndPathKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, []byte(`{"name": "x", "tunnels": [], "extra": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := readKey(dir, "../c.json"); err == nil {
		t.Fatal("a key name escaped the key directory")
	}
}

// ifaceDataplane supports XFRM interfaces.
type ifaceDataplane struct {
	fakeDataplane
	routes map[string][]string
}

func (*ifaceDataplane) EnsureInterface(string, uint32, int) error { return nil }
func (*ifaceDataplane) XFRMInterfaceBlocker() string              { return "" }
func (d *ifaceDataplane) SyncRoutes(r map[string][]string, _ net.IP) error {
	d.routes = r
	return nil
}

func redundantPlans(t *testing.T, last wirekubev1alpha1.IPsecTunnelPhase) []*Plan {
	t.Helper()
	var plans []*Plan
	for i, name := range []string{"a", "b"} {
		tu := &ipsec.Tunnel{Name: "gw/" + name, RemoteAddress: "198.51.100." + string(rune('1'+i)), PreSharedKey: "k",
			LocalTS: []string{"192.168.10.0/24"}, RemoteTS: []string{"10.20.0.0/16"}, IKEVersion: 2,
			InterfaceID: uint32(10 + i), MTU: 1400}
		plans = append(plans, &Plan{Group: "gw", Name: name, Index: i, Tunnel: tu, LastPhase: last})
	}
	Validate(plans)
	return plans
}

func TestUnknownLastPhaseDoesNotMoveTheCarrier(t *testing.T) {
	ch := &fakeCharon{conns: map[string]*ipsec.Tunnel{}}
	dp := &ifaceDataplane{}
	e := NewEngine(ch, dp, nil, testr.New(t))
	e.Sync(redundantPlans(t, ""))
	// b comes up and takes the routes.
	e.phases["gw/a"], e.phases["gw/b"] = wirekubev1alpha1.IPsecTunnelPhaseConnecting, wirekubev1alpha1.IPsecTunnelPhaseEstablished
	plans := redundantPlans(t, wirekubev1alpha1.IPsecTunnelPhaseUnknown)
	e.Sync(plans)
	if want := ipsec.InterfaceName(11); len(dp.routes[want]) == 0 {
		t.Fatalf("routes = %v; an observer's Unknown moved the carrier off the established tunnel", dp.routes)
	}

	// After a restart no phase is known; charon's SAs decide.
	restarted := NewEngine(&saByConn{fakeCharon: ch, up: plans[1].Tunnel.ConnName()}, dp, nil, testr.New(t))
	restarted.Sync(redundantPlans(t, wirekubev1alpha1.IPsecTunnelPhaseUnknown))
	if want := ipsec.InterfaceName(11); len(dp.routes[want]) == 0 {
		t.Fatalf("routes after a restart = %v; want them on the tunnel with SAs", dp.routes)
	}
}

type saByConn struct {
	*fakeCharon
	up string
}

func (s *saByConn) SA(conn string) (ipsec.SAState, error) {
	if conn == s.up {
		return ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}, nil
	}
	return ipsec.SAState{}, nil
}

func TestHealthNeedsAConfigAndCharonEvenWithoutTunnels(t *testing.T) {
	r, ch, _, path := gatewayFixture(t, `{"name": "vpn-a", "tunnels": []}`)
	health := func() int {
		rec := httptest.NewRecorder()
		r.ServeHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Code
	}
	ch.listErr = errors.New("dial unix: no such file")
	r.Sync()
	if health() != http.StatusServiceUnavailable {
		t.Fatal("healthy with charon gone and no tunnels")
	}
	ch.listErr = nil
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2, _, _, _ := gatewayFixture(t, "{")
	r2.Sync()
	rec := httptest.NewRecorder()
	r2.ServeHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal("healthy before any config could be read")
	}
}

func TestStalledLoopAnswersStatusWith503(t *testing.T) {
	r, _, _, _ := gatewayFixture(t, testConfig)
	now := time.Now()
	r.Now = func() time.Time { return now }
	r.Publisher.Stale = r.Stale
	r.Sync()
	get := func() int {
		rec := httptest.NewRecorder()
		r.Publisher.ServeStatus(rec, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
		return rec.Code
	}
	if get() != http.StatusOK {
		t.Fatal("fresh snapshot not served")
	}
	now = now.Add(time.Minute)
	if get() != http.StatusServiceUnavailable {
		t.Fatal("a stalled loop's snapshot was served as live")
	}
}

func TestIPv6SelectorsAreRefused(t *testing.T) {
	r, ch, _, _ := gatewayFixture(t, strings.Replace(testConfig, `"10.20.0.0/16"`, `"2001:db8::/32"`, 1))
	r.Sync()
	st := r.Publisher.Current().Tunnels[0]
	if len(ch.conns) != 0 || st.Reason != wirekubev1alpha1.IPsecReasonConfigError || !strings.Contains(st.Message, "IPv4") {
		t.Fatalf("an IPv6 tunnel was accepted: %+v", st)
	}
}

func TestIPv6PairsStayOutOfTheGuard(t *testing.T) {
	tu := &ipsec.Tunnel{LocalTS: []string{"192.168.10.0/24"}, RemoteTS: []string{"10.20.0.0/16", "2001:db8::/32"}}
	if got := GuardablePairs(tu); len(got) != 1 || got[0].Remote != "10.20.0.0/16" {
		t.Fatalf("pairs = %v", got)
	}
}

func TestCharonFailureDuringLoadIsNotAConfigError(t *testing.T) {
	r, ch, _, _ := gatewayFixture(t, testConfig)
	r.Engine.Charon = &failingLoad{fakeCharon: ch}
	r.Sync()
	if st := r.Publisher.Current().Tunnels[0]; st.Reason != wirekubev1alpha1.IPsecReasonIKEDaemonUnavailable {
		t.Fatalf("reason = %q", st.Reason)
	}
}

type failingLoad struct{ *fakeCharon }

func (*failingLoad) LoadConn(*ipsec.Tunnel) error { return errors.New("vici: connection reset") }

func TestCharonRefusingALoadIsAConfigError(t *testing.T) {
	r, ch, _, _ := gatewayFixture(t, testConfig)
	r.Engine.Charon = &refusingLoad{fakeCharon: ch}
	r.Sync()
	if st := r.Publisher.Current().Tunnels[0]; st.Reason != wirekubev1alpha1.IPsecReasonConfigError {
		t.Fatalf("reason = %q", st.Reason)
	}
}

type refusingLoad struct{ *fakeCharon }

func (*refusingLoad) LoadConn(*ipsec.Tunnel) error {
	return fmt.Errorf("vici load-conn: %w: command failed: invalid proposal", ipsec.ErrRejected)
}

func TestConfigOutsideTheCRDSchemaIsRefused(t *testing.T) {
	for name, field := range map[string]string{
		"remote %any":  `"remoteAddress": "%any"`,
		"interface id": `"remoteAddress": "198.51.100.10", "interfaceID": 4294967295`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := `{"name": "vpn-a", "localTrafficSelectors": ["192.168.10.0/24"], "tunnels": [{"name": "t1", ` + field +
				`, "remoteTrafficSelectors": ["10.20.0.0/16"], "preSharedKeyRef": {"name": "unused", "key": "t1"}}]}`
			r, ch, _, _ := gatewayFixture(t, cfg)
			r.Sync()
			st := r.Publisher.Current().Tunnels[0]
			if len(ch.conns) != 0 || st.Reason != wirekubev1alpha1.IPsecReasonConfigError {
				t.Fatalf("conns=%v status=%+v", ch.conns, st)
			}
		})
	}
}

func TestFailureLogMemoryForgetsTunnelsThatLeft(t *testing.T) {
	r, _, _, _ := gatewayFixture(t, testConfig)
	r.Sync()
	r.Engine.failureLogged["wk-vpn-a/t0@deadbeef"] = "AUTHENTICATION_FAILED"
	r.Sync()
	if len(r.Engine.failureLogged) != 0 {
		t.Fatalf("failureLogged = %v", r.Engine.failureLogged)
	}
}

func TestLongPollTimeoutReturnsTheLatestSnapshot(t *testing.T) {
	p := NewPublisher("pod-1", "uid-1")
	p.Publish(Snapshot{Tunnels: []wirekubev1alpha1.GatewayIPsecTunnelStatus{{Name: "t1", Phase: wirekubev1alpha1.IPsecTunnelPhaseConnecting, IKEState: "CONNECTING"}}})
	cur := p.Current()
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.Publish(Snapshot{Tunnels: []wirekubev1alpha1.GatewayIPsecTunnelStatus{{Name: "t1", Phase: wirekubev1alpha1.IPsecTunnelPhaseConnecting, IKEState: "DELETING"}}})
	}()
	rec := httptest.NewRecorder()
	p.ServeStatus(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v1/status?since=%d&bootID=%s&wait=200ms", cur.Seq, cur.BootID), nil))
	var got Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Seq != cur.Seq || got.Tunnels[0].IKEState != "DELETING" {
		t.Fatalf("snapshot after the wait = seq %d, ikeState %q", got.Seq, got.Tunnels[0].IKEState)
	}
}

func TestLocalSelectorCoveringTheGatewayIsRefused(t *testing.T) {
	cfg := strings.Replace(testConfig, `["192.168.10.0/24"]`, `["10.0.0.0/8"]`, 1)
	cfg = strings.Replace(cfg, `["10.20.0.0/16"]`, `["192.168.0.0/16"]`, 1)
	r, ch, _, _ := gatewayFixture(t, cfg)
	r.OwnAddresses = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.244.1.5")}, nil }
	r.Sync()
	st := r.Publisher.Current().Tunnels[0]
	if len(ch.conns) != 0 || st.Reason != wirekubev1alpha1.IPsecReasonConfigError || !strings.Contains(st.Message, "10.244.1.5") {
		t.Fatalf("conns=%v status=%+v", ch.conns, st)
	}
	r.OwnAddresses = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("172.16.0.5")}, nil }
	r.Sync()
	if len(ch.conns) != 1 {
		t.Fatalf("a tunnel clear of the uplink address was not loaded: %v", r.Publisher.Current().Tunnels)
	}
}

func TestValidateRefusesIPv6SelectorsForEveryCaller(t *testing.T) {
	p := &Plan{Group: "g", Name: "t1", Tunnel: &ipsec.Tunnel{Name: "t1", LocalTS: []string{"10.0.0.0/24"}, RemoteTS: []string{"2001:db8::/32"}}}
	Validate([]*Plan{p})
	if p.Err == nil || !strings.Contains(p.Err.Error(), "2001:db8::/32") {
		t.Fatalf("err = %v", p.Err)
	}
}
