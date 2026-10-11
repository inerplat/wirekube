package agent

import (
	"context"
	"crypto/sha256"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/strongswan/govici/vici"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

const testKey = "site/vpn"

// fakeCharon keys connections by tunnel key ("site/vpn"), not by the hashed
// connection name.
type fakeCharon struct {
	conns       map[string]*ipsec.Tunnel
	shared      map[string]bool
	loads       int
	unloads     []string
	initiated   []string
	sa          ipsec.SAState
	saByKey     map[string]ipsec.SAState
	listErr     error
	unloadErr   error
	loadConnErr error
}

func keyOf(conn string) string {
	if k, ok := ipsec.KeyOfConn(conn); ok {
		return k
	}
	return conn
}

func (f *fakeCharon) LoadShared(t *ipsec.Tunnel) error { f.shared[t.Name] = true; return nil }
func (f *fakeCharon) UnloadShared(n string) error      { delete(f.shared, keyOf(n)); return nil }
func (f *fakeCharon) LoadConn(t *ipsec.Tunnel) error {
	if f.loadConnErr != nil {
		return f.loadConnErr
	}
	f.loads++
	f.conns[t.Name] = t
	return nil
}
func (f *fakeCharon) UnloadConn(n string) error {
	if f.unloadErr != nil {
		return f.unloadErr
	}
	f.unloads = append(f.unloads, keyOf(n))
	delete(f.conns, keyOf(n))
	return nil
}
func (f *fakeCharon) ListConns() ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []string
	for _, t := range f.conns {
		out = append(out, t.ConnName())
	}
	sort.Strings(out)
	return out, nil
}
func (f *fakeCharon) SA(n string) (ipsec.SAState, error) {
	if sa, ok := f.saByKey[keyOf(n)]; ok {
		return sa, nil
	}
	return f.sa, nil
}
func (f *fakeCharon) Initiate(n string) error {
	f.initiated = append(f.initiated, keyOf(n))
	return nil
}

type fakeDataplane struct {
	// noXFRMI makes EnsureInterface fail as on a kernel without xfrm_interface.
	noXFRMI bool
	ensures int
	ifaces  map[string]uint32
	routes  map[string][]string
	src     net.IP
	rule    bool
	guard   []ipsec.SelectorPair
	blocker string
	// guardErr makes SyncGuard fail.
	guardErr error
}

var errUnsupportedKernel = errTest("creating XFRM interface: operation not supported")

func (f *fakeDataplane) EnsureRule() error { f.rule = true; return nil }
func (f *fakeDataplane) RemoveRule()       { f.rule = false }
func (f *fakeDataplane) EnsureInterface(n string, id uint32, _ int) error {
	f.ensures++
	if f.noXFRMI {
		return errUnsupportedKernel
	}
	f.ifaces[n] = id
	return nil
}
func (f *fakeDataplane) DeleteInterface(n string) error { delete(f.ifaces, n); return nil }
func (f *fakeDataplane) ListInterfaces() ([]string, error) {
	var out []string
	for n := range f.ifaces {
		out = append(out, n)
	}
	return out, nil
}
func (f *fakeDataplane) SyncRoutes(d map[string][]string, src net.IP) error {
	f.routes = d
	f.src = src
	return nil
}
func (f *fakeDataplane) IsUnsupported(err error) bool { return err == errUnsupportedKernel }
func (f *fakeDataplane) SyncGuard(p []ipsec.SelectorPair) error {
	if f.guardErr != nil {
		return f.guardErr
	}
	f.guard = p
	return nil
}
func (f *fakeDataplane) XFRMInterfaceBlocker() string                       { return f.blocker }
func (f *fakeDataplane) GuardDrops() (map[ipsec.SelectorPair]uint64, error) { return nil, nil }

type errTest string

func (e errTest) Error() string { return string(e) }

func ipsecTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wirekubev1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func tunnelSpec(name, remote, secret string) wirekubev1alpha1.GatewayIPsecTunnel {
	return wirekubev1alpha1.GatewayIPsecTunnel{Name: name, RemoteAddress: remote,
		PreSharedKeyRef: wirekubev1alpha1.IPsecSecretKeyRef{Name: secret}}
}

// ipsecFixture: peers gw-a (preferred) and gw-b, gateway "site" with tunnel "vpn".
func ipsecFixture(t *testing.T, node string, mutate func(*wirekubev1alpha1.WireKubeGateway), extra ...client.Object) (*Agent, *fakeCharon, *fakeDataplane, client.Client) {
	t.Helper()
	gw := &wirekubev1alpha1.WireKubeGateway{ObjectMeta: metav1.ObjectMeta{Name: "site"},
		Spec: wirekubev1alpha1.WireKubeGatewaySpec{PeerRefs: []string{"gw-a", "gw-b"},
			Routes: []wirekubev1alpha1.GatewayRoute{{CIDR: "10.77.1.0/24"}},
			IPsec:  []wirekubev1alpha1.GatewayIPsecTunnel{tunnelSpec("vpn", "203.0.113.10", "vpn-psk")}}}
	if mutate != nil {
		mutate(gw)
	}
	objs := []client.Object{
		&wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: "198.18.0.0/16"}},
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"},
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "a", AllowedIPs: []string{"198.18.0.1/32"}, Endpoint: "198.51.100.1:51820"}},
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-b"},
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "b", AllowedIPs: []string{"198.18.0.2/32"}, Endpoint: "198.51.100.2:51820"}},
		gw,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vpn-psk", Namespace: "wirekube-system"},
			Data: map[string][]byte{"psk": []byte("s3cret")}},
	}
	objs = append(objs, extra...)
	c := ctrlclientfake.NewClientBuilder().WithScheme(ipsecTestScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeGateway{}).Build()
	ch := &fakeCharon{conns: map[string]*ipsec.Tunnel{}, shared: map[string]bool{}}
	dp := &fakeDataplane{ifaces: map[string]uint32{}}
	a := &Agent{log: testr.New(t), client: c, nodeName: node, podNamespace: "wirekube-system"}
	a.ipsec = &ipsecState{charon: ch, dataplane: dp, reported: map[[2]string]bool{}, keys: map[string][sha256.Size]byte{}}
	return a, ch, dp, c
}

func getGateway(t *testing.T, c client.Client) *wirekubev1alpha1.WireKubeGateway {
	t.Helper()
	gw := &wirekubev1alpha1.WireKubeGateway{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "site"}, gw); err != nil {
		t.Fatal(err)
	}
	return gw
}

func tunnelStatusOf(t *testing.T, c client.Client, name string) wirekubev1alpha1.GatewayIPsecTunnelStatus {
	t.Helper()
	for _, st := range getGateway(t, c).Status.IPsec {
		if st.Name == name {
			return st
		}
	}
	return wirekubev1alpha1.GatewayIPsecTunnelStatus{}
}

func TestIPsecActiveGatewayLoadsTunnelWithDefaults(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", nil)
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}

	a.setupIPsec(context.Background())

	tu := ch.conns[testKey]
	if tu == nil {
		t.Fatalf("tunnel not loaded into charon: %v", ch.conns)
	}
	if tu.LocalTS[0] != "198.18.0.0/16" || tu.RemoteTS[0] != "10.77.1.0/24" {
		t.Errorf("selectors not defaulted from mesh and gateway: %v / %v", tu.LocalTS, tu.RemoteTS)
	}
	if tu.LocalID != "198.51.100.1" {
		t.Errorf("localID = %q; want the public address of this node's WireKubePeer endpoint", tu.LocalID)
	}
	if tu.PreSharedKey != "s3cret" || tu.IKEVersion != 2 || tu.MTU != ipsec.DefaultMTU {
		t.Errorf("defaults not applied: %+v", tu)
	}
	ifName := ipsec.InterfaceName(ipsec.DeriveInterfaceID(testKey))
	if dp.ifaces[ifName] != ipsec.DeriveInterfaceID(testKey) {
		t.Errorf("XFRM interface %s not ensured: %v", ifName, dp.ifaces)
	}
	if got := dp.routes[ifName]; len(got) != 1 || got[0] != "10.77.1.0/24" {
		t.Errorf("routes = %v", dp.routes)
	}
	if !dp.src.Equal(net.ParseIP("198.18.0.1")) || !dp.rule {
		t.Errorf("route source %v / rule %v", dp.src, dp.rule)
	}

	gw := getGateway(t, c)
	st := tunnelStatusOf(t, c, "vpn")
	if !gw.Status.Ready || st.Phase != wirekubev1alpha1.IPsecTunnelPhaseEstablished || st.InstalledChildSAs != 1 || st.LocalID != "198.51.100.1" {
		t.Errorf("ready=%v status=%+v", gw.Status.Ready, st)
	}

	a.setupIPsec(context.Background())
	if ch.loads != 1 {
		t.Errorf("connection reloaded without a change: %d loads", ch.loads)
	}
}

func TestIPsecExplicitLocalIDWins(t *testing.T) {
	a, ch, _, _ := ipsecFixture(t, "gw-a", func(g *wirekubev1alpha1.WireKubeGateway) { g.Spec.IPsec[0].LocalID = "vpn.example.net" })
	a.setupIPsec(context.Background())
	if got := ch.conns[testKey].LocalID; got != "vpn.example.net" {
		t.Errorf("localID = %q", got)
	}
}

func TestIPsecGatewayNotReadyUntilATunnelIsEstablished(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	a.setupIPsec(context.Background())
	if getGateway(t, c).Status.Ready {
		t.Fatalf("ready with no CHILD_SA")
	}
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	a.setupIPsec(context.Background())
	if !getGateway(t, c).Status.Ready {
		t.Fatalf("not ready with an established tunnel")
	}
}

func TestIPsecStandbyPeerDoesNothingAndDropsLeftovers(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-b", nil)
	ch.conns[testKey] = &ipsec.Tunnel{Name: testKey}
	dp.ifaces[ipsec.InterfaceName(ipsec.DeriveInterfaceID(testKey))] = ipsec.DeriveInterfaceID(testKey)
	a.ipsec.active = true

	a.setupIPsec(context.Background())

	if len(ch.conns) != 0 || len(ch.unloads) != 1 {
		t.Errorf("standby peer kept the connection: conns=%v unloads=%v", ch.conns, ch.unloads)
	}
	if len(dp.ifaces) != 0 || len(dp.routes) != 0 || dp.rule || len(dp.guard) != 0 {
		t.Errorf("standby peer kept dataplane state: %+v", dp)
	}
	if st := getGateway(t, c).Status.IPsec; len(st) != 0 {
		t.Errorf("standby peer wrote status: %+v", st)
	}
}

func TestIPsecFailoverFollowsGatewayElection(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-b", nil)
	a.setupIPsec(context.Background())
	if len(ch.conns) != 0 {
		t.Fatalf("gw-b loaded the tunnel while gw-a is elected")
	}
	if err := c.Delete(context.Background(), &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"}}); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	if tu := ch.conns[testKey]; tu == nil || tu.LocalID != "198.51.100.2" {
		t.Fatalf("gw-b did not take over the tunnel with its own localID: %+v", tu)
	}
	if st := tunnelStatusOf(t, c, "vpn"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseConnecting {
		t.Errorf("status after failover = %+v", st)
	}
}

func TestIPsecMissingSecretReportsErrorWithoutDataplane(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", nil)
	if err := c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vpn-psk", Namespace: "wirekube-system"}}); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	if len(ch.conns) != 0 || len(dp.ifaces) != 0 {
		t.Errorf("tunnel applied without its PSK: conns=%v ifaces=%v", ch.conns, dp.ifaces)
	}
	st := tunnelStatusOf(t, c, "vpn")
	if st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError || st.Message == "" || getGateway(t, c).Status.Ready {
		t.Errorf("status = %+v", st)
	}
}

func TestIPsecSecretOutsideAgentNamespaceIsNotRead(t *testing.T) {
	other := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "elsewhere", Namespace: "default"},
		Data: map[string][]byte{"psk": []byte("x")}}
	a, ch, _, _ := ipsecFixture(t, "gw-a", func(g *wirekubev1alpha1.WireKubeGateway) { g.Spec.IPsec[0].PreSharedKeyRef.Name = "elsewhere" }, other)
	a.setupIPsec(context.Background())
	if len(ch.conns) != 0 {
		t.Errorf("agent read a Secret outside its namespace")
	}
}

func TestIPsecCharonUnreachableIsReported(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	ch.listErr = errTest("dial unix /var/run/charon.vici: connect: no such file or directory")
	a.setupIPsec(context.Background())
	if st := tunnelStatusOf(t, c, "vpn"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError || st.Message == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestIPsecAutoFallsBackToPolicyWithoutXFRMInterfaces(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", nil)
	dp.noXFRMI = true
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	a.setupIPsec(context.Background())
	tu := ch.conns[testKey]
	if tu == nil || tu.RouteBased {
		t.Fatalf("Auto tunnel not loaded policy-based: %+v", tu)
	}
	if len(dp.routes) != 0 {
		t.Errorf("policy mode installed tunnel routes: %v", dp.routes)
	}
	st := tunnelStatusOf(t, c, "vpn")
	if st.Dataplane != wirekubev1alpha1.IPsecDataplanePolicy || st.InterfaceName != "" || st.Phase != wirekubev1alpha1.IPsecTunnelPhaseEstablished {
		t.Errorf("status = %+v", st)
	}
	before := dp.ensures
	a.setupIPsec(context.Background())
	if dp.ensures != before {
		t.Errorf("retried XFRM interface creation after the kernel refused it")
	}
}

func TestIPsecExplicitXFRMInterfaceDoesNotFallBack(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", func(g *wirekubev1alpha1.WireKubeGateway) {
		g.Spec.IPsec[0].Dataplane = wirekubev1alpha1.IPsecDataplaneXFRMInterface
	})
	dp.noXFRMI = true
	a.setupIPsec(context.Background())
	if len(ch.conns) != 0 {
		t.Errorf("XFRMInterface tunnel loaded without its interface")
	}
	if st := tunnelStatusOf(t, c, "vpn"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
		t.Errorf("status = %+v", st)
	}
}

func TestIPsecOverlappingRemoteSelectorsAreRejectedInBothModes(t *testing.T) {
	for _, mode := range []wirekubev1alpha1.IPsecDataplane{wirekubev1alpha1.IPsecDataplanePolicy, wirekubev1alpha1.IPsecDataplaneXFRMInterface} {
		t.Run(string(mode), func(t *testing.T) {
			a, ch, _, c := ipsecFixture(t, "gw-a", func(g *wirekubev1alpha1.WireKubeGateway) {
				g.Spec.IPsec[0].Dataplane = mode
				second := tunnelSpec("vpn2", "203.0.113.11", "vpn-psk")
				second.Dataplane = mode
				second.RemoteTrafficSelectors = []string{"10.77.0.0/16"}
				g.Spec.IPsec = append(g.Spec.IPsec, second)
			})
			a.setupIPsec(context.Background())
			if ch.conns[testKey] == nil || ch.conns["site/vpn2"] != nil {
				t.Fatalf("want only the first of two overlapping tunnels, got %v", ch.conns)
			}
			if st := tunnelStatusOf(t, c, "vpn2"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
				t.Errorf("overlapping tunnel status = %+v", st)
			}
		})
	}
}

func TestIPsecRejectsSecondKeyForSameRemoteIdentity(t *testing.T) {
	other := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "other-psk", Namespace: "wirekube-system"},
		Data: map[string][]byte{"psk": []byte("different")}}
	a, ch, _, c := ipsecFixture(t, "gw-a", func(g *wirekubev1alpha1.WireKubeGateway) {
		second := tunnelSpec("vpn2", "203.0.113.10", "other-psk")
		second.RemoteTrafficSelectors = []string{"10.77.2.0/24"}
		g.Spec.IPsec = append(g.Spec.IPsec, second)
	}, other)
	a.setupIPsec(context.Background())
	if ch.conns[testKey] == nil || ch.conns["site/vpn2"] != nil {
		t.Fatalf("want only the first tunnel loaded, got %v", ch.conns)
	}
	if st := tunnelStatusOf(t, c, "vpn2"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
		t.Errorf("conflicting tunnel status = %+v", st)
	}
}

func TestIPsecFailedConnectionLoadUnloadsItsKey(t *testing.T) {
	a, ch, _, _ := ipsecFixture(t, "gw-a", nil)
	ch.loadConnErr = errTest("vici load-conn: invalid proposal")
	a.setupIPsec(context.Background())
	if len(ch.shared) != 0 {
		t.Errorf("key left in charon after its connection failed to load: %v", ch.shared)
	}
}

func TestIPsecRestartedStandbyCleansLeftoversOnFirstSync(t *testing.T) {
	a, ch, dp, _ := ipsecFixture(t, "gw-b", nil)
	a.EnableIPsec(ch, nil)
	a.ipsec.dataplane = dp
	leftover := ipsec.InterfaceName(ipsec.DeriveInterfaceID(testKey))
	dp.ifaces[leftover] = ipsec.DeriveInterfaceID(testKey)
	dp.routes = map[string][]string{leftover: {"10.77.1.0/24"}}
	dp.rule = true

	a.setupIPsec(context.Background())
	if len(dp.ifaces) != 0 || len(dp.routes) != 0 || dp.rule {
		t.Fatalf("first sync after restart kept leftovers: %+v", dp)
	}
	dp.rule = true
	a.setupIPsec(context.Background())
	if !dp.rule {
		t.Errorf("idle sync touched the dataplane again")
	}
}

func TestIPsecDisabledAgentRemovesLeftoversOnceAndKeepsTheGuard(t *testing.T) {
	removes := 0
	var guard []ipsec.SelectorPair
	guardCalls := 0
	origRemove, origGuard := removeTunnelState, syncDisabledGuard
	removeTunnelState = func() error { removes++; return nil }
	syncDisabledGuard = func(p []ipsec.SelectorPair) error { guardCalls++; guard = p; return nil }
	defer func() { removeTunnelState, syncDisabledGuard = origRemove, origGuard }()

	a, _, _, c := ipsecFixture(t, "gw-a", nil)
	a.ipsec = nil
	a.setupIPsec(context.Background())
	a.setupIPsec(context.Background())
	if removes != 1 {
		t.Errorf("tunnel state removed %d times; want once per process", removes)
	}
	want := ipsec.SelectorPair{Local: "198.18.0.0/16", Remote: "10.77.1.0/24"}
	if len(guard) != 1 || guard[0] != want {
		t.Fatalf("guard = %v; want the tunnel's pair kept", guard)
	}

	// Without tunnels the guard is cleared once, then left alone.
	gw := getGateway(t, c)
	gw.Spec.IPsec = nil
	if err := c.Update(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	calls := guardCalls
	a.setupIPsec(context.Background())
	if len(guard) != 0 || guardCalls != calls {
		t.Errorf("guard=%v calls %d->%d; want cleared once, then left alone", guard, calls, guardCalls)
	}
}

func TestIPsecTeardownIsRetriedUntilCharonConfirms(t *testing.T) {
	a, ch, _, _ := ipsecFixture(t, "gw-b", nil)
	ch.conns[testKey] = &ipsec.Tunnel{Name: testKey}
	a.ipsec.active = true

	ch.listErr = errTest("vici: connection refused")
	a.setupIPsec(context.Background())
	if !a.ipsec.active {
		t.Fatalf("teardown abandoned while charon was unreachable")
	}
	ch.listErr = nil
	ch.unloadErr = errTest("vici unload-conn: timeout")
	a.setupIPsec(context.Background())
	if !a.ipsec.active {
		t.Fatalf("teardown abandoned after a failed unload")
	}
	ch.unloadErr = nil
	a.setupIPsec(context.Background())
	if ch.conns[testKey] != nil || a.ipsec.active {
		t.Fatalf("teardown not completed once charon recovered: conns=%v active=%v", ch.conns, a.ipsec.active)
	}
}

type failingGetClient struct {
	client.Client
	fail func(obj client.Object) bool
}

func (f failingGetClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if f.fail(obj) {
		return errTest("etcdserver: request timed out")
	}
	return f.Client.Get(ctx, key, obj, opts...)
}

func TestIPsecTransientAPIErrorsLeaveTheTunnelAlone(t *testing.T) {
	cases := map[string]func(client.Object) bool{
		"peer":   func(o client.Object) bool { _, ok := o.(*wirekubev1alpha1.WireKubePeer); return ok },
		"secret": func(o client.Object) bool { _, ok := o.(*corev1.Secret); return ok },
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			a, ch, dp, c := ipsecFixture(t, "gw-a", nil)
			ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
			a.setupIPsec(context.Background())
			if ch.conns[testKey] == nil {
				t.Fatalf("setup failed")
			}
			a.client = failingGetClient{Client: c, fail: fail}
			a.setupIPsec(context.Background())
			if ch.conns[testKey] == nil || len(ch.unloads) != 0 || len(dp.ifaces) != 1 {
				t.Errorf("transient %s error tore the tunnel down: conns=%v unloads=%v ifaces=%v", name, ch.conns, ch.unloads, dp.ifaces)
			}
		})
	}
}

func TestIPsecPendingWhenNoPeerIsElected(t *testing.T) {
	a, _, _, c := ipsecFixture(t, "gw-b", func(g *wirekubev1alpha1.WireKubeGateway) {
		g.Spec.PeerRefs = []string{"gone-a", "gone-b"}
		g.Status = wirekubev1alpha1.WireKubeGatewayStatus{Ready: true,
			IPsec: []wirekubev1alpha1.GatewayIPsecTunnelStatus{{Name: "vpn", Phase: wirekubev1alpha1.IPsecTunnelPhaseEstablished}}}
	})
	a.setupIPsec(context.Background())
	st := tunnelStatusOf(t, c, "vpn")
	if st.Phase != wirekubev1alpha1.IPsecTunnelPhasePending || st.Message == "" || getGateway(t, c).Status.Ready {
		t.Errorf("status = %+v ready=%v", st, getGateway(t, c).Status.Ready)
	}
}

func TestIPsecGuardCoversElectedTunnelsInEveryState(t *testing.T) {
	want := ipsec.SelectorPair{Local: "198.18.0.0/16", Remote: "10.77.1.0/24"}
	a, _, dp, c := ipsecFixture(t, "gw-a", nil)
	dp.noXFRMI = true
	a.setupIPsec(context.Background())
	if len(dp.guard) != 1 || dp.guard[0] != want {
		t.Fatalf("established policy-mode tunnel not guarded: %v", dp.guard)
	}
	if err := c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "vpn-psk", Namespace: "wirekube-system"}}); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	if len(dp.guard) != 1 || dp.guard[0] != want {
		t.Fatalf("failed tunnel not guarded: %v", dp.guard)
	}
	if err := c.Delete(context.Background(), &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"}}); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	if len(dp.guard) != 0 {
		t.Fatalf("guard kept after the tunnel moved away: %v", dp.guard)
	}
}

func TestIPsecReinitiatesALoadedTunnelWithoutAnIKESA(t *testing.T) {
	a, ch, _, _ := ipsecFixture(t, "gw-a", nil)
	a.setupIPsec(context.Background())
	if len(ch.initiated) != 0 {
		t.Fatalf("initiated in the sync that loaded the connection: %v", ch.initiated)
	}
	a.setupIPsec(context.Background())
	if len(ch.initiated) != 1 || ch.initiated[0] != testKey {
		t.Fatalf("tunnel without an IKE_SA not initiated: %v", ch.initiated)
	}
	ch.sa = ipsec.SAState{IKEState: "CONNECTING"}
	a.setupIPsec(context.Background())
	if len(ch.initiated) != 1 {
		t.Errorf("initiated again while an IKE_SA was connecting: %v", ch.initiated)
	}
}

func TestGatewayTransientPeerErrorDoesNotMoveRoutes(t *testing.T) {
	a, _, _, c := ipsecFixture(t, "gw-b", nil)
	a.client = failingGetClient{Client: c, fail: func(o client.Object) bool {
		p, ok := o.(*wirekubev1alpha1.WireKubePeer)
		return ok && p != nil && (p.Name == "" || p.Name == "gw-a")
	}}
	a.gwRetainedRulesChecked = true
	if err := a.setupGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := &wirekubev1alpha1.WireKubePeer{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "gw-b"}, b)
	if len(b.Spec.AllowedIPs) != 1 {
		t.Errorf("standby peer advertised gateway routes on a partial view: %v", b.Spec.AllowedIPs)
	}
}

func TestGatewayWithTunnelsIsNotReadyWithoutIPsec(t *testing.T) {
	a, _, _, c := ipsecFixture(t, "gw-a", nil)
	a.ipsec = nil
	a.updateGatewayStatus(context.Background(), getGateway(t, c), "gw-a")
	if gw := getGateway(t, c); gw.Status.Ready || gw.Status.ActivePeer != "gw-a" ||
		len(gw.Status.IPsec) != 1 || gw.Status.IPsec[0].Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
		t.Errorf("status = %+v", gw.Status)
	}
	// A gateway without tunnels is ready once elected.
	plain := getGateway(t, c)
	plain.Spec.IPsec = nil
	if err := c.Update(context.Background(), plain); err != nil {
		t.Fatal(err)
	}
	a.updateGatewayStatus(context.Background(), getGateway(t, c), "gw-a")
	if !getGateway(t, c).Status.Ready {
		t.Errorf("plain gateway not ready once elected")
	}
}

func redundantPair(mode wirekubev1alpha1.IPsecDataplane) func(*wirekubev1alpha1.WireKubeGateway) {
	return func(g *wirekubev1alpha1.WireKubeGateway) {
		g.Spec.IPsec[0].Dataplane = mode
		second := tunnelSpec("vpn2", "203.0.113.11", "vpn-psk")
		second.Dataplane = mode
		g.Spec.IPsec = append(g.Spec.IPsec, second)
	}
}

func TestIPsecRedundantTunnelsRouteIntoOneCarrierAndFailOver(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", redundantPair(wirekubev1alpha1.IPsecDataplaneXFRMInterface))
	first := ipsec.InterfaceName(ipsec.DeriveInterfaceID(testKey))
	second := ipsec.InterfaceName(ipsec.DeriveInterfaceID("site/vpn2"))

	a.setupIPsec(context.Background())
	if ch.conns[testKey] == nil || ch.conns["site/vpn2"] == nil {
		t.Fatalf("both redundant tunnels must be loaded: %v", ch.conns)
	}
	if len(dp.routes) != 1 || dp.routes[first] == nil {
		t.Fatalf("routes = %v; want only the first tunnel to carry", dp.routes)
	}

	// vpn loses its SA while vpn2 is up: the routes move to vpn2.
	ch.saByKey = map[string]ipsec.SAState{
		testKey:     {IKEState: "CONNECTING"},
		"site/vpn2": {IKEState: "ESTABLISHED", InstalledChildSAs: 1},
	}
	a.setupIPsec(context.Background())
	a.setupIPsec(context.Background())
	if len(dp.routes) != 1 || dp.routes[second] == nil {
		t.Fatalf("routes = %v; want the established standby to carry", dp.routes)
	}
	if st := tunnelStatusOf(t, c, "vpn2"); !st.Carrier || tunnelStatusOf(t, c, "vpn").Carrier {
		t.Errorf("carrier flags: vpn=%v vpn2=%v", tunnelStatusOf(t, c, "vpn").Carrier, st.Carrier)
	}
	gw := getGateway(t, c)
	if !gw.Status.Ready || gw.Status.IPsecSummary != "1/2 Established" {
		t.Errorf("ready=%v summary=%q", gw.Status.Ready, gw.Status.IPsecSummary)
	}

	ch.saByKey = nil
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	a.setupIPsec(context.Background())
	a.setupIPsec(context.Background())
	if dp.routes[first] == nil {
		t.Errorf("routes = %v; want the preferred tunnel back", dp.routes)
	}
	if got := getGateway(t, c).Status.IPsecSummary; got != "2/2 Established" {
		t.Errorf("summary = %q", got)
	}
}

func TestIPsecRedundantTunnelsNeedXFRMInterfaces(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", redundantPair(wirekubev1alpha1.IPsecDataplanePolicy))
	a.setupIPsec(context.Background())
	if ch.conns[testKey] == nil || ch.conns["site/vpn2"] != nil {
		t.Fatalf("policy mode must keep only the first redundant tunnel: %v", ch.conns)
	}
	if st := tunnelStatusOf(t, c, "vpn2"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError || st.Message == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestIPsecSettingChangeReplacesTheConnection(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	a.setupIPsec(context.Background())
	old := ch.conns[testKey].ConnName()

	gw := getGateway(t, c)
	gw.Spec.IPsec[0].ESP.Proposals = []string{"aes128gcm16-modp2048"}
	if err := c.Update(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	tu := ch.conns[testKey]
	if tu == nil || tu.ConnName() == old || ch.loads != 2 {
		t.Fatalf("connection not reloaded under a new name: %+v loads=%d", tu, ch.loads)
	}
	if len(ch.unloads) != 1 || ch.unloads[0] != testKey {
		t.Errorf("old connection not unloaded (its SAs keep the old settings): %v", ch.unloads)
	}
	if !ch.shared[testKey] {
		t.Errorf("key missing after the replacement")
	}
}

func TestIPsecConnectingTunnelExplainsTheFailure(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	a.ipsec.failures = &ipsec.FailureWatcher{}
	a.setupIPsec(context.Background())
	conn := ch.conns[testKey].ConnName()

	ev := vici.NewMessage()
	_ = ev.Set("ikesa-name", conn)
	_ = ev.Set("msg", "received AUTHENTICATION_FAILED notify error")
	a.ipsec.failures.Observe(ev, time.Now())
	a.setupIPsec(context.Background())
	st := tunnelStatusOf(t, c, "vpn")
	if st.Phase != wirekubev1alpha1.IPsecTunnelPhaseConnecting || !strings.Contains(st.Message, "pre-shared key") || !strings.Contains(st.Message, "AUTHENTICATION_FAILED") {
		t.Fatalf("status = %+v", st)
	}

	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	a.setupIPsec(context.Background())
	if st := tunnelStatusOf(t, c, "vpn"); st.Message != "" {
		t.Errorf("message kept after the tunnel came up: %q", st.Message)
	}
}

func TestIPsecMetricsFollowTheTunnels(t *testing.T) {
	ipsecTunnelEstablished.Reset()
	ipsecTunnelChildSAs.Reset()
	ipsecTunnelCarrier.Reset()
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 2}
	a.setupIPsec(context.Background())
	if got := testutil.ToFloat64(ipsecTunnelChildSAs.WithLabelValues("site", "vpn")); got != 2 {
		t.Fatalf("child SA gauge = %v", got)
	}
	if got := testutil.ToFloat64(ipsecTunnelEstablished.WithLabelValues("site", "vpn")); got != 1 {
		t.Fatalf("established gauge = %v", got)
	}

	if err := c.Delete(context.Background(), &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"}}); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	if n := testutil.CollectAndCount(ipsecTunnelEstablished); n != 0 {
		t.Errorf("%d tunnel series left after the tunnel moved away", n)
	}
}

func TestIPsecKeyChangeReconnectsWithoutLeakingIntoTheName(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	a.setupIPsec(context.Background())
	name := ch.conns[testKey].ConnName()

	secret := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "wirekube-system", Name: "vpn-psk"}, secret); err != nil {
		t.Fatal(err)
	}
	secret.Data["psk"] = []byte("rotated")
	if err := c.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	tu := ch.conns[testKey]
	if tu == nil || tu.PreSharedKey != "rotated" || ch.loads != 2 || len(ch.unloads) != 1 {
		t.Fatalf("key change not applied by reconnecting: %+v loads=%d unloads=%v", tu, ch.loads, ch.unloads)
	}
	if tu.ConnName() != name {
		t.Errorf("connection name %s -> %s: it must not depend on the key", name, tu.ConnName())
	}
	a.setupIPsec(context.Background())
	if ch.loads != 2 {
		t.Errorf("reloaded again without a change: %d loads", ch.loads)
	}
}

func TestIPsecRestartedAgentReloadsKeysButKeepsTheSAs(t *testing.T) {
	a, ch, _, _ := ipsecFixture(t, "gw-a", nil)
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	a.setupIPsec(context.Background())
	delete(ch.shared, testKey)

	// Simulate a new agent process: charon keeps the connection.
	a.ipsec.keys = map[string][sha256.Size]byte{}
	a.setupIPsec(context.Background())
	if ch.loads != 1 || len(ch.unloads) != 0 {
		t.Errorf("restart renegotiated the tunnel: loads=%d unloads=%v", ch.loads, ch.unloads)
	}
	if !ch.shared[testKey] {
		t.Errorf("key not reloaded after the restart")
	}
}

func TestIPsecDoesNotTryXFRMInterfacesWhenTheKernelRulesThemOut(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", nil)
	dp.blocker = "the kernel was booted with ipv6.disable=1, so xfrm_interface cannot load"
	a.setupIPsec(context.Background())
	if dp.ensures != 0 {
		t.Fatalf("tried to create %d XFRM interfaces on a kernel that rules them out", dp.ensures)
	}
	if tu := ch.conns[testKey]; tu == nil || tu.RouteBased {
		t.Fatalf("Auto tunnel not loaded policy-based: %+v", tu)
	}

	gw := getGateway(t, c)
	gw.Spec.IPsec[0].Dataplane = wirekubev1alpha1.IPsecDataplaneXFRMInterface
	if err := c.Update(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	a.setupIPsec(context.Background())
	st := tunnelStatusOf(t, c, "vpn")
	if dp.ensures != 0 || st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError || !strings.Contains(st.Message, "ipv6.disable=1") {
		t.Errorf("explicit XFRMInterface: ensures=%d status=%+v", dp.ensures, st)
	}
}

func TestIPsecTunnelWithoutAGuardIsAnErrorButStaysLoaded(t *testing.T) {
	a, ch, dp, c := ipsecFixture(t, "gw-a", nil)
	ch.sa = ipsec.SAState{IKEState: "ESTABLISHED", InstalledChildSAs: 1}
	dp.guardErr = errTest("iptables: Couldn't load match `policy'")
	a.setupIPsec(context.Background())

	if ch.conns[testKey] == nil {
		t.Fatalf("connection unloaded; an SA still encrypts the traffic the routes pull here")
	}
	st := tunnelStatusOf(t, c, "vpn")
	if st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError || !strings.Contains(st.Message, "plaintext guard") || getGateway(t, c).Status.Ready {
		t.Fatalf("status = %+v ready=%v", st, getGateway(t, c).Status.Ready)
	}

	dp.guardErr = nil
	a.setupIPsec(context.Background())
	if st := tunnelStatusOf(t, c, "vpn"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseEstablished || !getGateway(t, c).Status.Ready {
		t.Errorf("not recovered once the guard installed: %+v", st)
	}
}

func TestIPsecReplacementWaitsForThePreviousConnectionToUnload(t *testing.T) {
	a, ch, _, c := ipsecFixture(t, "gw-a", nil)
	a.setupIPsec(context.Background())
	old := ch.conns[testKey].ConnName()

	gw := getGateway(t, c)
	gw.Spec.IPsec[0].DPD.DelaySeconds = 10
	if err := c.Update(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	ch.unloadErr = errTest("vici unload-conn: timeout")
	a.setupIPsec(context.Background())
	if tu := ch.conns[testKey]; tu == nil || tu.ConnName() != old || ch.loads != 1 {
		t.Fatalf("replacement loaded while the old connection was still in charon: %+v loads=%d", tu, ch.loads)
	}
	if st := tunnelStatusOf(t, c, "vpn"); st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
		t.Errorf("status = %+v", st)
	}

	ch.unloadErr = nil
	a.setupIPsec(context.Background())
	if tu := ch.conns[testKey]; tu == nil || tu.ConnName() == old || ch.loads != 2 {
		t.Fatalf("replacement not loaded once the old connection unloaded: %+v loads=%d", tu, ch.loads)
	}
}
