package ipsec

import (
	"strings"
	"testing"

	"github.com/strongswan/govici/vici"
)

func validTunnel() *Tunnel {
	return &Tunnel{
		Name:          "vpn-a",
		RemoteAddress: "203.0.113.10",
		PreSharedKey:  "s3cret",
		LocalTS:       []string{"198.18.0.0/16"},
		RemoteTS:      []string{"10.77.1.0/24"},
		IKEVersion:    2,
		IKEProposals:  []string{DefaultIKEProposal},
		IKELifetime:   DefaultIKELifetime,
		ESPProposals:  []string{DefaultESPProposal},
		ESPLifetime:   DefaultESPLifetime,
		DPDDelay:      DefaultDPDDelay,
		DPDAction:     DefaultDPDAction,
		RouteBased:    true,
		InterfaceID:   DeriveInterfaceID("vpn-a"),
		MTU:           DefaultMTU,
	}
}

func TestDeriveInterfaceIDIsStableAndUsable(t *testing.T) {
	a, b := DeriveInterfaceID("vpn-a"), DeriveInterfaceID("vpn-a")
	if a != b {
		t.Fatalf("interface ID not stable: %d vs %d", a, b)
	}
	if a == 0 || a == 0xffffffff {
		t.Fatalf("derived a reserved interface ID %d", a)
	}
	if DeriveInterfaceID("vpn-b") == a {
		t.Fatalf("distinct names derived the same ID %d", a)
	}
	if n := InterfaceName(0xffffffff); len(n) > 15 {
		t.Fatalf("interface name %q exceeds IFNAMSIZ", n)
	}
}

func TestValidate(t *testing.T) {
	if err := validTunnel().Validate(); err != nil {
		t.Fatalf("valid tunnel rejected: %v", err)
	}
	cases := map[string]func(*Tunnel){
		"empty psk":        func(t *Tunnel) { t.PreSharedKey = "" },
		"no remote":        func(t *Tunnel) { t.RemoteAddress = "" },
		"no local ts":      func(t *Tunnel) { t.LocalTS = nil },
		"no remote ts":     func(t *Tunnel) { t.RemoteTS = nil },
		"bad cidr":         func(t *Tunnel) { t.RemoteTS = []string{"10.77.1.0/33"} },
		"overlap":          func(t *Tunnel) { t.RemoteTS = []string{"198.18.5.0/24"} },
		"ike version":      func(t *Tunnel) { t.IKEVersion = 3 },
		"reserved if_id 0": func(t *Tunnel) { t.InterfaceID = 0 },
		// Rejected before the dataplane mode is chosen.
		"reserved if_id max policy mode": func(t *Tunnel) { t.RouteBased = false; t.InterfaceID = 0xffffffff },
	}
	for name, mutate := range cases {
		tu := validTunnel()
		mutate(tu)
		if err := tu.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadConnMessageIsRouteBased(t *testing.T) {
	tu := validTunnel()
	msg, err := tu.LoadConnMessage()
	if err != nil {
		t.Fatal(err)
	}
	conn, ok := msg.Get(tu.ConnName()).(*vici.Message)
	if !ok {
		t.Fatalf("connection wk-vpn-a missing: %v", msg)
	}
	if got := conn.Get("version"); got != "2" {
		t.Errorf("version = %v", got)
	}
	if got := conn.Get("remote_addrs"); !equal(got, []string{"203.0.113.10"}) {
		t.Errorf("remote_addrs = %v", got)
	}
	if got := conn.Get("encap"); got != "no" {
		t.Errorf("encap = %v", got)
	}
	local := conn.Get("local").(*vici.Message)
	if local.Get("auth") != "psk" || local.Get("id") != nil {
		t.Errorf("local section = %v; want psk auth and no id when LocalID is empty", local)
	}
	remote := conn.Get("remote").(*vici.Message)
	if remote.Get("id") != "203.0.113.10" {
		t.Errorf("remote id = %v; want the remote address by default", remote.Get("id"))
	}
	child := conn.Get("children").(*vici.Message).Get(tu.ConnName()).(*vici.Message)
	ifID := child.Get("if_id_in")
	if ifID == nil || ifID != child.Get("if_id_out") {
		t.Errorf("if_id_in/out = %v/%v; both must bind the XFRM interface", ifID, child.Get("if_id_out"))
	}
	if !equal(child.Get("local_ts"), tu.LocalTS) || !equal(child.Get("remote_ts"), tu.RemoteTS) {
		t.Errorf("traffic selectors = %v / %v", child.Get("local_ts"), child.Get("remote_ts"))
	}
	if child.Get("start_action") != "start" || child.Get("close_action") != "start" {
		t.Errorf("child must self-start and restart on close: %v", child)
	}
}

func TestLoadConnMessageHonoursLocalIDAndEncap(t *testing.T) {
	tu := validTunnel()
	tu.LocalID = "198.51.100.7"
	tu.RemoteID = "vpn.example.net"
	tu.ForceEncap = true
	msg, err := tu.LoadConnMessage()
	if err != nil {
		t.Fatal(err)
	}
	conn := msg.Get(tu.ConnName()).(*vici.Message)
	if conn.Get("encap") != "yes" {
		t.Errorf("encap = %v", conn.Get("encap"))
	}
	if conn.Get("local").(*vici.Message).Get("id") != "198.51.100.7" {
		t.Errorf("local id not set")
	}
	if conn.Get("remote").(*vici.Message).Get("id") != "vpn.example.net" {
		t.Errorf("remote id not set")
	}

	shared, err := tu.LoadSharedMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !equal(shared.Get("owners"), []string{"vpn.example.net", "198.51.100.7"}) {
		t.Errorf("owners = %v", shared.Get("owners"))
	}
	if shared.Get("id") != tu.ConnName() || shared.Get("type") != "IKE" || shared.Get("data") != "s3cret" {
		t.Errorf("shared = %v", shared)
	}
}

func TestFingerprint(t *testing.T) {
	a, b := validTunnel(), validTunnel()
	a.LocalTS = []string{"198.18.0.0/16", "10.42.0.0/16"}
	b.LocalTS = []string{"10.42.0.0/16", "198.18.0.0/16"}
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("selector order changed the fingerprint")
	}
	b.PreSharedKey = "rotated"
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("the fingerprint, part of the logged connection name, depends on the pre-shared key")
	}
	b.DPDDelay = 10
	if a.Fingerprint() == b.Fingerprint() {
		t.Errorf("a setting change did not change the fingerprint")
	}
}

func TestParseSAsPrefersEstablishedAndCountsInstalledChildren(t *testing.T) {
	mk := func(state string, children map[string]string) *vici.Message {
		ike := vici.NewMessage()
		_ = ike.Set("state", state)
		cs := vici.NewMessage()
		for name, st := range children {
			c := vici.NewMessage()
			_ = c.Set("state", st)
			_ = cs.Set(name, c)
		}
		_ = ike.Set("child-sas", cs)
		m := vici.NewMessage()
		_ = m.Set("wk-vpn-a", ike)
		return m
	}
	got := parseSAs("wk-vpn-a", []*vici.Message{
		mk("ESTABLISHED", map[string]string{"wk-vpn-a-1": "INSTALLED", "wk-vpn-a-2": "REKEYING"}),
		mk("CONNECTING", nil),
	})
	if got.IKEState != "ESTABLISHED" || got.InstalledChildSAs != 1 {
		t.Fatalf("got %+v", got)
	}
	if got := parseSAs("wk-vpn-a", nil); got.IKEState != "" || got.InstalledChildSAs != 0 {
		t.Fatalf("empty list gave %+v", got)
	}
}

func TestOwnedNamesIgnoresForeignConnections(t *testing.T) {
	m1 := vici.NewMessage()
	_ = m1.Set("wk-site/vpn@0123abcd", vici.NewMessage())
	m2 := vici.NewMessage()
	_ = m2.Set("site-to-hq", vici.NewMessage())
	got := ownedNames([]*vici.Message{m1, m2})
	if strings.Join(got, ",") != "wk-site/vpn@0123abcd" {
		t.Fatalf("got %v", got)
	}
}

func TestConnNameFollowsTheSettings(t *testing.T) {
	a, b := validTunnel(), validTunnel()
	if a.ConnName() != b.ConnName() {
		t.Fatalf("same settings, different names: %s %s", a.ConnName(), b.ConnName())
	}
	b.ESPProposals = []string{"aes128gcm16-modp2048"}
	if a.ConnName() == b.ConnName() {
		t.Fatalf("changed proposals kept the name %s", a.ConnName())
	}
	for _, tu := range []*Tunnel{a, b} {
		if key, ok := KeyOfConn(tu.ConnName()); !ok || key != tu.Name {
			t.Errorf("KeyOfConn(%s) = %q, %v", tu.ConnName(), key, ok)
		}
	}
}

func equal(got any, want []string) bool {
	g, ok := got.([]string)
	if !ok || len(g) != len(want) {
		return false
	}
	for i := range g {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

func TestLoadConnMessagePolicyModeHasNoInterfaceID(t *testing.T) {
	tu := validTunnel()
	tu.RouteBased = false
	msg, err := tu.LoadConnMessage()
	if err != nil {
		t.Fatal(err)
	}
	child := msg.Get(tu.ConnName()).(*vici.Message).Get("children").(*vici.Message).Get(tu.ConnName()).(*vici.Message)
	if child.Get("if_id_in") != nil || child.Get("if_id_out") != nil {
		t.Errorf("policy-mode child carries if_id: %v", child)
	}
	a := validTunnel()
	if a.Fingerprint() == tu.Fingerprint() {
		t.Errorf("switching dataplane mode did not change the fingerprint")
	}
}
