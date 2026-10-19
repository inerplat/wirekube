//go:build linux

package connect

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/inerplat/wirekube/pkg/wireguard"
)

// TestDataplanePair peers two real dataplanes over loopback and checks the host
// state each installs and removes. It needs root and /dev/net/tun.
func TestDataplanePair(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("needs /dev/net/tun")
	}
	kpA, _ := wireguard.GenerateKeyPair()
	kpB, _ := wireguard.GenerateKeyPair()

	a := openTestDataplane(t, "wkctest-a", kpA.Private)
	b := openTestDataplane(t, "wkctest-b", kpB.Private)

	cfgA := TunnelConfig{
		Address:       netip.MustParsePrefix("10.199.1.1/32"),
		MTU:           1248,
		PeerPublicKey: kpB.PublicKeyBase64(),
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.199.2.0/24"), netip.MustParsePrefix("10.198.0.0/16")},
	}
	cfgB := TunnelConfig{
		Address:       netip.MustParsePrefix("10.199.2.1/32"),
		MTU:           1248,
		PeerPublicKey: kpA.PublicKeyBase64(),
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.199.1.0/24")},
	}
	portA := listenOn(t, a, 51901)
	portB := listenOn(t, b, 51902)
	if _, err := b.Apply(cfgB, portA); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(cfgA, portB); err != nil {
		t.Fatal(err)
	}

	linkA, err := netlink.LinkByName("wkctest-a")
	if err != nil {
		t.Fatal(err)
	}
	if linkA.Attrs().MTU != 1248 || linkA.Attrs().Flags&(1<<0) == 0 {
		t.Fatalf("link mtu=%d flags=%v", linkA.Attrs().MTU, linkA.Attrs().Flags)
	}
	if got := linkRoutes(t, linkA); got != "10.198.0.0/16,10.199.2.0/24" {
		t.Fatalf("routes = %s", got)
	}

	deadline := time.Now().Add(10 * time.Second)
	for a.LastHandshake().IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("no handshake between the two dataplanes")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A narrower status drops the stale route.
	cfgA.Routes = cfgA.Routes[:1]
	if _, err := a.Apply(cfgA, portB); err != nil {
		t.Fatal(err)
	}
	if got := linkRoutes(t, linkA); got != "10.199.2.0/24" {
		t.Fatalf("routes after narrowing = %s", got)
	}

	// A reissued peer may come back on another address; only the new one
	// may remain.
	cfgA.Address = netip.MustParsePrefix("10.199.1.2/32")
	if _, err := a.Apply(cfgA, portB); err != nil {
		t.Fatal(err)
	}
	addrs, err := netlink.AddrList(linkA, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].IPNet.String() != "10.199.1.2/32" {
		t.Fatalf("addresses after readdressing = %v", addrs)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkByName("wkctest-a"); err == nil {
		t.Fatal("interface survived Close")
	}
}

func openTestDataplane(t *testing.T, name string, key [32]byte) Dataplane {
	t.Helper()
	dp, err := OpenDataplane(name, 1248, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	return dp
}

// listenOn pins the device's UDP port. wireguard-go reports a port of 0 when
// it cannot also open the IPv6 socket, as in an IPv6-less container, so the
// test fixes the port rather than reading it back.
func listenOn(t *testing.T, dp Dataplane, port uint16) netip.AddrPort {
	t.Helper()
	if err := dp.(*wgDataplane).dev.IpcSet("listen_port=" + strconv.Itoa(int(port)) + "\n"); err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func linkRoutes(t *testing.T, link netlink.Link) string {
	t.Helper()
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range routes {
		if r.Dst != nil && r.Protocol == 4 { // RTPROT_STATIC
			out = append(out, r.Dst.String())
		}
	}
	return strings.Join(out, ",")
}

// TestDataplaneLeavesExistingRoutesAlone pre-installs a route for one of the
// granted ranges, as another VPN might, and checks the session neither takes
// it over nor leaves the host without it after disconnecting.
func TestDataplaneLeavesExistingRoutesAlone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("needs /dev/net/tun")
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	_, taken, _ := net.ParseCIDR("10.197.0.0/16")
	existing := &netlink.Route{LinkIndex: lo.Attrs().Index, Dst: taken}
	if err := netlink.RouteAdd(existing); err != nil {
		t.Fatal(err)
	}
	defer netlink.RouteDel(existing)

	kp, _ := wireguard.GenerateKeyPair()
	peer, _ := wireguard.GenerateKeyPair()
	dp := openTestDataplane(t, "wkctest-c", kp.Private)
	cfg := TunnelConfig{
		Address:       netip.MustParsePrefix("10.199.3.1/32"),
		MTU:           1248,
		PeerPublicKey: peer.PublicKeyBase64(),
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.196.0.0/16"), netip.MustParsePrefix("10.197.0.0/16")},
	}
	warnings, err := dp.Apply(cfg, netip.MustParseAddrPort("127.0.0.1:9"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "10.197.0.0/16") {
		t.Fatalf("warnings = %q", warnings)
	}
	link, err := netlink.LinkByName("wkctest-c")
	if err != nil {
		t.Fatal(err)
	}
	if got := linkRoutes(t, link); got != "10.196.0.0/16" {
		t.Fatalf("tunnel routes = %s", got)
	}
	if err := dp.Close(); err != nil {
		t.Fatal(err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: taken}, netlink.RT_FILTER_DST)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].LinkIndex != lo.Attrs().Index {
		t.Fatalf("the pre-existing route did not survive the session: %+v", routes)
	}
}
