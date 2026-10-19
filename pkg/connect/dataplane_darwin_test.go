//go:build darwin

package connect

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inerplat/wirekube/pkg/wireguard"
)

// TestDarwinDataplanePair brings up two real utun dataplanes peered over
// loopback and checks the address, routes and resolver files each installs
// and removes. It needs root; CI runs it under sudo on a macOS runner.
func TestDarwinDataplanePair(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	kpA, _ := wireguard.GenerateKeyPair()
	kpB, _ := wireguard.GenerateKeyPair()
	a := openDarwinTestDataplane(t, kpA.Private)
	b := openDarwinTestDataplane(t, kpB.Private)

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
	portA := darwinListenOn(t, a, 51901)
	portB := darwinListenOn(t, b, 51902)
	if _, err := b.Apply(cfgB, portA); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(cfgA, portB); err != nil {
		t.Fatal(err)
	}

	ifc := mustRun(t, "/sbin/ifconfig", a.Name())
	if !strings.Contains(ifc, "inet 10.199.1.1 --> 10.199.1.1") || !strings.Contains(ifc, "mtu 1248") || !strings.Contains(ifc, "UP") {
		t.Fatalf("interface state:\n%s", ifc)
	}
	for _, dst := range []string{"10.198.0.1", "10.199.2.9"} {
		if got := routeInterface(t, dst); got != a.Name() {
			t.Fatalf("route to %s leaves via %q, want %s", dst, got, a.Name())
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for a.LastHandshake().IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("no handshake between the two dataplanes")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A narrower status drops the stale route, and a new address replaces
	// the old one.
	cfgA.Routes = cfgA.Routes[:1]
	cfgA.Address = netip.MustParsePrefix("10.199.1.2/32")
	if _, err := a.Apply(cfgA, portB); err != nil {
		t.Fatal(err)
	}
	if got := routeInterface(t, "10.198.0.1"); got == a.Name() {
		t.Fatal("stale route still points into the tunnel")
	}
	ifc = mustRun(t, "/sbin/ifconfig", a.Name())
	if strings.Contains(ifc, "10.199.1.1 ") || !strings.Contains(ifc, "inet 10.199.1.2 --> 10.199.1.2") {
		t.Fatalf("addresses after readdressing:\n%s", ifc)
	}

	// DNS, on a domain nothing else uses.
	dns := DNSConfig{
		Server: netip.MustParseAddr("10.199.2.53"),
		Domain: "wkc-test.invalid",
		Search: []string{"ns.svc.wkc-test.invalid"},
	}
	if err := a.SetDNS(dns); err != nil {
		t.Fatal(err)
	}
	domainFile := filepath.Join(resolverDir, dns.Domain)
	searchFile := filepath.Join(resolverDir, searchResolverName(a.Name()))
	deadline = time.Now().Add(10 * time.Second)
	for !strings.Contains(mustRun(t, "/usr/sbin/scutil", "--dns"), "domain   : wkc-test.invalid") {
		if time.Now().After(deadline) {
			t.Fatalf("resolver for %s never showed up in scutil --dns", dns.Domain)
		}
		time.Sleep(200 * time.Millisecond)
	}

	name := a.Name()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{domainFile, searchFile} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s survived Close", f)
		}
	}
	if err := exec.Command("/sbin/ifconfig", name).Run(); err == nil {
		t.Fatalf("%s survived Close", name)
	}
}

func openDarwinTestDataplane(t *testing.T, key [32]byte) Dataplane {
	t.Helper()
	dp, err := OpenDataplane(DefaultInterfaceName, 1248, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	return dp
}

func darwinListenOn(t *testing.T, dp Dataplane, port uint16) netip.AddrPort {
	t.Helper()
	if err := dp.(*wgDataplane).dev.IpcSet("listen_port=" + strconv.Itoa(int(port)) + "\n"); err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

// routeInterface asks the kernel which interface a packet to dst would use.
func routeInterface(t *testing.T, dst string) string {
	t.Helper()
	out, _ := exec.Command("/sbin/route", "-n", "get", dst).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func mustRun(t *testing.T, path string, args ...string) string {
	t.Helper()
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", path, args, err, out)
	}
	return string(out)
}
