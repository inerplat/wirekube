package connect

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBSDCommandArgs(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.12.7/32")
	v6 := netip.MustParsePrefix("fd00::7/128")
	for _, tc := range []struct {
		got, want []string
	}{
		{ifconfigAddArgs("utun5", v4), []string{"utun5", "inet", "100.64.12.7/32", "100.64.12.7", "alias"}},
		{ifconfigDelArgs("utun5", v4), []string{"utun5", "inet", "100.64.12.7", "-alias"}},
		{ifconfigAddArgs("utun5", v6), []string{"utun5", "inet6", "fd00::7/128", "alias"}},
		{ifconfigDelArgs("utun5", v6), []string{"utun5", "inet6", "fd00::7", "-alias"}},
		{routeArgs("add", netip.MustParsePrefix("10.96.0.0/12"), "utun5"), []string{"-q", "-n", "add", "-inet", "10.96.0.0/12", "-interface", "utun5"}},
		{routeArgs("delete", netip.MustParsePrefix("fd00::/64"), "utun5"), []string{"-q", "-n", "delete", "-inet6", "fd00::/64", "-interface", "utun5"}},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestResolverFiles(t *testing.T) {
	cfg := DNSConfig{
		Server: netip.MustParseAddr("10.96.0.10"),
		Domain: "cluster.local",
		Search: []string{"default.svc.cluster.local", "svc.cluster.local"},
	}
	domain := renderDomainResolver(cfg, 42, "utun5")
	if !strings.HasSuffix(domain, "\nnameserver 10.96.0.10\n") {
		t.Fatalf("domain resolver:\n%s", domain)
	}
	search := renderSearchResolver(cfg, 42, "utun5")
	if !strings.HasSuffix(search, "\nsearch default.svc.cluster.local svc.cluster.local\n") {
		t.Fatalf("search resolver:\n%s", search)
	}
	if pid, ok := resolverOwner(domain); !ok || pid != 42 {
		t.Fatalf("owner = %d %v", pid, ok)
	}
	if _, ok := resolverOwner("nameserver 1.1.1.1\n"); ok {
		t.Fatal("a foreign resolver file was claimed as ours")
	}
}

func TestResolverFileOwnership(t *testing.T) {
	dir := t.TempDir()
	alive := map[int]bool{1: true, 2: true}
	isAlive := func(pid int) bool { return alive[pid] }
	path := filepath.Join(dir, "cluster.local")
	cfg := DNSConfig{Server: netip.MustParseAddr("10.96.0.10"), Domain: "cluster.local"}

	// A file someone else wrote is never touched.
	foreign := filepath.Join(dir, "corp.example")
	if err := os.WriteFile(foreign, []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := claimResolverFile(foreign, renderDomainResolver(cfg, 1, "utun5"), 1, isAlive); err == nil {
		t.Fatal("claimed a foreign resolver file")
	}

	if err := claimResolverFile(path, renderDomainResolver(cfg, 1, "utun5"), 1, isAlive); err != nil {
		t.Fatal(err)
	}
	// A second live session cannot take it, and cannot remove it.
	if err := claimResolverFile(path, renderDomainResolver(cfg, 2, "utun6"), 2, isAlive); err == nil || !strings.Contains(err.Error(), "pid 1") {
		t.Fatalf("second session claim = %v", err)
	}
	if err := releaseResolverFile(path, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("another session's release removed the file")
	}

	// Once the owner is dead its file is stale and can be taken over.
	alive[1] = false
	if got := staleResolverFiles(dir, isAlive); len(got) != 1 || got[0] != path {
		t.Fatalf("stale = %v", got)
	}
	if err := claimResolverFile(path, renderDomainResolver(cfg, 2, "utun6"), 2, isAlive); err != nil {
		t.Fatal(err)
	}
	if err := releaseResolverFile(path, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("owner's release left the file behind")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign file disappeared")
	}
}
