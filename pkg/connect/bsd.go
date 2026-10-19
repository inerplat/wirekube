package connect

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The helpers below build the macOS host configuration. They carry no build
// constraint so their output can be tested on any platform; host_darwin.go
// is the only caller at run time.

func inetFamily(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

// ifconfigAddArgs assigns p to a point-to-point utun interface, as wg-quick
// does: an IPv4 utun address needs an explicit destination, itself.
func ifconfigAddArgs(ifName string, p netip.Prefix) []string {
	if p.Addr().Is4() {
		return []string{ifName, "inet", p.String(), p.Addr().String(), "alias"}
	}
	return []string{ifName, "inet6", p.String(), "alias"}
}

func ifconfigDelArgs(ifName string, p netip.Prefix) []string {
	if p.Addr().Is4() {
		return []string{ifName, "inet", p.Addr().String(), "-alias"}
	}
	return []string{ifName, "inet6", p.Addr().String(), "-alias"}
}

// routeArgs builds a route(8) invocation sending p out of ifName.
func routeArgs(op string, p netip.Prefix, ifName string) []string {
	return []string{"-q", "-n", op, inetFamily(p), p.String(), "-interface", ifName}
}

// resolverHeader marks an /etc/resolver file as written by a connect
// session, naming the process that owns it so a later session can tell a
// live session's file from one a crashed session left behind.
const resolverHeaderPrefix = "# wirekubectl connect pid="

func resolverHeader(pid int, ifName string) string {
	return fmt.Sprintf("%s%d interface=%s\n", resolverHeaderPrefix, pid, ifName)
}

// renderDomainResolver sends every name under cfg.Domain to cfg.Server.
func renderDomainResolver(cfg DNSConfig, pid int, ifName string) string {
	return resolverHeader(pid, ifName) + "nameserver " + cfg.Server.String() + "\n"
}

// renderSearchResolver contributes cfg.Search to the system search list.
// macOS merges "search" lines from /etc/resolver files into it.
func renderSearchResolver(cfg DNSConfig, pid int, ifName string) string {
	return resolverHeader(pid, ifName) + "search " + strings.Join(cfg.Search, " ") + "\n"
}

// resolverOwner returns the pid recorded in a file connect wrote.
func resolverOwner(content string) (int, bool) {
	line, _, _ := strings.Cut(content, "\n")
	rest, ok := strings.CutPrefix(line, resolverHeaderPrefix)
	if !ok {
		return 0, false
	}
	pidStr, _, _ := strings.Cut(rest, " ")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, false
	}
	return pid, true
}

// staleResolverFiles lists files in dir that a connect session wrote and
// whose process is gone. Unlike the tunnel interface and its routes, these
// files outlive a killed process.
func staleResolverFiles(dir string, alive func(pid int) bool) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var stale []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if pid, ok := resolverOwner(string(data)); ok && !alive(pid) {
			stale = append(stale, path)
		}
	}
	return stale
}

// claimResolverFile writes content to path unless another live session or
// something other than connect owns it. A file a dead session left behind is
// taken over.
func claimResolverFile(path, content string, self int, alive func(int) bool) error {
	if data, err := os.ReadFile(path); err == nil {
		pid, ours := resolverOwner(string(data))
		switch {
		case !ours:
			return fmt.Errorf("%s exists and was not written by connect; remove it or pass --dns=false", path)
		case pid != self && alive(pid):
			return fmt.Errorf("%s is held by another connect session (pid %d)", path, pid)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// releaseResolverFile removes path only while it still belongs to self.
func releaseResolverFile(path string, self int) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if pid, ok := resolverOwner(string(data)); !ok || pid != self {
		return nil
	}
	return os.Remove(path)
}
