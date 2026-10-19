//go:build darwin

package connect

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// DefaultInterfaceName lets the kernel pick the next free utun unit; macOS
// only accepts utun names for this kind of interface.
const DefaultInterfaceName = "utun"

const (
	ifconfigPath = "/sbin/ifconfig"
	routePath    = "/sbin/route"
	resolverDir  = "/etc/resolver"
)

// Supported reports whether this process can run a connect session: creating
// a utun interface and routing through it takes root.
func Supported() error {
	if unix.Geteuid() == 0 {
		return nil
	}
	return errors.New("connect needs root to create the tunnel interface; rerun it with sudo")
}

type darwinHost struct {
	name          string
	pid           int
	addr          netip.Prefix
	routes        map[netip.Prefix]bool
	resolverFiles []string
}

func newHostNetwork(name string) (hostNetwork, error) {
	for _, path := range staleResolverFiles(resolverDir, processAlive) {
		_ = os.Remove(path)
	}
	return &darwinHost{name: name, pid: os.Getpid(), routes: map[netip.Prefix]bool{}}, nil
}

func (h *darwinHost) SetAddress(p netip.Prefix) error {
	if h.addr == p {
		return nil
	}
	if err := run(ifconfigPath, ifconfigAddArgs(h.name, p)...); err != nil {
		return fmt.Errorf("assign %s to %s: %w", p, h.name, err)
	}
	// A reissued peer can come back with a different address; the old one
	// would otherwise linger as a second address on the interface.
	if h.addr.IsValid() {
		if err := run(ifconfigPath, ifconfigDelArgs(h.name, h.addr)...); err != nil {
			return fmt.Errorf("remove previous address %s: %w", h.addr, err)
		}
	}
	h.addr = p
	if err := run(ifconfigPath, h.name, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", h.name, err)
	}
	return nil
}

func (h *darwinHost) SyncRoutes(routes []netip.Prefix, _ netip.Addr) ([]string, error) {
	var warnings []string
	want := make(map[netip.Prefix]bool, len(routes))
	for _, p := range routes {
		want[p] = true
		if h.routes[p] {
			continue
		}
		err := run(routePath, routeArgs("add", p, h.name)...)
		if err != nil && strings.Contains(err.Error(), "File exists") {
			warnings = append(warnings, fmt.Sprintf("%s is already routed on this host; leaving that route in place, so it does not go through the tunnel", p))
			continue
		}
		if err != nil {
			return warnings, fmt.Errorf("route %s via %s: %w", p, h.name, err)
		}
		h.routes[p] = true
	}
	for p := range h.routes {
		if want[p] {
			continue
		}
		err := run(routePath, routeArgs("delete", p, h.name)...)
		if err != nil && !strings.Contains(err.Error(), "not in table") {
			return warnings, fmt.Errorf("remove route %s: %w", p, err)
		}
		delete(h.routes, p)
	}
	return warnings, nil
}

// SetDNS writes /etc/resolver files, which macOS watches, for the cluster domain
// and the search domains. They outlive a killed process, so each records its
// owner's pid for the next session to clear out.
func (h *darwinHost) SetDNS(cfg DNSConfig) error {
	domainFile := filepath.Join(resolverDir, cfg.Domain)
	if err := claimResolverFile(domainFile, renderDomainResolver(cfg, h.pid, h.name), h.pid, processAlive); err != nil {
		return err
	}
	h.resolverFiles = append(h.resolverFiles, domainFile)
	if len(cfg.Search) == 0 {
		return nil
	}
	searchFile := filepath.Join(resolverDir, searchResolverName(h.name))
	if err := claimResolverFile(searchFile, renderSearchResolver(cfg, h.pid, h.name), h.pid, processAlive); err != nil {
		return err
	}
	h.resolverFiles = append(h.resolverFiles, searchFile)
	return nil
}

// Close removes the resolver files. Routes and addresses need no undoing:
// they disappear with the utun interface when the device closes.
func (h *darwinHost) Close() error {
	var errs []error
	for _, path := range h.resolverFiles {
		if err := releaseResolverFile(path, h.pid); err != nil {
			errs = append(errs, err)
		}
	}
	h.resolverFiles = nil
	return errors.Join(errs...)
}

func searchResolverName(ifName string) string { return "search.wirekube-connect-" + ifName }

func processAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

func run(path string, args ...string) error {
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", filepath.Base(path), strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
