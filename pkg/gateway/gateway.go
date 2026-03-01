// Package gateway implements the WireKube gateway process.
// The gateway runs as a privileged pod on a VPN node and bridges
// non-VPN nodes into the WireGuard mesh via iptables NAT.
package gateway

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Gateway manages iptables rules to route non-VPN node traffic into the mesh.
type Gateway struct {
	ifaceName   string
	routedCIDRs []string
	masquerade  bool
}

// New creates a new Gateway from environment variables.
// Expected env vars:
//   - WG_INTERFACE: WireGuard interface name (default: wg0)
//   - ROUTED_CIDRS: comma-separated list of non-VPN pod/node CIDRs
//   - MASQUERADE: "true" to enable SNAT (default: true)
func New() (*Gateway, error) {
	iface := os.Getenv("WG_INTERFACE")
	if iface == "" {
		iface = "wg0"
	}

	routedStr := os.Getenv("ROUTED_CIDRS")
	if routedStr == "" {
		return nil, fmt.Errorf("ROUTED_CIDRS env var is required")
	}
	cidrs := strings.Split(routedStr, ",")
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
	}

	masq := os.Getenv("MASQUERADE") != "false"

	return &Gateway{
		ifaceName:   iface,
		routedCIDRs: cidrs,
		masquerade:  masq,
	}, nil
}

// Setup installs the necessary iptables rules and enables IP forwarding.
func (g *Gateway) Setup() error {
	// Enable IP forwarding
	if err := enableIPForwarding(); err != nil {
		return err
	}

	for _, cidr := range g.routedCIDRs {
		cidr = strings.TrimSpace(cidr)
		// Accept forwarded packets from non-VPN nodes through wg0
		if err := iptables("-A", "FORWARD", "-i", g.ifaceName, "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := iptables("-A", "FORWARD", "-o", g.ifaceName, "-s", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}

		// MASQUERADE so mesh nodes see the gateway's mesh IP as source
		if g.masquerade {
			if err := iptables("-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", g.ifaceName, "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}
	return nil
}

// Teardown removes the iptables rules installed by Setup.
func (g *Gateway) Teardown() error {
	for _, cidr := range g.routedCIDRs {
		cidr = strings.TrimSpace(cidr)
		_ = iptables("-D", "FORWARD", "-i", g.ifaceName, "-d", cidr, "-j", "ACCEPT")
		_ = iptables("-D", "FORWARD", "-o", g.ifaceName, "-s", cidr, "-j", "ACCEPT")
		if g.masquerade {
			_ = iptables("-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", g.ifaceName, "-j", "MASQUERADE")
		}
	}
	return nil
}

func enableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func iptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
