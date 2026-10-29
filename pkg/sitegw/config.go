package sitegw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

// Config is what a standalone site gateway terminates: the tunnels of one
// connection. It is read from a file, so the gateway needs no Kubernetes
// credentials.
type Config struct {
	// Name groups the tunnels; it prefixes their charon connection names.
	Name string `json:"name"`
	// ConnectionUID identifies the connection this gateway serves. It is
	// echoed in the status snapshot so a reader can tell a stale gateway
	// from the current one.
	ConnectionUID string `json:"connectionUID,omitempty"`
	// LocalTrafficSelectors default every tunnel's local selectors, for
	// example the networks of the VPC behind the gateway.
	LocalTrafficSelectors []string `json:"localTrafficSelectors,omitempty"`
	// LocalID defaults every tunnel's local IKE identity, usually the public
	// address the remote gateway is configured with.
	LocalID string `json:"localID,omitempty"`
	// RouteSource is the source address of routes into XFRM interfaces:
	// the gateway's address on the local network.
	RouteSource string `json:"routeSource,omitempty"`
	// Tunnels are the connection's tunnels. The pre-shared key of each is
	// read from the file preSharedKeyRef.key (default "psk") in the key
	// directory; preSharedKeyRef.name is not used.
	Tunnels []wirekubev1alpha1.GatewayIPsecTunnel `json:"tunnels"`
}

// LoadConfig reads a config file and returns it with a hash of its bytes.
// Unknown fields are refused, so a typo does not silently drop a setting.
func LoadConfig(path string) (*Config, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	cfg := &Config{}
	if err := dec.Decode(cfg); err != nil {
		return nil, "", fmt.Errorf("parsing %s: %w", path, err)
	}
	if cfg.Name == "" {
		return nil, "", fmt.Errorf("%s: name is empty", path)
	}
	seen := map[string]bool{}
	for _, t := range cfg.Tunnels {
		if t.Name == "" {
			return nil, "", fmt.Errorf("%s: a tunnel has no name", path)
		}
		if seen[t.Name] {
			return nil, "", fmt.Errorf("%s: tunnel %s is listed twice", path, t.Name)
		}
		seen[t.Name] = true
	}
	sum := sha256.Sum256(b)
	return cfg, hex.EncodeToString(sum[:]), nil
}

// Plans resolves the config's tunnels, reading each pre-shared key from
// keyDir. A tunnel that cannot be resolved keeps its Err, so its status says
// why; the returned plans have passed Validate.
func (c *Config) Plans(keyDir string) []*Plan {
	plans := make([]*Plan, 0, len(c.Tunnels))
	for i := range c.Tunnels {
		s := &c.Tunnels[i]
		p := &Plan{Group: c.Name, Name: s.Name, Index: i, Dataplane: s.Dataplane}
		p.Tunnel = ipsec.FromTunnelSpec(c.Name, s, c.LocalTrafficSelectors, nil, c.LocalID)
		psk, err := readKey(keyDir, s.PreSharedKeyRef.Key)
		switch {
		case err != nil:
			p.Err = err
		default:
			p.Tunnel.PreSharedKey = psk
			p.Err = specChecks(s)
			if p.Err == nil {
				p.Err = p.Tunnel.Validate()
			}
		}
		plans = append(plans, p)
	}
	Validate(plans)
	return plans
}

var remoteAddress = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9.:]*[A-Za-z0-9])?$`)

// specChecks refuses the two values that neither Validate nor charon would
// catch: a wildcard remote address and an interface ID that wraps in uint32.
func specChecks(s *wirekubev1alpha1.GatewayIPsecTunnel) error {
	if len(s.RemoteAddress) > 253 || !remoteAddress.MatchString(s.RemoteAddress) {
		return fmt.Errorf("remoteAddress %q is not an address or host name", s.RemoteAddress)
	}
	if s.InterfaceID < 0 || s.InterfaceID > 4294967294 {
		return fmt.Errorf("interfaceID %d is outside 0-4294967294", s.InterfaceID)
	}
	return nil
}

// RefuseOwnAddresses fails tunnels whose local selectors cover one of the
// gateway's own uplink addresses: the IPsec policies and the guard would
// then also take the gateway's replies to the probes and readers of its
// status.
func RefuseOwnAddresses(plans []*Plan, own []netip.Addr) {
	for _, p := range plans {
		if p.Err != nil || p.Tunnel == nil {
			continue
		}
		for _, c := range p.Tunnel.LocalTS {
			pfx, err := netip.ParsePrefix(c)
			if err != nil {
				continue
			}
			for _, a := range own {
				if pfx.Contains(a) {
					p.Err = fmt.Errorf("local traffic selector %s covers the gateway's own uplink address %s; its replies would go into the tunnel", c, a)
				}
			}
		}
	}
}

func readKey(dir, key string) (string, error) {
	if key == "" {
		key = ipsec.DefaultPreSharedKeyID
	}
	if key != filepath.Base(key) || strings.HasPrefix(key, ".") {
		return "", fmt.Errorf("pre-shared key name %q is not a plain file name", key)
	}
	b, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		return "", fmt.Errorf("reading pre-shared key %q: %w", key, err)
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" {
		return "", fmt.Errorf("pre-shared key %q is empty", key)
	}
	return v, nil
}
