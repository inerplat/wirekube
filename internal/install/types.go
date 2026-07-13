package install

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var digestPattern = regexp.MustCompile(`@sha256:[a-fA-F0-9]{64}$`)

const (
	SchemaVersion       = "v1alpha1"
	FieldManager        = "wirekubectl.wirekube.io"
	InventoryName       = "wirekube-installation"
	InstallationIDLabel = "wirekube.io/installation-id"

	RelayNone         = "none"
	RelayLoadBalancer = "load-balancer"
	RelayNodePort     = "node-port"
	RelayExternal     = "external"

	RelayTransportTCP = "tcp"
	RelayTransportWSS = "wss"
)

type Options struct {
	Namespace          string
	Image              string
	Relay              string
	RelayEndpoint      string
	RelayUDPEndpoint   string
	RelayTransport     string
	RelayUDP           bool
	RelayUDPConfigured bool       `json:"-"`
	PreviousResources  []Resource `json:"-"`
	MeshCIDR           string
	NodeAddresses      string
	ExcludeCIDRs       []string
	Yes                bool
	DryRun             bool
	Adopt              bool
	Timeout            time.Duration
	Context            string
	ClusterServer      string
	WireKubeVersion    string
}

type Detection struct {
	KubernetesVersion string `json:"kubernetesVersion"`
	Provider          string `json:"provider"`
	CNI               string `json:"cni"`
}

type Resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Preserve   bool   `json:"preserve,omitempty"`
}

type Plan struct {
	SchemaVersion    string     `json:"schemaVersion"`
	Context          string     `json:"context"`
	ClusterServer    string     `json:"clusterServer"`
	Detection        Detection  `json:"detection"`
	WireKubeVersion  string     `json:"wireKubeVersion"`
	Image            string     `json:"image"`
	Namespace        string     `json:"namespace"`
	Relay            string     `json:"relay"`
	RelayEndpoint    string     `json:"relayEndpoint,omitempty"`
	RelayUDPEndpoint string     `json:"relayUDPEndpoint,omitempty"`
	RelayTransport   string     `json:"relayTransport"`
	RelayUDP         bool       `json:"relayUDP"`
	MeshCIDR         string     `json:"meshCIDR"`
	NodeAddresses    string     `json:"nodeAddresses"`
	Resources        []Resource `json:"resources"`
	Impact           []string   `json:"infrastructureImpact"`
	Warnings         []string   `json:"warnings,omitempty"`
}

type Inventory struct {
	SchemaVersion   string     `json:"schemaVersion"`
	InstallationID  string     `json:"installationID"`
	InstalledAt     time.Time  `json:"installedAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	WireKubeVersion string     `json:"wireKubeVersion"`
	Image           string     `json:"image"`
	Options         Options    `json:"options"`
	Resources       []Resource `json:"resources"`
}

type Result struct {
	SchemaVersion  string    `json:"schemaVersion"`
	Operation      string    `json:"operation"`
	InstallationID string    `json:"installationID,omitempty"`
	Ready          bool      `json:"ready"`
	Plan           Plan      `json:"plan"`
	CompletedAt    time.Time `json:"completedAt"`
}

func (o *Options) Normalize() error {
	if o.Namespace == "" {
		o.Namespace = "wirekube-system"
	}
	if o.MeshCIDR == "" {
		o.MeshCIDR = "auto"
	}
	if o.NodeAddresses == "" {
		o.NodeAddresses = "mesh-only"
	}
	if o.Relay == "" {
		if o.Yes {
			return fmt.Errorf("--relay must be specified when --yes is used")
		}
		o.Relay = RelayLoadBalancer
	}
	if o.RelayTransport == "" {
		o.RelayTransport = RelayTransportTCP
	}
	switch o.RelayTransport {
	case RelayTransportTCP, RelayTransportWSS:
	default:
		return fmt.Errorf("unsupported --relay-transport value %q", o.RelayTransport)
	}
	if o.Relay == RelayLoadBalancer && !o.RelayUDPConfigured {
		o.RelayUDP = true
	}
	switch o.Relay {
	case RelayNone:
		if o.RelayEndpoint != "" {
			return fmt.Errorf("--relay-endpoint is not valid with --relay=%s", o.Relay)
		}
		if o.RelayUDPEndpoint != "" {
			return fmt.Errorf("--relay-udp-endpoint is not valid with --relay=%s", o.Relay)
		}
		if o.RelayTransport != RelayTransportTCP {
			return fmt.Errorf("--relay-transport=%s is not valid with --relay=none", o.RelayTransport)
		}
	case RelayLoadBalancer:
		if o.RelayTransport == RelayTransportTCP {
			if o.RelayEndpoint != "" {
				return fmt.Errorf("--relay-endpoint is not valid with --relay=%s and --relay-transport=tcp", o.Relay)
			}
		} else if err := validateWSSEndpoint("--relay-endpoint", o.RelayEndpoint); err != nil {
			return err
		}
		if o.RelayUDPEndpoint != "" {
			return fmt.Errorf("--relay-udp-endpoint is not valid with --relay=%s", o.Relay)
		}
	case RelayNodePort, RelayExternal:
		if strings.TrimSpace(o.RelayEndpoint) == "" {
			return fmt.Errorf("--relay-endpoint is required with --relay=%s", o.Relay)
		}
		if o.RelayTransport == RelayTransportWSS {
			if err := validateWSSEndpoint("--relay-endpoint", o.RelayEndpoint); err != nil {
				return err
			}
		} else {
			if err := validateEndpoint("--relay-endpoint", o.RelayEndpoint); err != nil {
				return err
			}
			_, port, _ := net.SplitHostPort(o.RelayEndpoint)
			if o.Relay == RelayNodePort && port != "30478" {
				return fmt.Errorf("--relay=node-port with --relay-transport=tcp currently requires endpoint port 30478")
			}
		}
		if o.Relay == RelayNodePort {
			if o.RelayTransport == RelayTransportTCP && o.RelayUDPEndpoint != "" {
				return fmt.Errorf("--relay-udp-endpoint is derived from --relay-endpoint with --relay=node-port and --relay-transport=tcp")
			}
			if o.RelayTransport == RelayTransportWSS && o.RelayUDPEndpoint != "" {
				if !o.RelayUDP {
					return fmt.Errorf("--relay-udp-endpoint requires --relay-udp with --relay=node-port")
				}
				if err := validateEndpoint("--relay-udp-endpoint", o.RelayUDPEndpoint); err != nil {
					return err
				}
				_, port, _ := net.SplitHostPort(o.RelayUDPEndpoint)
				if port != "30479" {
					return fmt.Errorf("--relay=node-port with --relay-transport=wss currently requires UDP endpoint port 30479")
				}
			}
			if o.RelayTransport == RelayTransportWSS && o.RelayUDP && o.RelayUDPEndpoint == "" {
				return fmt.Errorf("--relay-udp-endpoint is required when --relay=node-port, --relay-transport=wss, and --relay-udp=true")
			}
		}
		if o.Relay == RelayExternal && o.RelayUDPEndpoint != "" {
			if err := validateEndpoint("--relay-udp-endpoint", o.RelayUDPEndpoint); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported relay mode %q", o.Relay)
	}
	if !digestPattern.MatchString(o.Image) {
		return fmt.Errorf("--image must be pinned by digest (IMAGE@sha256:DIGEST)")
	}
	if o.RelayUDP && o.Relay != RelayLoadBalancer && o.Relay != RelayNodePort {
		return fmt.Errorf("--relay-udp is supported only with load-balancer or node-port relay provisioning")
	}
	switch o.NodeAddresses {
	case "mesh-only", "internal-ip":
	default:
		return fmt.Errorf("unsupported --node-addresses value %q", o.NodeAddresses)
	}
	return nil
}

func validateEndpoint(flag, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", flag, value, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid %s %q: host is empty", flag, value)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid %s %q: port must be between 1 and 65535", flag, value)
	}
	return nil
}

func validateWSSEndpoint(flag, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", flag, value, err)
	}
	if parsed.Scheme != "wss" || parsed.Host == "" {
		return fmt.Errorf("invalid %s %q: expected wss://HOST/PATH", flag, value)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("invalid %s %q: user info and fragments are not supported", flag, value)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return fmt.Errorf("invalid %s %q: WebSocket path is required", flag, value)
	}
	return nil
}
