// Package agent contains the WireKube node agent logic.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/wirekube/wirekube/pkg/agent/nat"
)

// DiscoveryMethod records how an endpoint was found.
type DiscoveryMethod string

const (
	MethodManual       DiscoveryMethod = "manual"
	MethodIPv6         DiscoveryMethod = "ipv6"
	MethodSTUN         DiscoveryMethod = "stun"
	MethodAWSMetadata  DiscoveryMethod = "aws-metadata"
	MethodUPnP         DiscoveryMethod = "upnp"
	MethodInternalIP   DiscoveryMethod = "internal-ip"
)

// EndpointResult holds a discovered endpoint and how it was found.
type EndpointResult struct {
	Endpoint string
	Method   DiscoveryMethod
	NATType  nat.NATType
}

// DiscoverEndpoint attempts to find the public WireGuard endpoint for this node.
// It tries methods in order: manual annotation, IPv6, STUN, AWS metadata, UPnP, internal IP.
func DiscoverEndpoint(ctx context.Context, node *corev1.Node, listenPort int, stunServers []string) (*EndpointResult, error) {
	// 1. Manual override via node annotation
	if ep, ok := node.Annotations[AnnotationEndpoint]; ok && ep != "" {
		return &EndpointResult{Endpoint: ep, Method: MethodManual}, nil
	}

	// 2. Public IPv6 address (no NAT, direct connectivity)
	if ep := getPublicIPv6Endpoint(node, listenPort); ep != "" {
		return &EndpointResult{Endpoint: ep, Method: MethodIPv6}, nil
	}

	// 3. STUN-based discovery with Symmetric NAT detection (RFC 5780).
	// Queries two STUN servers from the same socket; if mapped ports differ,
	// the node is behind Symmetric NAT and STUN endpoint is unusable for P2P.
	stunCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var detectedNATType nat.NATType
	if stunResult, err := nat.DiscoverPublicEndpointWithNATType(stunCtx, listenPort, stunServers); err == nil {
		detectedNATType = stunResult.NATType
		if stunResult.NATType == nat.NATSymmetric {
			// Symmetric NAT: mapped port is unreliable, but the public IP is still valid.
			// Use STUN-discovered IP with the configured listen port for the CRD endpoint.
			if host, _, err := net.SplitHostPort(stunResult.Endpoint); err == nil {
				ep := fmt.Sprintf("%s:%d", host, listenPort)
				fmt.Printf("[endpoint] symmetric NAT: using STUN public IP with listen port → %s\n", ep)
				return &EndpointResult{Endpoint: ep, Method: MethodSTUN, NATType: nat.NATSymmetric}, nil
			}
		}
		return &EndpointResult{Endpoint: stunResult.Endpoint, Method: MethodSTUN, NATType: stunResult.NATType}, nil
	}

	// 4. AWS EC2 Instance Metadata Service
	if ep := getAWSPublicIP(listenPort); ep != "" {
		return &EndpointResult{Endpoint: ep, Method: MethodAWSMetadata, NATType: detectedNATType}, nil
	}

	// 5. UPnP / NAT-PMP port forwarding
	upnpCtx, cancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel2()
	if res, err := nat.ForwardPortUPnP(upnpCtx, listenPort); err == nil {
		ep := fmt.Sprintf("%s:%d", res.ExternalIP, res.ExternalPort)
		return &EndpointResult{Endpoint: ep, Method: MethodUPnP, NATType: detectedNATType}, nil
	}

	// 6. Fallback: use ExternalIP from Node status
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeExternalIP {
			ep := fmt.Sprintf("%s:%d", addr.Address, listenPort)
			return &EndpointResult{Endpoint: ep, Method: MethodInternalIP, NATType: detectedNATType}, nil
		}
	}

	// 7. Last resort: InternalIP (same network only, but better than nothing)
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			ep := fmt.Sprintf("%s:%d", addr.Address, listenPort)
			return &EndpointResult{Endpoint: ep, Method: MethodInternalIP, NATType: detectedNATType}, nil
		}
	}

	return nil, fmt.Errorf("could not determine node endpoint by any method")
}

// getPublicIPv6Endpoint returns a public IPv6 endpoint if the node has a global IPv6 address.
func getPublicIPv6Endpoint(node *corev1.Node, port int) string {
	for _, addr := range node.Status.Addresses {
		ip := net.ParseIP(addr.Address)
		if ip == nil || ip.To4() != nil {
			continue // skip non-IPv6
		}
		if isPublicIPv6(ip) {
			return fmt.Sprintf("[%s]:%d", ip.String(), port)
		}
	}
	// Also check local interfaces for IPv6
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.To4() != nil || !isPublicIPv6(ip) {
				continue
			}
			return fmt.Sprintf("[%s]:%d", ip.String(), port)
		}
	}
	return ""
}

func isPublicIPv6(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// getAWSPublicIP queries the EC2 Instance Metadata Service for the public IP.
func getAWSPublicIP(port int) string {
	// Try IMDSv2 first
	token, err := imdsToken()
	if err != nil {
		return imdsv1PublicIP(port)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/public-ipv4", nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ip := string(body)
	if net.ParseIP(ip) == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func imdsToken() (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return "", fmt.Errorf("IMDSv2 token request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func imdsv1PublicIP(port int) string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/public-ipv4")
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ip := string(body)
	if net.ParseIP(ip) == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// Suppress unused import warning
var _ = json.Marshal

const AnnotationEndpoint = "wirekube.io/endpoint"
