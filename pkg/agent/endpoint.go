// Package agent contains the WireKube node agent logic.
package agent

import (
	"context"
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
	Endpoint       string
	Method         DiscoveryMethod
	NATType        nat.NATType
	PortPrediction *nat.PortPrediction
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
	result, detectedNATType := discoverViaSTUN(ctx, listenPort, stunServers)
	if result != nil {
		return result, nil
	}

	// 4. AWS EC2 Instance Metadata Service
	if ep := getAWSPublicIP(listenPort); ep != "" {
		return &EndpointResult{Endpoint: ep, Method: MethodAWSMetadata, NATType: detectedNATType}, nil
	}

	// 5. UPnP / NAT-PMP port forwarding
	upnpCtx, upnpCancel := context.WithTimeout(ctx, 10*time.Second)
	defer upnpCancel()
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

const AnnotationEndpoint = "wirekube.io/endpoint"

// discoverViaSTUN attempts STUN-based endpoint discovery and NAT type detection.
// Tries the WireGuard listen port first; if unavailable (interface already running),
// retries on an ephemeral port for NAT type detection only.
// Returns the endpoint result (nil if STUN failed entirely) and the detected NAT type.
func discoverViaSTUN(ctx context.Context, listenPort int, stunServers []string) (*EndpointResult, nat.NATType) {
	stunCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if sr, err := nat.DiscoverPublicEndpointWithNATType(stunCtx, listenPort, stunServers); err == nil {
		return buildSTUNResult(sr, listenPort, false), sr.NATType
	}

	// Listen port may be held by an existing WireGuard interface (restart
	// preservation). Retry on an ephemeral port — NAT type detection only
	// needs to compare mapped ports across STUN servers.
	probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer probeCancel()
	sr, err := nat.DiscoverPublicEndpointWithNATType(probeCtx, 0, stunServers)
	if err != nil {
		return nil, nat.NATUnknown
	}
	fmt.Printf("[endpoint] STUN on listen port failed; NAT type detected via ephemeral port: %s\n", sr.NATType)
	return buildSTUNResult(sr, listenPort, true), sr.NATType
}

// buildSTUNResult converts a raw STUN result into an EndpointResult.
//
// useListenPort=false (bound to WG listen port): for cone NAT the mapped port
// equals the WG port, so the STUN endpoint is used as-is. For symmetric NAT
// the mapped port is unstable and gets replaced with listenPort.
//
// useListenPort=true (bound to ephemeral port): the mapped port reflects the
// ephemeral source, not WG. Always substitute listenPort.
func buildSTUNResult(sr *nat.STUNResult, listenPort int, useListenPort bool) *EndpointResult {
	ep := sr.Endpoint
	if useListenPort || sr.NATType == nat.NATSymmetric {
		host, _, err := net.SplitHostPort(sr.Endpoint)
		if err != nil {
			return nil
		}
		ep = fmt.Sprintf("%s:%d", host, listenPort)
	}
	return &EndpointResult{
		Endpoint:       ep,
		Method:         MethodSTUN,
		NATType:        sr.NATType,
		PortPrediction: sr.PortPrediction,
	}
}
