// Package nat provides NAT traversal utilities for WireKube agents.
package nat

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

var defaultSTUNServers = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun1.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

// NATType describes the NAT mapping behavior detected via STUN.
type NATType string

const (
	NATUnknown   NATType = ""
	NATCone      NATType = "cone"
	NATSymmetric NATType = "symmetric"
)

// STUNResult holds the outcome of a STUN-based endpoint discovery,
// including NAT type detection.
type STUNResult struct {
	Endpoint string
	NATType  NATType
}

// ErrSymmetricNAT is returned when Symmetric NAT is detected.
// The STUN-mapped port differs per destination, making direct P2P impossible.
var ErrSymmetricNAT = fmt.Errorf("symmetric NAT detected: STUN-mapped port varies per destination")

// DiscoverPublicEndpoint queries STUN servers to discover the public IP:port
// for the given local UDP port. It queries at least two servers from the same
// socket and compares mapped ports to detect Symmetric NAT (RFC 5780).
// Returns ErrSymmetricNAT if endpoint-dependent mapping is detected.
func DiscoverPublicEndpoint(ctx context.Context, localPort int, stunServers []string) (string, error) {
	result, err := DiscoverPublicEndpointWithNATType(ctx, localPort, stunServers)
	if err != nil {
		return "", err
	}
	if result.NATType == NATSymmetric {
		return "", ErrSymmetricNAT
	}
	return result.Endpoint, nil
}

// DiscoverPublicEndpointWithNATType is like DiscoverPublicEndpoint but returns
// the full STUNResult including detected NAT type instead of an error for
// Symmetric NAT. The caller can decide how to handle Symmetric NAT.
func DiscoverPublicEndpointWithNATType(ctx context.Context, localPort int, stunServers []string) (*STUNResult, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("binding UDP port %d: %w", localPort, err)
	}
	defer conn.Close()

	// Query multiple STUN servers from the same socket for NAT type detection.
	type stunResponse struct {
		endpoint string
		ip       string
		port     string
	}
	var results []stunResponse
	var lastErr error

	for _, server := range stunServers {
		endpoint, err := querySTUN(ctx, conn, server)
		if err != nil {
			lastErr = err
			continue
		}
		ip, port, _ := net.SplitHostPort(endpoint)
		results = append(results, stunResponse{endpoint: endpoint, ip: ip, port: port})
		if len(results) >= 2 {
			break
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
	}

	if len(results) == 1 {
		fmt.Printf("[stun] warning: only 1 STUN server responded — cannot detect Symmetric NAT (need 2+ servers)\n")
		return &STUNResult{Endpoint: results[0].endpoint, NATType: NATUnknown}, nil
	}

	// Compare mapped ports from two different STUN servers.
	// Same port → Endpoint-Independent Mapping (Cone NAT) → direct P2P possible.
	// Different port → Endpoint-Dependent Mapping (Symmetric NAT) → direct P2P impossible.
	if results[0].port != results[1].port {
		fmt.Printf("[stun] symmetric NAT detected: %s (server 1) vs %s (server 2)\n",
			results[0].endpoint, results[1].endpoint)
		return &STUNResult{Endpoint: results[0].endpoint, NATType: NATSymmetric}, nil
	}

	return &STUNResult{Endpoint: results[0].endpoint, NATType: NATCone}, nil
}

func querySTUN(ctx context.Context, conn *net.UDPConn, server string) (string, error) {
	// Parse stun: URI
	addr, err := resolveSTUNAddr(server)
	if err != nil {
		return "", err
	}

	// Set deadline
	deadline := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining < deadline {
			deadline = remaining
		}
	}
	if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		return "", err
	}
	defer conn.SetDeadline(time.Time{})

	// Build and send STUN Binding Request
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteToUDP(msg.Raw, addr); err != nil {
		return "", fmt.Errorf("sending STUN request: %w", err)
	}

	// Read response
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", fmt.Errorf("reading STUN response: %w", err)
	}

	// Parse response
	var resp stun.Message
	resp.Raw = buf[:n]
	if err := resp.Decode(); err != nil {
		return "", fmt.Errorf("decoding STUN response: %w", err)
	}

	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(&resp); err != nil {
		// Try MappedAddress as fallback
		var mappedAddr stun.MappedAddress
		if err2 := mappedAddr.GetFrom(&resp); err2 != nil {
			return "", fmt.Errorf("getting address from STUN response: %w", err)
		}
		return fmt.Sprintf("%s:%d", mappedAddr.IP, mappedAddr.Port), nil
	}

	return fmt.Sprintf("%s:%d", xorAddr.IP, xorAddr.Port), nil
}

func resolveSTUNAddr(server string) (*net.UDPAddr, error) {
	// Handle "stun:host:port" or "host:port" format
	host := server
	if len(host) > 5 && host[:5] == "stun:" {
		host = host[5:]
	}
	addr, err := net.ResolveUDPAddr("udp4", host)
	if err != nil {
		return nil, fmt.Errorf("resolving STUN server %s: %w", server, err)
	}
	return addr, nil
}
