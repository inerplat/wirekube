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

// DiscoverPublicEndpoint queries STUN servers to discover the public IP:port
// for the given local UDP port. Returns the endpoint as "ip:port".
func DiscoverPublicEndpoint(ctx context.Context, localPort int, stunServers []string) (string, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	// Bind a local UDP socket on the given port
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return "", fmt.Errorf("binding UDP port %d: %w", localPort, err)
	}
	defer conn.Close()

	var lastErr error
	for _, server := range stunServers {
		endpoint, err := querySTUN(ctx, conn, server)
		if err != nil {
			lastErr = err
			continue
		}
		return endpoint, nil
	}
	return "", fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
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
