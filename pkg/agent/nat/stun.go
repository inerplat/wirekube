// Package nat provides NAT traversal utilities for WireKube agents.
package nat

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/pion/stun/v3"
)

var defaultSTUNServers = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

// NATType describes the NAT mapping behavior detected via STUN.
type NATType string

const (
	NATUnknown            NATType = ""
	NATCone               NATType = "cone"
	NATPortRestrictedCone NATType = "port-restricted-cone"
	NATSymmetric          NATType = "symmetric"
)

// PortPrediction describes the NAT's port allocation pattern observed via STUN.
type PortPrediction struct {
	BasePort    int
	Increment   int
	Jitter      int
	SamplePorts []int
}

// GenerateCandidates produces a list of predicted ports spread around the base.
// For sequential NATs the list fans out from the predicted next port.
// For unpredictable NATs it covers a wide range.
func (pp PortPrediction) GenerateCandidates(n int) []int {
	if n <= 0 {
		return nil
	}
	ports := make([]int, 0, n)

	if pp.Increment != 0 && pp.Jitter <= abs(pp.Increment)*2 {
		// Sequential allocation: fan out from predicted next port
		nextPort := pp.BasePort + pp.Increment
		for i := 0; i < n; i++ {
			p := nextPort + pp.Increment*i
			if p > 0 && p < 65536 {
				ports = append(ports, p)
			}
		}
	} else {
		// Random/unpredictable allocation: scan a wide range around the base
		start := pp.BasePort - n/2
		if start < 1024 {
			start = 1024
		}
		for i := 0; i < n; i++ {
			p := start + i
			if p > 0 && p < 65536 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// STUNResult holds the outcome of a STUN-based endpoint discovery,
// including NAT type detection and port prediction data.
type STUNResult struct {
	Endpoint       string
	NATType        NATType
	PortPrediction *PortPrediction
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
//
// Queries all available STUN servers (minimum 2) to:
//  1. Detect NAT type by comparing mapped ports.
//  2. Build a port prediction model for birthday attack traversal.
func DiscoverPublicEndpointWithNATType(ctx context.Context, localPort int, stunServers []string) (*STUNResult, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("binding UDP port %d: %w", localPort, err)
	}
	defer conn.Close()

	type stunResponse struct {
		endpoint string
		ip       string
		port     int
	}
	var results []stunResponse
	var lastErr error

	// Query ALL available servers (not just 2) for better port prediction.
	for _, server := range stunServers {
		endpoint, err := querySTUN(ctx, conn, server)
		if err != nil {
			lastErr = err
			continue
		}
		ip, portStr, _ := net.SplitHostPort(endpoint)
		port, _ := strconv.Atoi(portStr)
		results = append(results, stunResponse{endpoint: endpoint, ip: ip, port: port})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
	}

	if len(results) == 1 {
		log.Printf("[stun] warning: only 1 STUN server responded — cannot detect Symmetric NAT (need 2+ servers)\n")
		return &STUNResult{Endpoint: results[0].endpoint, NATType: NATUnknown}, nil
	}

	// Collect all observed ports for port prediction.
	samplePorts := make([]int, len(results))
	for i, r := range results {
		samplePorts[i] = r.port
	}

	// Determine NAT type and build port prediction.
	allSame := true
	for i := 1; i < len(results); i++ {
		if results[i].port != results[0].port {
			allSame = false
			break
		}
	}

	if allSame {
		return &STUNResult{
			Endpoint: results[0].endpoint,
			NATType:  NATCone,
		}, nil
	}

	// Symmetric NAT detected — build port prediction model.
	pp := buildPortPrediction(samplePorts)
	log.Printf("[stun] symmetric NAT detected: ports %v (increment=%d, jitter=%d)\n",
		samplePorts, pp.Increment, pp.Jitter)

	return &STUNResult{
		Endpoint:       results[0].endpoint,
		NATType:        NATSymmetric,
		PortPrediction: &pp,
	}, nil
}

// buildPortPrediction analyzes a sequence of STUN-observed ports to determine
// the NAT's port allocation pattern.
func buildPortPrediction(ports []int) PortPrediction {
	pp := PortPrediction{
		BasePort:    ports[len(ports)-1],
		SamplePorts: ports,
	}

	if len(ports) < 2 {
		return pp
	}

	deltas := make([]int, 0, len(ports)-1)
	for i := 1; i < len(ports); i++ {
		deltas = append(deltas, ports[i]-ports[i-1])
	}

	sum := 0
	for _, d := range deltas {
		sum += d
	}
	avgIncrement := sum / len(deltas)
	pp.Increment = avgIncrement

	maxJitter := 0
	for _, d := range deltas {
		j := abs(d - avgIncrement)
		if j > maxJitter {
			maxJitter = j
		}
	}
	pp.Jitter = maxJitter

	return pp
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
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck

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

// NATProbeFunc sends a UDP probe from a different source port to the given
// endpoint. Used by DetectPortRestriction to request the relay to probe us.
type NATProbeFunc func(ip net.IP, port int) error

// DetectPortRestriction checks whether a cone NAT is port-restricted using a
// dual-probe technique that distinguishes NAT restriction from firewall blocking.
//
// The relay sends TWO probes:
//  1. Verification probe from the relay's bound UDP port (same port we opened
//     the NAT for) — tests basic reachability.
//  2. Test probe from a random ephemeral port — tests port restriction.
//
// Decision matrix:
//   - Both received   → cone (address-restricted or full cone)
//   - Only verify     → port-restricted cone
//   - Neither         → firewall blocking, NOT NAT restriction → cone
func DetectPortRestriction(ctx context.Context, stunServers []string, relayIP string, probeFunc NATProbeFunc) (NATType, error) {
	if len(stunServers) == 0 {
		stunServers = defaultSTUNServers
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return NATCone, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	stunCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	endpoint, err := querySTUN(stunCtx, conn, stunServers[0])
	if err != nil {
		return NATCone, fmt.Errorf("STUN query for port-restriction test: %w", err)
	}

	ip, portStr, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(portStr)
	mappedIP := net.ParseIP(ip)
	if mappedIP == nil {
		return NATCone, fmt.Errorf("invalid STUN mapped IP: %s", ip)
	}

	// Send a packet to the relay IP on port 3478 (UDP) to open the NAT filter.
	// For address-restricted cone: opens for relay_ip:* (any port)
	// For port-restricted cone: opens for relay_ip:3478 only
	relayAddr, err := net.ResolveUDPAddr("udp4", relayIP+":3478")
	if err != nil {
		return NATCone, fmt.Errorf("resolve relay addr: %w", err)
	}
	conn.WriteToUDP([]byte("WIREKUBE_NAT_OPEN"), relayAddr)

	// Ask the relay to send dual probes (verify from :3478, test from random).
	if err := probeFunc(mappedIP, port); err != nil {
		return NATCone, fmt.Errorf("requesting NAT probe: %w", err)
	}

	// Wait for probe packets. Track which probes we received.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	buf := make([]byte, 256)
	gotVerify := false
	gotTest := false

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout
		}
		if !addr.IP.Equal(relayAddr.IP) {
			continue // ignore non-relay packets
		}

		payload := string(buf[:n])
		if payload == "WIREKUBE_NAT_VERIFY" && addr.Port == relayAddr.Port {
			gotVerify = true
			log.Printf("[stun] port-restriction test: received verify probe from %s\n", addr)
		} else if payload == "WIREKUBE_NAT_PROBE" && addr.Port != relayAddr.Port {
			gotTest = true
			log.Printf("[stun] port-restriction test: received test probe from %s\n", addr)
		}

		if gotVerify && gotTest {
			break // both received, no need to wait more
		}
	}

	if gotVerify && gotTest {
		log.Printf("[stun] port-restriction test: both probes received → cone (not port-restricted)\n")
		return NATCone, nil
	}
	if gotVerify && !gotTest {
		log.Printf("[stun] port-restriction test: only verify probe received → port-restricted-cone\n")
		return NATPortRestrictedCone, nil
	}
	// Neither probe received — the path itself is blocked (firewall), not NAT.
	log.Printf("[stun] port-restriction test: no probes received (firewall likely blocking) → keeping cone\n")
	return NATCone, nil
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
