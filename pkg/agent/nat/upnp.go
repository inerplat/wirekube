package nat

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

// UPnPForwardResult holds the result of a successful UPnP port forward.
type UPnPForwardResult struct {
	ExternalIP   string
	ExternalPort int
}

// ForwardPortUPnP attempts to open a port via UPnP/NAT-PMP on the local router.
// Returns the external IP and port if successful.
func ForwardPortUPnP(ctx context.Context, internalPort int) (*UPnPForwardResult, error) {
	// Try IGD v2 first (more modern)
	if res, err := tryIGDv2(ctx, internalPort); err == nil {
		return res, nil
	}
	// Fallback to IGD v1
	if res, err := tryIGDv1(ctx, internalPort); err == nil {
		return res, nil
	}
	return nil, fmt.Errorf("UPnP port forward failed: no compatible IGD found")
}

func tryIGDv2(ctx context.Context, port int) (*UPnPForwardResult, error) {
	clients, _, err := internetgateway2.NewWANIPConnection1Clients()
	if err != nil || len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv2 clients found")
	}

	client := clients[0]
	localIP, err := getLocalIP()
	if err != nil {
		return nil, err
	}

	leaseDuration := uint32(3600) // 1 hour; renew periodically
	if err := client.AddPortMappingCtx(ctx,
		"",               // remote host (empty = any)
		uint16(port),     // external port
		"UDP",
		uint16(port), // internal port
		localIP,
		true,
		"wirekube",
		leaseDuration,
	); err != nil {
		return nil, fmt.Errorf("IGDv2 AddPortMapping: %w", err)
	}

	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	return &UPnPForwardResult{ExternalIP: extIP, ExternalPort: port}, nil
}

func tryIGDv1(ctx context.Context, port int) (*UPnPForwardResult, error) {
	clients, _, err := internetgateway1.NewWANIPConnection1Clients()
	if err != nil || len(clients) == 0 {
		return nil, fmt.Errorf("no IGDv1 clients found")
	}

	client := clients[0]
	localIP, err := getLocalIP()
	if err != nil {
		return nil, err
	}

	if err := client.AddPortMappingCtx(ctx,
		"",
		uint16(port),
		"UDP",
		uint16(port),
		localIP,
		true,
		"wirekube",
		3600,
	); err != nil {
		return nil, fmt.Errorf("IGDv1 AddPortMapping: %w", err)
	}

	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	return &UPnPForwardResult{ExternalIP: extIP, ExternalPort: port}, nil
}

// getLocalIP returns the primary non-loopback IPv4 address.
func getLocalIP() (string, error) {
	conn, err := net.DialTimeout("udp4", "8.8.8.8:80", 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("detecting local IP: %w", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
