// gateway is the WireKube gateway process.
// It runs as a privileged pod on a VPN node and bridges
// non-VPN node traffic into the WireGuard mesh via iptables NAT.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/wirekube/wirekube/pkg/gateway"
)

func main() {
	gw, err := gateway.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize gateway: %v\n", err)
		os.Exit(1)
	}

	if err := gw.Setup(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set up gateway rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("gateway: iptables rules installed, routing non-VPN traffic into mesh")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	fmt.Println("gateway: shutting down, removing iptables rules")
	if err := gw.Teardown(); err != nil {
		fmt.Fprintf(os.Stderr, "teardown error: %v\n", err)
	}
}
