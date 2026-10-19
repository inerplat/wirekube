//go:build !linux && !darwin

package connect

import (
	"fmt"
	"runtime"
)

// DefaultInterfaceName is the tunnel interface connect asks for.
const DefaultInterfaceName = "wkconnect0"

// Supported reports whether this platform can run a connect session.
func Supported() error {
	return fmt.Errorf("wirekubectl connect is not supported on %s yet", runtime.GOOS)
}

func newHostNetwork(string) (hostNetwork, error) { return nil, Supported() }
