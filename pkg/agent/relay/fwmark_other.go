//go:build !linux

package relay

import "syscall"

// dialControl is a no-op on non-Linux platforms.
func dialControl(network, address string, c syscall.RawConn) error {
	return nil
}
