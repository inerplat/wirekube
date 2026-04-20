//go:build !linux

package relay

import "syscall"

// listenControl is a no-op on non-Linux platforms.
func listenControl(network, address string, c syscall.RawConn) error {
	return nil
}
