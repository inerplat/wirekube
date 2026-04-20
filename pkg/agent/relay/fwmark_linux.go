package relay

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// wkFwMark is the WireKube fwmark (0x574B = "WK").
// TCP sockets marked with this value bypass the WireKube routing table
// and use the main table, preventing circular dependency when the relay
// TCP connection would otherwise be routed through the WG tunnel.
const wkFwMark = 0x574B

// dialControl sets SO_MARK on the relay TCP socket so it bypasses
// the WireKube routing table (table 22347).
func dialControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, wkFwMark)
	})
	if err != nil {
		return err
	}
	return opErr
}
