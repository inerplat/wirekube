package relay

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// wkFwMark is the WireKube fwmark (0x574B = "WK").
// The relay server sets this on its TCP listener so accepted connections
// bypass the WireKube routing table. Without this, reply packets to
// remote agents would be routed through the WG tunnel, creating a
// circular dependency.
const wkFwMark = 0x574B

// listenControl sets SO_MARK on the relay TCP listener socket.
// Accepted connections inherit the mark from the listening socket.
func listenControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, wkFwMark)
	})
	if err != nil {
		return err
	}
	return opErr
}
