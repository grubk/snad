//go:build windows

package snadbox

import (
	"net"
	"syscall"
)

// enableMulticastLoopback re-enables IP_MULTICAST_LOOP on conn, which
// net.ListenMulticastUDP disables by default. Without this, two snad
// instances running on the same machine (as opposed to two separate devices
// on the LAN) can never discover each other: the OS only loops a host's own
// multicast sends back to sockets on that same host when this option is on.
// Real cross-device discovery is unaffected either way, since loopback only
// governs local delivery back to the sending host. Best-effort: if the
// underlying fd can't be reached or the option can't be set, discovery still
// works for genuinely separate devices, so errors are ignored.
func enableMulticastLoopback(conn *net.UDPConn) {
	sc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = sc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
	})
}
