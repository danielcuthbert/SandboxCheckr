//go:build linux

package bridge

import (
	"net"
	"syscall"
	"unsafe"
)

// EnsureLoopback brings the loopback interface up when it is down. A bridge
// that runs in its own network namespace (unshare --net, which the sandbox
// runner uses so the DNS relay can bind port 53 unprivileged) starts with the
// interface down; nothing it binds is reachable until it is up. Outside such
// a namespace this is a no-op.
func EnsureLoopback() {
	iface, err := net.InterfaceByName("lo")
	if err != nil || iface.Flags&net.FlagUp != 0 {
		return
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	// struct ifreq: 16 bytes of name, then a union whose first member is the
	// 2-byte flags field. Setting IFF_UP is one ioctl.
	var ifr [40]byte
	copy(ifr[:16], "lo")
	ifr[16] = byte(syscall.IFF_UP)
	ifr[17] = byte(syscall.IFF_UP >> 8)
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0])))
}
