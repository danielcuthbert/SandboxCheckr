//go:build linux

package bridge

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// ifreq mirrors struct ifreq far enough for SIOC[SG]IFFLAGS: IFNAMSIZ bytes of
// name, then the union whose first member is the 2-byte flags field. A struct
// rather than a byte slice so the flags sit at the alignment the kernel reads
// them at.
type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// linkUp brings one interface up. SIOCSIFFLAGS writes the whole flags word, so
// the current flags are read first and IFF_UP ORed into them: writing IFF_UP
// alone would clear IFF_RUNNING and whatever else the kernel had set.
func linkUp(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening a socket to bring up %s: %w", name, err)
	}
	defer syscall.Close(fd)
	var ifr ifreq
	copy(ifr.name[:], name)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return fmt.Errorf("reading the flags of %s: %w", name, errno)
	}
	if ifr.flags&syscall.IFF_UP != 0 {
		return nil
	}
	ifr.flags |= syscall.IFF_UP
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return fmt.Errorf("setting %s up: %w", name, errno)
	}
	return nil
}

// EnsureLoopback brings the loopback interface up when it is down, or says why
// it could not. A bridge that runs in its own network namespace (unshare
// --net, which the sandbox runner uses so the DNS relay can bind port 53
// unprivileged) starts with the interface down; nothing it binds is reachable
// until it is up, so a silent failure here turns into every connection in the
// sandbox failing with no explanation. Outside such a namespace the interface
// is already up and this is a no-op.
func EnsureLoopback() error {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("looking up the loopback interface: %w", err)
	}
	if iface.Flags&net.FlagUp != 0 {
		return nil
	}
	return linkUp("lo")
}
