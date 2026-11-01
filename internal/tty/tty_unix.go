//go:build darwin || linux

package tty

import (
	"os"
	"syscall"
	"unsafe"
)

// winsize mirrors struct winsize from <sys/ioctl.h>. Only Col is used.
type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// ioctlWidth asks the kernel for the window size via TIOCGWINSZ. The ioctl
// number differs by OS and is defined in the per-OS files alongside this one.
func ioctlWidth(f *os.File) int {
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(tiocgwinsz),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 || ws.Col == 0 {
		return 0
	}
	return int(ws.Col)
}
