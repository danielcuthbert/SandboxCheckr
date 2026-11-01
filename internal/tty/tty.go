// Package tty detects terminal capabilities using only the standard library,
// matching the project's no-third-party-dependency rule.
//
// It answers two questions the renderer needs to adapt to its environment: is
// output going to an interactive terminal (so colour and the banner make
// sense), and how wide is it (so the layout fits rather than assuming 80).
package tty

import (
	"os"
	"strconv"
)

// IsTerminal reports whether f is an interactive terminal.
//
// It checks the character-device bit rather than issuing an ioctl, so it needs
// no per-OS code: a pipe or a regular file is not a character device, a console
// is. This is the same signal the standard library uses to decide whether a
// stream is a console.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Width returns the terminal width in columns, or 0 when it cannot be
// determined. It tries the kernel ioctl first, then falls back to the COLUMNS
// environment variable, which some CI shells export even when the ioctl is
// unavailable.
func Width(f *os.File) int {
	if w := ioctlWidth(f); w > 0 {
		return w
	}
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}
