//go:build darwin

package tty

// TIOCGWINSZ on the BSD-derived Darwin kernel.
const tiocgwinsz = 0x40087468
