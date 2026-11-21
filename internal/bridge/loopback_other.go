//go:build !linux

package bridge

// EnsureLoopback is a no-op where the bridge does not run in a network
// namespace of its own, so there is no interface to bring up. It returns an
// error for the same reason the Linux one does: the caller treats failure as
// fatal, and that call has to compile on every platform the binary builds for.
func EnsureLoopback() error { return nil }
