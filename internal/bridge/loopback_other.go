//go:build !linux

package bridge

// EnsureLoopback is a no-op where the bridge does not run in a network
// namespace of its own.
func EnsureLoopback() {}
