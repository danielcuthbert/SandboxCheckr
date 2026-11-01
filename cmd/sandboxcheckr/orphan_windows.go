//go:build windows

package main

// stopOrphanedProxy is a no-op on Windows: no proxied mechanism is implemented
// there, so no runner ever starts a proxy to clean up.
func stopOrphanedProxy(private string) {}
