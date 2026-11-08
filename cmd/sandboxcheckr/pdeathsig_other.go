//go:build !linux

package main

// armSelfPdeathsig is a no-op where PR_SET_PDEATHSIG does not exist (macOS,
// Windows). The orphaned-proxy case there still relies on stopOrphanedProxy,
// which covers every path except a SIGKILLed run.
func armSelfPdeathsig() {}
