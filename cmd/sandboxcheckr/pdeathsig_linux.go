//go:build linux

package main

import (
	"os"
	"syscall"
)

// armSelfPdeathsig arms PR_SET_PDEATHSIG for the proxy: when its parent (the
// runner shell) dies, the kernel SIGKILLs the proxy. This closes the case
// where a SIGKILLed `run` skips every deferred cleanup and leaves the proxy
// serving egress indefinitely. No-op if the parent already died first.
func armSelfPdeathsig() {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
		return
	}
	if os.Getppid() == 1 { // parent died between fork and prctl
		os.Exit(1)
	}
}
