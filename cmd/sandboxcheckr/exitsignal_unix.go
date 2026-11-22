//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// signalled reports whether the program was killed by a signal rather than
// exiting. It is how a sandbox that stops a program shows up in the exit
// status: dyld aborts a process it cannot load, and a confined helper that
// cannot reach its library segfaults rather than reporting a refusal.
func signalled(exitErr *exec.ExitError) bool {
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled()
}
