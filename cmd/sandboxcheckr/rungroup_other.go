//go:build !unix

package main

import (
	"os"
	"os/exec"
	"time"
)

// Windows has no process groups and os.Process can only be killed, not
// signalled, so a bounded run stops the runner shell and whatever the job
// object still holds; there is no tree to address as one.

func isolateRunGroup(cmd *exec.Cmd) {}

func inRunGroup(cmd *exec.Cmd) bool { return false }

func signalRun(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(sig)
}

// stopRun ends a run whose deadline passed, escalating to a kill after grace if
// the run has not gone away on its own.
func stopRun(cmd *exec.Cmd, grace time.Duration, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	select {
	case <-done:
		return
	case <-time.After(grace):
	}
	select {
	case <-done:
	default:
		_ = cmd.Process.Kill()
	}
}
