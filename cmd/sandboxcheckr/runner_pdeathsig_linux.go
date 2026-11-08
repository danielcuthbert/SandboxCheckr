//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// armRunnerPdeathsig makes the runner shell die with this process. Without it
// a SIGKILLed run leaves the runner, the proxy and the sandbox orphaned.
func armRunnerPdeathsig(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
