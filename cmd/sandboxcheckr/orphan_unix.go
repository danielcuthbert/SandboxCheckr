//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// armRunnerPdeathsig makes the runner shell die with this process. Without it
// a SIGKILLed run leaves the runner, the proxy and the sandbox orphaned.
func armRunnerPdeathsig(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// stopOrphanedProxy terminates this run's egress proxy if the runner died
// before its trap could stop it — killed outright, say, rather than exiting
// through the trap. The proxy prints the exit summary when it shuts down, so
// stopping it here is what makes the summary appear after the child exits on
// every path, not only orderly ones.
//
// The runner records the proxy PID in a file inside the private runner
// directory, which is never granted to the sandbox, so the PID is the one the
// runner chose and nothing else. A recycled PID is still refused unless
// /proc confirms the process is this tool's proxy.
func stopOrphanedProxy(private string) {
	b, err := os.ReadFile(filepath.Join(private, ".proxy-pid"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	if !aliveProxy(pid) {
		return
	}
	fmt.Fprintln(os.Stderr, "── observed connection attempts ──")
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if !aliveProxy(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = p.Signal(syscall.SIGKILL)
}

// aliveProxy reports whether pid is alive and, where /proc exists, is actually
// this tool's proxy, so a recycled PID is never signalled.
func aliveProxy(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return true // no /proc (macOS): trust the runner's record
	}
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	return len(args) >= 2 && strings.HasSuffix(args[0], "sandboxcheckr") && args[1] == "proxy"
}
