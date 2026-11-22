//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// A bounded run needs to stop everything the program started, not just the
// shell that started it: the children are as confined as their parent, and a
// report printed while one of them is still writing is worth little. The runner
// shell goes into its own process group, which makes the whole tree addressable
// as one signal.

// isolateRunGroup puts the runner shell and everything it starts into their own
// process group. It is called only when a deadline is armed: without a deadline
// the run stays in the terminal's foreground group exactly as it always was.
func isolateRunGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// inRunGroup reports whether the run was put in its own group.
func inRunGroup(cmd *exec.Cmd) bool {
	return cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid
}

// signalRun forwards a signal the reader sent sandboxcheckr to the run itself.
// In its own group the program gets it directly; otherwise it goes to the
// runner shell, which is what happened before bounded runs existed.
func signalRun(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process == nil {
		return
	}
	if inRunGroup(cmd) {
		// The group is the run: the shell, the program, and every helper the
		// program started. Sending to the shell alone would orphan them.
		if err := syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal)); err == nil {
			return
		}
	}
	_ = cmd.Process.Signal(sig)
}

// stopRun ends a run whose deadline passed. SIGTERM first, so a program that
// gets to clean up leaves less behind; SIGKILL to the group after grace if it is
// still there. done is closed when the run has been waited for, which is the
// only reliable word that the group is finished: a leader the parent has not
// reaped yet still answers a signal probe, so waiting on the channel beats
// polling the process table.
func stopRun(cmd *exec.Cmd, grace time.Duration, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if inRunGroup(cmd) {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
	} else if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return
	}
	select {
	case <-done:
		return
	case <-time.After(grace):
	}
	if inRunGroup(cmd) {
		// The group may already be gone, in which case this is ESRCH and means
		// nothing. The window in which another process could have taken the
		// identifier is the grace period, and it opens only after the run has
		// been reaped, which is the case done just ruled out.
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	} else {
		_ = cmd.Process.Kill()
	}
}
