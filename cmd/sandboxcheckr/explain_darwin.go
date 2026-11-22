//go:build darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// kernelLogDenials asks the unified log what the sandbox refused during the run,
// from every process it confined. The lines are written by sandboxd at a level
// below the default, hence --info and --debug; without them the denials that
// matter are not in the output at all. The query costs a second or two on a warm
// log and more on a busy machine, which is why --explain is opt-in.
//
// The predicate names no process on purpose. The kernel logs a refusal against
// the process that asked, so filtering by the command the user typed drops every
// refusal by a helper or an interpreter, which is where a failing script's answer
// usually is. Attribution happens in Go, where the name is still respected.
func kernelLogDenials(since, until time.Time) ([]string, error) {
	secs := int(until.Sub(since).Seconds()) + 2
	if secs < 2 {
		secs = 2
	}
	if secs > explainWindowCap {
		secs = explainWindowCap
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/log", "show",
		"--style", "compact",
		"--last", fmt.Sprintf("%ds", secs),
		"--info", "--debug",
		"--predicate", `eventMessage CONTAINS "Sandbox: "`)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("the log query timed out; try a shorter run")
		}
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		// An empty result usually means the query itself found nothing at all,
		// which must not be reported as "the sandbox refused nothing".
		return nil, fmt.Errorf("the log query returned nothing")
	}
	return strings.Split(string(out), "\n"), nil
}
