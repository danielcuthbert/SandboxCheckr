//go:build darwin

package probe

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Brokered-egress probes for macOS.
//
// A socket-level network deny — the profile's `(deny network*)` — does not, on
// older macOS, cover network performed by a system daemon on the process's
// behalf: name resolution via mDNSResponder, or a URL opened via
// LaunchServices. These probes exercise those paths so the tool measures
// "can data leave by any means?" rather than only "can this process open a
// socket?". On macOS 26.6 both are blocked by the strict profile (SBX-001
// refuted); the probes remain as a regression test against a future OS change.

// brokerProbes runs the macOS brokered-egress and cross-app automation checks.
// ctx carries the battery's network budget, which bounds the helper binaries
// these probes run as well as any socket.
func brokerProbes(ctx context.Context) []model.ProbeResult {
	return []model.ProbeResult{
		probeBrokerDNS(ctx),
		probeBrokerLaunchServices(ctx),
		probeAppleEvents(ctx),
	}
}

// probeAppleEvents tries to send an Apple Event to another application.
//
// Apple Events are a cross-process automation channel: a confined process that
// can send them could tell Safari to fetch a URL, Mail to send a message, or
// Terminal to run a command — all outside the sandbox. `appleevent-send` is
// denied by the profile's deny-default (and, from this version, explicitly), so
// this should fail. A failure may also be TCC Automation refusing, not only the
// sandbox; the channel is closed either way, and the confound is noted rather
// than hidden.
func probeAppleEvents(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilAppleEvents, Want: model.VerdictBlocked}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e",
		`tell application "System Events" to get the name of the first process`).CombinedOutput()
	s := strings.ToLower(string(out))

	switch {
	case err == nil && strings.TrimSpace(s) != "":
		r.Verdict = model.VerdictAllowed
		r.Detail = "the process can send Apple Events — a channel to drive other applications " +
			"outside the sandbox (Safari, Mail, Terminal)"
	case ctx.Err() != nil:
		// A timeout is most often a TCC Automation consent dialog waiting for a
		// click, which is neither a refusal nor a success.
		r.Verdict = model.VerdictErrored
		r.Detail = "the Apple Events probe timed out (possibly waiting on a consent prompt); not counted as contained"
	case strings.Contains(s, "-1743") || strings.Contains(s, "not authorized") ||
		strings.Contains(s, "not allowed") || strings.Contains(s, "-600") ||
		strings.Contains(s, "not permitted") || strings.Contains(s, "sandbox") ||
		strings.Contains(s, "-10004") || strings.Contains(s, "privilege violation"):
		// -1743 is errAEEventNotPermitted (TCC Automation); -600 is the target
		// being unreachable from inside a sandbox; -10004 (privilege violation)
		// is the sandbox refusing appleevent-send.
		r.Verdict = model.VerdictBlocked
		r.Detail = "Apple Events are refused (by the sandbox and/or TCC Automation), so cross-app " +
			"automation is unavailable"
	case isExecRefused(err):
		r.Verdict = model.VerdictBlocked
		r.Detail = "osascript could not be executed, so Apple Events cannot be sent this way"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "Apple Events reachability inconclusive: " + strings.TrimSpace(string(out))
	}
	return r
}

// isExecRefused reports whether a helper failed to start because the sandbox
// refused to execute it, as opposed to it starting and failing for its own
// reasons.
func isExecRefused(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// osascript/dscacheutil killed by the sandbox at exec time show up as
		// a signal; a normal non-zero exit tells us nothing.
		return !exitErr.Exited()
	}
	v, _ := classify(err)
	return v == model.VerdictBlocked
}

// probeBrokerDNS resolves a name through dscacheutil, which queries
// mDNSResponder over Mach rather than opening a DNS socket itself. Resolution
// succeeding is the finding: it means brokered DNS is reachable despite any
// socket-level deny.
func probeBrokerDNS(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilBrokerDNS, Want: model.VerdictBlocked}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/dscacheutil",
		"-q", "host", "-a", "name", egressHost).CombinedOutput()

	switch {
	case strings.Contains(string(out), "ip_address"):
		r.Verdict = model.VerdictAllowed
		r.Detail = "name resolved via dscacheutil (mDNSResponder over Mach); a socket-level " +
			"network deny does not cover this brokered path"
	case ctx.Err() != nil:
		r.Verdict = model.VerdictErrored
		r.Detail = "brokered DNS probe timed out; not counted as contained"
	case isExecRefused(err):
		r.Verdict = model.VerdictBlocked
		r.Detail = "dscacheutil could not be executed, so brokered DNS is unreachable this way"
	case !resolverWorksUnconfined():
		// No answer here, but no answer outside either: the machine is offline
		// or the resolver is down, and the sandbox gets no credit for that.
		r.Verdict = model.VerdictErrored
		r.Detail = "brokered DNS did not resolve, but this host may simply be offline; not counted as contained"
	default:
		r.Verdict = model.VerdictBlocked
		r.Detail = "brokered DNS via dscacheutil did not resolve"
	}
	return r
}

// resolverWorksUnconfined is set by the parent (via --online) when it observed
// working name resolution outside the sandbox. Without that control a failed
// lookup inside could equally mean the laptop is offline.
var resolverWorksUnconfined = func() bool { return HostOnline }

// probeBrokerLaunchServices asks LaunchServices to activate an app.
//
// The target is SystemUIServer, which is always running and has no window, and
// -g keeps it in the background: on success nothing visible happens. What is
// being tested is whether launchservicesd will act on the process's behalf. If
// it will, the process can launch any app outside the sandbox — a browser to
// fetch a URL, say. A refusal surfaces as error -54 (permission).
//
// An earlier version asked LaunchServices to open an unclaimed URL scheme and
// treated "no application knows how to open" as reachability. That answer comes
// from reading the LaunchServices database, which a sandboxed process may do;
// it never reaches the launch path, so the probe reported a hole in profiles
// that actually block launching.
func probeBrokerLaunchServices(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilBrokerLaunch, Want: model.VerdictBlocked}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/open", "-g", "-j", "-a",
		"/System/Library/CoreServices/SystemUIServer.app").CombinedOutput()
	s := strings.ToLower(string(out))

	switch {
	case err == nil:
		r.Verdict = model.VerdictAllowed
		r.Detail = "LaunchServices launches apps on the process's behalf; `open` could start a " +
			"browser outside the sandbox to fetch an arbitrary URL"
	case ctx.Err() != nil:
		r.Verdict = model.VerdictErrored
		r.Detail = "LaunchServices probe timed out; not counted as contained"
	case strings.Contains(s, "-54") || strings.Contains(s, "not permitted") ||
		strings.Contains(s, "permission") || isExecRefused(err):
		r.Verdict = model.VerdictBlocked
		r.Detail = "LaunchServices refused to launch an app, so it cannot start an out-of-sandbox helper"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "LaunchServices reachability inconclusive: " + strings.TrimSpace(string(out))
	}
	return r
}
