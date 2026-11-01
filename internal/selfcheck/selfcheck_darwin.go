//go:build darwin

package selfcheck

import (
	"context"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

// detect looks for evidence that this process is inside a Seatbelt sandbox.
//
// The signals below were derived empirically: when developing this tool inside
// an already-sandboxed shell, a trivial "(allow default)" profile failed to
// apply and ps was refused. Both are reliable tells.
func detect() model.Confinement {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return conclude([]signal{
		sandboxReinitRefused(ctx),
		processInfoDenied(ctx),
	})
}

// sandboxReinitRefused is the strongest signal available on macOS.
//
// We ask sandbox-exec to apply a profile that permits everything and run a
// trivial command. An unconfined process always succeeds at this: the profile
// grants no restrictions, so there is nothing to fail on. If it fails with
// EPERM, the kernel refused the sandbox_apply call itself — which is what
// happens when the caller is already sandboxed (forbidden-sandbox-reinit).
//
// Using an allow-all profile is deliberate. Any restrictive profile would
// conflate "we are confined" with "the profile was rejected", and we would not
// be able to tell which.
func sandboxReinitRefused(ctx context.Context) signal {
	sbx, err := sysexec.Lookup("sandbox-exec")
	if err != nil {
		// Without sandbox-exec we cannot run this probe. Absence of the binary
		// is not evidence of confinement, so report nothing rather than guess.
		return signal{}
	}
	out, err := sysexec.Run(ctx, sbx, "-p", "(version 1)(allow default)", "/usr/bin/true")
	if err == nil {
		return signal{}
	}
	combined := strings.ToLower(out)
	switch {
	case strings.Contains(combined, "sandbox_apply"),
		strings.Contains(combined, "operation not permitted"),
		strings.Contains(combined, "sandbox-reinit"):
		return signal{
			present: true,
			kind:    "seatbelt",
			detail: "sandbox-exec refused to apply a permissive '(allow default)' profile " +
				"(forbidden-sandbox-reinit); an unconfined process can always apply this profile",
		}
	}
	return signal{}
}

// processInfoDenied checks whether we can enumerate processes. A Seatbelt
// profile denying process-info* makes ps fail with "operation not permitted".
//
// This is corroborating rather than conclusive — ps could fail for other
// reasons — so it is reported as its own evidence line and carries the same
// weight as any other single signal.
func processInfoDenied(ctx context.Context) signal {
	ps, err := sysexec.Lookup("ps")
	if err != nil {
		return signal{}
	}
	out, err := sysexec.Run(ctx, ps, "-o", "pid=", "-p", "1")
	if err == nil && strings.TrimSpace(out) != "" {
		return signal{}
	}
	// Only a permission refusal counts. ps failing for any other reason (a
	// timeout, a missing pid, an odd environment) is not evidence of a
	// sandbox, and a false "confined" turns the whole report indeterminate.
	low := strings.ToLower(out)
	if strings.Contains(low, "not permitted") || strings.Contains(low, "permission denied") {
		return signal{
			present: true,
			kind:    "seatbelt",
			detail:  "process enumeration via ps is denied, indicating a profile blocking process-info*",
		}
	}
	return signal{}
}
