// Package run orchestrates the four stages and assembles the report.
package run

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/agentscan"
	"github.com/danielcuthbert/sandboxcheckr/internal/detect"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/probe"
	"github.com/danielcuthbert/sandboxcheckr/internal/rank"
	"github.com/danielcuthbert/sandboxcheckr/internal/selfcheck"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

// Version is the tool version, overridable at build time with -ldflags.
var Version = "0.1.0-dev"

// Options controls a run.
type Options struct {
	// SkipProbes runs passive detection only.
	SkipProbes bool
	// PeerProbes additionally launches two sandboxed peers per mechanism to
	// test whether they can reach each other. Off by default: it doubles the
	// child processes and answers a different question from the main battery.
	PeerProbes bool
	// SkipBaseline omits the unsandboxed baseline run.
	SkipBaseline bool
	// TCC enables the opt-in macOS user-folder probes.
	TCC bool
	// ProxyPort is the loopback port the proxied variants use.
	ProxyPort int
}

// Execute performs stages 1 through 4 and returns the assembled report.
func Execute(ctx context.Context, opts Options) model.Report {
	rep := model.Report{
		Tool:        "sandboxcheckr",
		Version:     Version,
		GeneratedAt: time.Now().UTC(),
		Host:        hostInfo(ctx),
	}

	// Stage 1. This gates everything: if we are confined, downstream failures
	// are unreachability rather than absence, and must not be reported as
	// "this host has no sandboxing".
	rep.SelfCheck = selfcheck.Run()

	// Stage 2a: passive host posture. Always runs, never has side effects, and
	// stays useful even when no confinement mechanism is available at all.
	rep.Posture = detect.Run(ctx)

	// Stage 2b: discover and lint sandbox profiles other agent tools have
	// already installed. Read-only, and it answers "what is actually wrapping my
	// agents today?" rather than only the hypothetical sandboxes we generate.
	rep.AgentSandboxes = agentscan.Run()

	// Stage 2 and 3.
	rep.LaunchedFrom = launcher(ctx)

	var harness *probe.Harness
	if !opts.SkipProbes {
		if h, err := probe.NewHarness(); err == nil {
			h.TCC = opts.TCC
			harness = h
		}
	}

	// The unsandboxed baseline: what an agent can do when started straight
	// from this shell. It runs even when SandboxCheckr is itself confined —
	// then it describes the sandbox it is in, which is still true and useful,
	// and the report labels it accordingly.
	if harness != nil && !opts.SkipBaseline {
		b := model.MechanismReport{
			ID:   "none",
			Name: "No sandbox (run directly from this shell)",
			Summary: "The program inherits this shell's full authority: every file you can read, " +
				"every environment variable, every privacy grant held by the app you launched it from, " +
				"and unrestricted network.",
			PermitsNetwork: true,
			Egress:         "open",
			BestFor:        "what you have today: the agent runs straight from your terminal",
			Availability:   model.Availability{Status: model.StatusPass},
		}
		if results, err := harness.RunBaseline(ctx); err != nil {
			b.Availability.Status = model.StatusIndeterminate
			b.Notes = append(b.Notes, "baseline probes did not complete: "+err.Error())
		} else {
			b.Probes = results
			rank.Score(&b, nil)
		}
		rep.Baseline = &b
	}

	for _, m := range mechanisms.All(opts.ProxyPort) {
		mr := model.MechanismReport{
			ID:             m.ID(),
			Name:           m.Name(),
			Summary:        m.Summary(),
			Gaps:           m.KnownGaps(),
			PermitsNetwork: m.PermitsNetwork(),
			Tradeoff:       m.Tradeoff(),
			Egress:         m.Egress(),
			BestFor:        m.BestFor(),
		}
		mr.Availability = m.Detect(ctx)

		if rep.SelfCheck.Confined && mr.Availability.Status == model.StatusAbsent {
			// We are confined, so we cannot distinguish "absent" from
			// "unreachable from in here". Downgrade the claim rather than
			// assert something we cannot support.
			mr.Availability.Status = model.StatusIndeterminate
			mr.Availability.Detail += " (SandboxCheckr is itself confined, so this may be unreachable rather than absent)"
		}

		if harness != nil && mr.Availability.Status == model.StatusPass {
			results, err := harness.Run(ctx, m)
			if err != nil {
				mr.Notes = append(mr.Notes, "probes did not complete: "+err.Error())
				mr.Availability.Status = model.StatusIndeterminate
			} else {
				mr.Probes = results
			}

			if opts.PeerProbes {
				channels, err := harness.RunPeers(ctx, m)
				if err != nil {
					mr.Notes = append(mr.Notes, "peer probing did not complete: "+err.Error())
				} else {
					mr.PeerChannels = channels
				}
			}
		}

		rep.Mechanisms = append(rep.Mechanisms, mr)
	}

	// Stage 4. The baseline is the control: a probe that could not conclude, or
	// that the bare host already blocks, is not evidence about the mechanism.
	rep.Recommended, rep.RecommendedNetwork = rank.Apply(rep.Mechanisms, rep.Baseline)
	rep.Gaps = gapsFor(rep)
	rep.NextSteps = nextSteps(rep)

	return rep
}

// gapsFor collects the exposures that remain under the recommendation.
//
// It merges two sources: the documented limits of the recommended mechanism,
// and any probe that came back ALLOWED — a measured hole is a gap whether or
// not anyone documented it.
func gapsFor(rep model.Report) []model.Gap {
	var out []model.Gap

	// TCC exposure describes running WITHOUT the recommended sandbox, which
	// is true whatever the recommendation is — including when there is none.
	out = append(out, tccGaps(rep)...)

	if rep.Recommended == "" {
		// When we were confined, we genuinely do not know whether this host has
		// usable sandboxing — we were prevented from finding out. Saying "no
		// mechanism was found" here would be the precise false negative this
		// tool exists to prevent, and it would contradict the INDETERMINATE
		// verdict reported above. Report the uncertainty instead.
		if rep.SelfCheck.Confined {
			out = append(out, model.Gap{
				Severity: "medium",
				Title:    "Inconclusive: SandboxCheckr could not evaluate this host from inside a sandbox",
				Detail: "The checks ran inside an existing sandbox, which blocks the very operations " +
					"needed to evaluate sandboxing. This is NOT a finding that the host lacks " +
					"confinement — it is an absence of evidence either way. Re-run from an unconfined " +
					"shell before drawing any conclusion.",
			})
			return out
		}
		out = append(out, model.Gap{
			Severity: "high",
			Title:    "No usable confinement mechanism was found",
			Detail: "Nothing on this host both contained the probes and left the sandbox usable. " +
				"Running untrusted code here exposes the full authority of your user account: " +
				"every file you can read, every credential you have, and unrestricted network access.",
		})
		return out
	}

	for _, m := range rep.Mechanisms {
		if m.ID != rep.Recommended {
			continue
		}
		for _, g := range m.Gaps {
			if g.Source == "" {
				g.Source = "documented"
			}
			out = append(out, g)
		}

		// A peer channel is a measured gap in its own right. Every mechanism
		// here is scored on confining ONE process; if two can still reach each
		// other, the score is answering a narrower question than the reader is
		// likely to be asking.
		for _, ch := range m.PeerChannels {
			if !ch.Carried {
				continue
			}
			out = append(out, model.Gap{
				Severity: "high",
				Source:   "measured",
				Title:    "Separately-sandboxed processes can signal each other via " + ch.Name,
				Detail: ch.Detail + ". Confining each process individually does not isolate them " +
					"from one another, so several agents under this profile can coordinate and " +
					"stage data between themselves.",
			})
		}

		for _, p := range m.Probes {
			if p.Verdict != model.VerdictAllowed || p.Want != model.VerdictBlocked || p.ID == model.ProbeProcExec {
				// Positive controls want ALLOWED, and proc.exec is
				// informational: a coding agent must be able to run commands.
				continue
			}
			out = append(out, model.Gap{
				Severity: "high",
				Source:   "measured",
				Title:    "Measured exposure: " + p.ID.Label() + " (" + string(p.ID) + ")",
				Detail:   p.Detail,
			})
		}
	}
	return out
}

// tccGaps turns baseline TCC exposure into gaps with concrete remediation.
//
// These are reported under any recommendation, because they describe what
// happens when an agent is NOT run in the recommended sandbox — which is how
// most agents are run today — and the fix is a settings change, not a profile.
func tccGaps(rep model.Report) []model.Gap {
	if rep.Baseline == nil {
		return nil
	}
	// Remediation is about the launching app's grants. When we are confined,
	// the baseline measured someone else's sandbox; a TCC finding there is
	// still real (the outer sandbox did not stop it), so it is reported.
	app, bundle := "the app you launched this from", ""
	if rep.LaunchedFrom != nil {
		app, bundle = rep.LaunchedFrom.Name, rep.LaunchedFrom.BundleID
	}
	var out []model.Gap
	for _, p := range rep.Baseline.Probes {
		if p.Verdict != model.VerdictAllowed {
			continue
		}
		switch p.ID {
		case model.ProbeTCCFullDisk:
			fix := "Remove it in System Settings → Privacy & Security → Full Disk Access, unless you are " +
				"certain every program you will ever start from " + app + " should read your mail."
			if bundle != "" {
				fix += " Or reset it from a shell: tccutil reset SystemPolicyAllFiles " + bundle
			}
			g := model.Gap{
				Severity: "high",
				Source:   "host",
				Title:    app + " has Full Disk Access, and every agent started from it inherits it",
				Detail: "macOS privacy grants belong to the launching app, not to the program. " + p.Detail +
					". Run agents inside the recommended sandbox, which does not inherit this. " + fix,
			}
			if bundle != "" {
				g.Fix = "tccutil reset SystemPolicyAllFiles " + bundle
			}
			out = append(out, g)
		case model.ProbeTCCUserFolders:
			fix := "Review System Settings → Privacy & Security → Files & Folders for " + app + "."
			if bundle != "" {
				fix += " To revoke from a shell: tccutil reset SystemPolicyDesktopFolder " + bundle +
					" (likewise SystemPolicyDocumentsFolder, SystemPolicyDownloadsFolder)."
			}
			g := model.Gap{
				Severity: "medium",
				Source:   "host",
				Title:    "Agents started from " + app + " can reach Desktop, Documents and Downloads",
				Detail: p.Detail + ". TCC was configured to allow " + app + " into these folders, and " +
					"that permission is inherited by everything it launches. " + fix,
			}
			if bundle != "" {
				g.Fix = "tccutil reset SystemPolicyDesktopFolder " + bundle + "  (and …DocumentsFolder, …DownloadsFolder)"
			}
			out = append(out, g)
		}
	}
	return out
}

// nextSteps turns the report into a short, ordered to-do list.
//
// The report's job is to change what the reader does next, and a list of
// sixty findings does not tell anyone where to start. This picks at most five
// actions, most consequential first, each with a command where one exists.
func nextSteps(rep model.Report) []model.Step {
	if rep.SelfCheck.Confined {
		return []model.Step{{Text: "Re-run from a normal, unsandboxed terminal to get a real answer."}}
	}
	var out []model.Step
	byID := map[string]model.MechanismReport{}
	for _, m := range rep.Mechanisms {
		byID[m.ID] = m
	}

	// 1. Run agents in the best configuration that still has network, since
	//    an agent cannot work without it. Prefer the proxied variant.
	pick := rep.RecommendedNetwork
	if m, ok := byID[pick]; ok && m.Egress == "open" {
		for _, c := range rep.Mechanisms {
			if c.Egress == "proxy" && c.Usable && c.Score > 0 {
				pick = c.ID
				break
			}
		}
	}
	if pick != "" {
		command := "sandboxcheckr --emit " + pick + " --workdir ."
		if byID[pick].Egress == "proxy" {
			command = "sandboxcheckr run <agent>"
		}
		if base := rep.Baseline; base != nil && byID[pick].Score > base.Score {
			out = append(out, model.Step{
				Text: fmt.Sprintf("Run coding agents inside %s instead of directly (%d/100 instead of %d/100).",
					pick, byID[pick].Score, base.Score),
				Command: command,
			})
		} else {
			out = append(out, model.Step{Text: "Run coding agents inside " + pick + ".",
				Command: command})
		}
		if byID[pick].Egress == "proxy" {
			out = append(out, model.Step{
				Text:    "Build its allow-list from evidence: run the agent in observe mode, then review the destinations.",
				Command: "sandboxcheckr run --observe <agent>",
			})
		}
	}

	// 2. Host-level fixes with concrete commands (TCC grants).
	for _, g := range rep.Gaps {
		if g.Source == "host" && g.Fix != "" {
			out = append(out, model.Step{Text: g.Title + ".", Command: g.Fix})
		}
	}

	// 3. An agent sandbox already installed that leaves egress open.
	for _, a := range rep.AgentSandboxes {
		if a.Egress == "open" {
			out = append(out, model.Step{
				Text: fmt.Sprintf("The %s sandbox profile leaves network%s open; it does not stop exfiltration. "+
					"Prefer a proxied profile.", a.Tool, map[bool]string{true: " and reads", false: ""}[a.ReadsOpen]),
				Command: "sandboxcheckr lint " + a.Path,
			})
		}
	}

	// 4. Posture failures.
	for _, f := range rep.Posture {
		if f.Status == model.StatusFail {
			out = append(out, model.Step{Text: "Fix host posture: " + f.Name + " is " + f.Value + "."})
		}
	}

	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// launcher identifies the app this process inherits privacy grants from.
//
// macOS exports __CFBundleIdentifier into processes started from a GUI app,
// and terminals set TERM_PROGRAM. Both can be spoofed by whoever started us,
// but they are only used to word remediation advice, never to decide a verdict.
func launcher(ctx context.Context) *model.Launcher {
	bundle := os.Getenv("__CFBundleIdentifier")
	prog := os.Getenv("TERM_PROGRAM")
	if bundle == "" && prog == "" {
		return nil
	}
	names := map[string]string{
		"com.apple.Terminal":            "Terminal",
		"com.googlecode.iterm2":         "iTerm2",
		"com.mitchellh.ghostty":         "Ghostty",
		"dev.warp.Warp-Stable":          "Warp",
		"net.kovidgoyal.kitty":          "kitty",
		"org.alacritty":                 "Alacritty",
		"com.github.wez.wezterm":        "WezTerm",
		"com.microsoft.VSCode":          "Visual Studio Code",
		"com.todesktop.230313mzl4w4u92": "Cursor",
		"dev.zed.Zed":                   "Zed",
	}
	progBundles := map[string]string{
		"Apple_Terminal": "com.apple.Terminal",
		"iTerm.app":      "com.googlecode.iterm2",
		"ghostty":        "com.mitchellh.ghostty",
		"WarpTerminal":   "dev.warp.Warp-Stable",
		"vscode":         "com.microsoft.VSCode",
		"WezTerm":        "com.github.wez.wezterm",
	}
	if bundle == "" {
		bundle = progBundles[prog]
	}
	name := names[bundle]
	if name == "" {
		name = prog
	}
	if name == "" {
		name = bundle
	}
	return &model.Launcher{Name: name, BundleID: bundle}
}

// hostInfo gathers machine identification for fleet inventory.
func hostInfo(ctx context.Context) model.Host {
	h := model.Host{OS: runtime.GOOS, Arch: runtime.GOARCH}

	if p, err := sysexec.Lookup("uname"); err == nil {
		if out, err := sysexec.Run(ctx, p, "-r"); err == nil {
			h.Kernel = strings.TrimSpace(out)
		}
	}
	if runtime.GOOS == "darwin" {
		if p, err := sysexec.Lookup("sw_vers"); err == nil {
			if out, err := sysexec.Run(ctx, p, "-productVersion"); err == nil {
				h.Version = strings.TrimSpace(out)
			}
		}
	}

	h.CPUs = runtime.NumCPU()
	if hn, err := os.Hostname(); err == nil {
		h.Hostname = hn
	}
	h.User = currentUser()
	// Geteuid < 0 on platforms without the concept; only 0 is root.
	h.Elevated = os.Geteuid() == 0

	return h
}

// currentUser resolves the login name without os/user, which can require cgo in
// static builds — this tool is built CGO_ENABLED=0. Falls back to the numeric
// uid when the environment carries no name.
func currentUser() string {
	for _, k := range []string{"USER", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if uid := os.Getuid(); uid >= 0 {
		return "uid " + strconv.Itoa(uid)
	}
	return ""
}
