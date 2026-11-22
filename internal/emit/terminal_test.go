package emit

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// sampleReport is a realistic unconfined result: one strong strict variant, one
// weaker practical variant, a degraded posture finding, and a mix of probe
// outcomes including a skip and an inconclusive.
func sampleReport() model.Report {
	return model.Report{
		Tool: "sandboxcheckr", Version: "0.1.0-dev",
		GeneratedAt: time.Now(),
		Host: model.Host{
			OS: "darwin", Arch: "arm64", Version: "26.6.2",
			Kernel: "25.6.0", Hostname: "test-host", CPUs: 8, User: "tester",
		},
		SelfCheck: model.Confinement{Confined: false},
		Posture: []model.PostureFinding{
			{ID: "sip", Name: "System Integrity Protection", Status: model.StatusPass, Value: "enabled",
				Impact: "System files are protected from modification even by root."},
			{ID: "filevault", Name: "FileVault disk encryption", Status: model.StatusFail, Value: "OFF",
				Impact: "The disk is NOT encrypted. Anything a sandbox protects at runtime is readable by anyone with physical access."},
			{ID: "data-volume-flags", Name: "Data volume mount flags", Status: model.StatusDegraded,
				Value: "exec + setuid permitted", Raw: "apfs,local,journaled",
				Impact: "Any binary written to your home directory can be run immediately."},
		},
		Mechanisms: []model.MechanismReport{
			{
				ID: "seatbelt-strict", Name: "macOS Seatbelt — strict", Score: 100, Usable: true,
				Summary:      "Kernel-enforced policy on a child process.",
				Availability: model.Availability{Status: model.StatusPass},
				Tradeoff:     "Nothing can reach the network, so a coding agent will not work.",
				Probes: []model.ProbeResult{
					{ID: model.ProbeFSWriteAllowed, Verdict: model.VerdictAllowed, Want: model.VerdictAllowed},
					{ID: model.ProbeFSWriteOutside, Verdict: model.VerdictBlocked, Want: model.VerdictBlocked},
					{ID: model.ProbePersistence, Verdict: model.VerdictBlocked, Want: model.VerdictBlocked},
					{ID: model.ProbeNetEgressTCP, Verdict: model.VerdictBlocked, Want: model.VerdictBlocked},
					{ID: model.ProbeContainerSocket, Verdict: model.VerdictSkipped, Want: model.VerdictBlocked},
				},
			},
			{
				ID: "seatbelt-network", Name: "macOS Seatbelt — practical", Score: 45, Usable: true,
				PermitsNetwork: true,
				Summary:        "Kernel-enforced policy on a child process.",
				Availability:   model.Availability{Status: model.StatusPass},
				Tradeoff:       "Filesystem is locked down, but egress is unrestricted.",
				Probes: []model.ProbeResult{
					{ID: model.ProbeFSWriteAllowed, Verdict: model.VerdictAllowed, Want: model.VerdictAllowed},
					{ID: model.ProbeFSWriteOutside, Verdict: model.VerdictBlocked, Want: model.VerdictBlocked},
					{ID: model.ProbeFSReadSecrets, Verdict: model.VerdictAllowed, Want: model.VerdictBlocked,
						Detail: "credential files are readable: .ssh/id_ed25519"},
					{ID: model.ProbeNetEgressTCP, Verdict: model.VerdictErrored, Want: model.VerdictBlocked,
						Detail: "the connection timed out, which cannot distinguish a sandbox blackholing traffic from an unreachable network"},
					{ID: model.ProbeContainerSocket, Verdict: model.VerdictSkipped, Want: model.VerdictBlocked},
				},
			},
		},
		Recommended:        "seatbelt-strict",
		RecommendedNetwork: "seatbelt-network",
		NextSteps: []model.Step{{Text: "Run coding agents inside seatbelt-network.",
			Command: "sandboxcheckr --emit seatbelt-network --workdir ."}},
		Gaps: []model.Gap{
			{Severity: "high", Title: "Seatbelt cannot filter network traffic by hostname",
				Detail: "Policies gate sockets and ports, not destinations."},
			{Severity: "low", Title: "A denial may come from TCC rather than the sandbox",
				Detail: "macOS privacy controls independently block some paths."},
			{Severity: "high", Source: "measured", Title: "Measured exposure: Read credential files",
				Detail: "credential files are readable: .ssh/id_ed25519"},
		},
	}
}

func render(t *testing.T, o Options) string {
	t.Helper()
	var buf bytes.Buffer
	Terminal(&buf, sampleReport(), o)
	return buf.String()
}

// The verdict must appear before the evidence. A reader who stops early should
// still have the answer.
func TestVerdictPrecedesEvidence(t *testing.T) {
	out := render(t, Options{})
	verdict := strings.Index(out, "VERDICT")
	matrix := strings.Index(out, "WHAT EACH OPTION STOPS")
	posture := strings.Index(out, "HOST POSTURE")

	if verdict < 0 || posture < 0 || matrix < 0 {
		t.Fatalf("missing sections:\n%s", out)
	}
	if !(verdict < matrix && matrix < posture) {
		t.Error("expected order: VERDICT, WHAT EACH OPTION STOPS, HOST POSTURE")
	}
}

// Both recommendations must be named, since the strongest one denies network.
func TestBothRecommendationsShown(t *testing.T) {
	out := render(t, Options{})
	if !strings.Contains(out, "strongest") || !strings.Contains(out, "with network") {
		t.Errorf("both recommendations should be labelled:\n%s", out)
	}
	if !strings.Contains(out, "--emit seatbelt-") {
		t.Error("should print a runnable emit command")
	}
}

// Problems must sort above things that are fine, or a single degraded finding
// ends up below the fold under a wall of passes.
func TestPostureSortsProblemsFirst(t *testing.T) {
	out := render(t, Options{})
	fail := strings.Index(out, "FileVault")
	degraded := strings.Index(out, "Data volume")
	pass := strings.Index(out, "System Integrity")

	if !(fail < degraded && degraded < pass) {
		t.Errorf("expected FAIL, then DEGRADED, then PASS:\n%s", out)
	}
}

// A passing check should not get a paragraph by default; a failing one must.
func TestImpactShownOnlyForProblems(t *testing.T) {
	out := render(t, Options{})
	if strings.Contains(out, "System files are protected from modification") {
		t.Error("passing findings should not print their impact by default")
	}
	if !strings.Contains(out, "The disk is NOT encrypted") {
		t.Error("failing findings must print their impact")
	}

	verbose := render(t, Options{Verbose: true})
	if !strings.Contains(verbose, "System files are protected from modification") {
		t.Error("--verbose must expand passing findings too")
	}
	if !strings.Contains(verbose, "apfs,local,journaled") {
		t.Error("--verbose must show raw observed values")
	}
}

// Exposures need their explanation; contained probes only need their names.
func TestProbesGroupedByOutcome(t *testing.T) {
	out := render(t, Options{Verbose: true})
	if !strings.Contains(out, "EXPOSED") {
		t.Error("exposures must be labelled EXPOSED")
	}
	if !strings.Contains(out, "credential files are readable") {
		t.Error("an exposure must carry its detail")
	}
	if !strings.Contains(out, "contained") {
		t.Error("contained probes should be grouped under one label")
	}
	if !strings.Contains(out, "unverified") {
		t.Error("an inconclusive probe must be labelled unverified, not contained")
	}
	if !strings.Contains(out, "n/a") {
		t.Error("skipped probes should be shown as not applicable")
	}
}

// An inconclusive probe must never be rendered inside the contained group.
//
// Scoped to the seatbelt-network block: the strict variant genuinely blocks
// net.egress.tcp, so a global scan would flag correct output.
func TestUnverifiedNotRenderedAsContained(t *testing.T) {
	out := render(t, Options{Verbose: true})

	// Anchor inside MECHANISMS: the first "seatbelt-network" in the document is
	// the VERDICT row, and slicing from there would sweep in the strict block.
	mechIdx := strings.Index(out, "MECHANISMS")
	if mechIdx < 0 {
		t.Fatal("MECHANISMS section not found")
	}
	rel := strings.Index(out[mechIdx:], "seatbelt-network")
	if rel < 0 {
		t.Fatal("seatbelt-network mechanism block not found")
	}
	section := out[mechIdx+rel:]
	if end := strings.Index(section, "WHAT THIS STILL"); end > 0 {
		section = section[:end]
	}

	for _, line := range strings.Split(section, "\n") {
		if strings.Contains(line, "contained") && strings.Contains(line, "net.egress.tcp") {
			t.Errorf("errored probe appears in the contained list: %q", line)
		}
	}
	if !strings.Contains(section, "unverified") {
		t.Error("the errored probe should appear under unverified")
	}
}

// --no-color must emit no escape sequences, so output stays pipeable.
func TestNoColorEmitsNoEscapes(t *testing.T) {
	out := render(t, Options{Color: false})
	if strings.Contains(out, "\x1b[") {
		t.Error("--no-color output must contain no ANSI escapes")
	}
}

// Gaps sort high severity first.
func TestGapsSortBySeverity(t *testing.T) {
	out := render(t, Options{})
	high := strings.Index(out, "cannot filter network traffic")
	low := strings.Index(out, "denial may come from TCC")
	if high < 0 || low < 0 || high > low {
		t.Error("high-severity gaps must come first")
	}
}

// A discovered agent sandbox is reported with its egress posture and findings,
// so "you already have a sandbox, here's how good it is" surfaces in the report.
func TestAgentSandboxSection(t *testing.T) {
	rep := sampleReport()
	rep.AgentSandboxes = []model.AgentSandbox{{
		Tool: "acme", Path: "/x/.config/acme/claude-sandbox.sb",
		Egress: "open", ReadsOpen: true,
		Findings: []model.Gap{{Severity: "high", Title: "Allows everything by default", Detail: "…"}},
	}}
	var b bytes.Buffer
	Terminal(&b, rep, Options{})
	out := b.String()

	for _, want := range []string{"AGENT SANDBOXES ON THIS HOST", "acme", "OPEN", "everything by default"} {
		if !strings.Contains(out, want) {
			t.Errorf("agent-sandbox section missing %q", want)
		}
	}
}

// The banner leads with the wordmark, carries host context, and puts the
// operator credit at the foot — the requested layout.
func TestBannerLayout(t *testing.T) {
	var b bytes.Buffer
	Terminal(&b, sampleReport(), Options{Banner: true})
	out := b.String()

	wm := strings.Index(out, "S A N D B O X C H E C K R")
	if wm < 0 {
		t.Fatal("wordmark missing from banner")
	}
	name := strings.Index(out, "@danielcuthbert")
	if name < 0 {
		t.Fatal("operator credit missing from banner")
	}
	if name < wm {
		t.Error("operator credit should appear below the wordmark, not above it")
	}
	for _, s := range []string{"host", "kernel", "machine", "cpus", "user", "test-host", "tester"} {
		if !strings.Contains(out, s) {
			t.Errorf("banner system-info missing %q", s)
		}
	}
}

// Running as root is the worst starting point for containment, so the banner
// must flag it rather than list it like any other user.
func TestBannerFlagsRoot(t *testing.T) {
	rep := sampleReport()
	rep.Host.User = "root"
	rep.Host.Elevated = true
	var b bytes.Buffer
	Terminal(&b, rep, Options{Banner: true})
	if !strings.Contains(b.String(), "ROOT") {
		t.Error("elevated (root) user must be flagged in the banner")
	}
}

// With the banner off (piped / CI), the compact one-line header still names the
// tool and host, but without the wordmark art.
func TestNoBannerUsesCompactHeader(t *testing.T) {
	var b bytes.Buffer
	Terminal(&b, sampleReport(), Options{})
	out := b.String()
	if strings.Contains(out, "S A N D B O X C H E C K R") {
		t.Error("banner-off output should not contain the wordmark")
	}
	if !strings.Contains(out, "SandboxCheckr") {
		t.Error("compact header should still name the tool")
	}
}

// ASCII mode must emit none of the Unicode glyphs, so it stays legible on
// terminals that cannot render them. The cleanup restores the default set so a
// later test reading the package glyph vars is not contaminated.
func TestASCIIModeAvoidsUnicode(t *testing.T) {
	t.Cleanup(func() { applyGlyphs(false) })
	out := render(t, Options{ASCII: true})
	for _, u := range []string{"█", "░", "─", "✓", "✗", "▲", "·"} {
		if strings.Contains(out, u) {
			t.Errorf("ASCII mode still emitted the Unicode glyph %q", u)
		}
	}
	if !strings.Contains(out, "#") {
		t.Error("expected ASCII score-bar fill '#' in ASCII mode")
	}
}

// Width is clamped so the layout never collapses (too narrow) or sprawls (too
// wide), and an unset width falls back to the stable default.
func TestWidthClamped(t *testing.T) {
	var b bytes.Buffer
	Terminal(&b, sampleReport(), Options{Width: 500})
	if width != 110 {
		t.Errorf("width=%d, want clamped to 110", width)
	}
	Terminal(&b, sampleReport(), Options{Width: 10})
	if width != 50 {
		t.Errorf("width=%d, want clamped to 50", width)
	}
	Terminal(&b, sampleReport(), Options{})
	if width != 74 {
		t.Errorf("width=%d, want default 74 when unset", width)
	}
}

func TestScoreBarScalesWithScore(t *testing.T) {
	c := palette(false)
	if got := scoreBar(c, 100); strings.Count(got, "█") != 10 {
		t.Errorf("100 → %q, want 10 filled cells", got)
	}
	if got := scoreBar(c, 0); strings.Count(got, "█") != 0 {
		t.Errorf("0 → %q, want no filled cells", got)
	}
	// A non-zero score must never render as an empty bar; that reads as zero.
	if got := scoreBar(c, 4); strings.Count(got, "█") != 1 {
		t.Errorf("4 → %q, want at least one filled cell", got)
	}
}

// The positive control wants ALLOWED, so it must never be rendered inside the
// "contained" group — a successful write is not a blocked one, and saying so
// would invert the meaning of the row.
func TestPositiveControlNotLabelledContained(t *testing.T) {
	out := render(t, Options{Verbose: true})
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "contained") && strings.Contains(line, string(model.ProbeFSWriteAllowed)) {
			t.Errorf("positive control rendered as contained: %q", line)
		}
	}
	if !strings.Contains(out, "usable") {
		t.Error("the positive control should be reported on its own 'usable' line")
	}
}

// A sandbox that breaks the program must say so in the probe listing, not only
// in the score.
func TestFailedPositiveControlRendersUnusable(t *testing.T) {
	rep := sampleReport()
	rep.Mechanisms[0].Probes[0] = model.ProbeResult{
		ID: model.ProbeFSWriteAllowed, Verdict: model.VerdictBlocked, Want: model.VerdictAllowed,
	}
	var buf bytes.Buffer
	Terminal(&buf, rep, Options{Verbose: true})
	if !strings.Contains(buf.String(), "UNUSABLE") {
		t.Error("a failed positive control must be called out as UNUSABLE")
	}
}

// The default view is one comparison table: a row per probe and a column per
// configuration, so "what does the sandbox stop that I'm exposed to today"
// is read straight across a row.
func TestMatrixComparesConfigurations(t *testing.T) {
	rep := sampleReport()
	rep.Baseline = &model.MechanismReport{ID: "none", Score: 10, Usable: true, Egress: "open",
		Probes: []model.ProbeResult{
			{ID: model.ProbeFSWriteOutside, Verdict: model.VerdictAllowed, Want: model.VerdictBlocked},
		}}
	var b bytes.Buffer
	Terminal(&b, rep, Options{})
	out := b.String()
	for _, want := range []string{"WHAT EACH OPTION STOPS", "no sandbox", "strict", "network",
		"Write outside the project", "OPEN", "stops", "? unsure"} {
		if !strings.Contains(out, want) {
			t.Errorf("matrix missing %q", want)
		}
	}
	// The row for a probe must read across: OPEN without a sandbox, stops in strict.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Write outside the project") {
			if !(strings.Index(line, "OPEN") < strings.Index(line, "stops")) {
				t.Errorf("row should show OPEN (no sandbox) before stops (strict): %q", line)
			}
		}
	}
}

// Documented limits are the same on every run; by default only their titles
// are shown, while measured gaps keep their full explanation.
func TestDocumentedLimitsCollapsed(t *testing.T) {
	rep := sampleReport()
	for i := range rep.Gaps {
		if rep.Gaps[i].Source == "" {
			rep.Gaps[i].Source = "documented"
		}
	}
	var b bytes.Buffer
	Terminal(&b, rep, Options{})
	out := b.String()
	if strings.Contains(out, "Policies gate sockets and ports") {
		t.Error("documented limit detail should be collapsed by default")
	}
	if !strings.Contains(out, "cannot filter network traffic by hostname") {
		t.Error("documented limit title should still be listed")
	}
	if !strings.Contains(out, "credential files are readable") {
		t.Error("measured gaps must keep their detail")
	}
}

func TestNextStepsRendered(t *testing.T) {
	out := render(t, Options{})
	if !strings.Contains(out, "WHAT TO DO") || !strings.Contains(out, "$ sandboxcheckr --emit seatbelt-network") {
		t.Errorf("next steps missing:\n%s", out)
	}
}

// The table must say what each column is and how to use one: the column names
// are otherwise jargon, and nothing would tell a reader that SandboxCheckr
// builds these sandboxes itself.
func TestMatrixExplainsColumnsAndUsage(t *testing.T) {
	rep := sampleReport()
	rep.Mechanisms[0].BestFor = "builds and tests with no network"
	rep.Mechanisms[1].BestFor = "network wide open"
	var b bytes.Buffer
	Terminal(&b, rep, Options{Width: 110})
	out := b.String()
	for _, want := range []string{
		"seatbelt-strict", "builds and tests with no network", // key: full name + purpose
		"SandboxCheckr generates and has just tested", // provenance
		"left open", // per-column exposure count
		"★",         // recommended column
		"To use a column", "--emit seatbelt-network", "sh seatbelt-network.sh",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("matrix missing %q", want)
		}
	}
}

// A section header is read as a rule the table under it sits inside, so it has
// to land on the column width exactly. The filler used to be measured in bytes,
// which counted each ─ as three columns and pulled every header four short.
func TestSectionIsExactlyTheColumnWidth(t *testing.T) {
	t.Cleanup(func() { applyGlyphs(false) })
	for _, note := range []string{"", "2 hosts, 3 refused", "run 13610e6f, 1 trip — café"} {
		got := strings.TrimSuffix(Section(Styles{}, 74, "destinations", note), "\n")
		if n := utf8.RuneCountInString(got); n != 74 {
			t.Errorf("note %q: header is %d columns wide, want 74:\n%s", note, n, got)
		}
		if !strings.HasPrefix(got, "── DESTINATIONS") {
			t.Errorf("note %q: header does not start with the rule and title: %q", note, got)
		}
	}
}
