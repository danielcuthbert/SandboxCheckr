// Package emit renders a report for humans and machines.
package emit

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

var width = 74

func clampWidth(n int) int {
	switch {
	case n < 50:
		return 50
	case n > 110:
		return 110
	default:
		return n
	}
}

// Options controls rendering.
type Options struct {
	Color   bool
	Banner  bool
	Verbose bool
	Width   int
	ASCII   bool
}

// Terminal writes the human-readable report.
func Terminal(w io.Writer, rep model.Report, o Options) {
	if o.Width > 0 {
		width = clampWidth(o.Width)
	} else {
		width = 74
	}
	applyGlyphs(o.ASCII)

	c := palette(o.Color)
	if o.Banner {
		Banner(w, c, rep)
	} else {
		writeHeader(w, c, rep)
	}
	writeTrust(w, c, rep.SelfCheck)
	writeVerdict(w, c, rep)
	writeNextSteps(w, c, rep.NextSteps)
	if o.Verbose {
		// The long form: every probe, every mechanism, every detail.
		writeBaseline(w, c, rep)
		writeMechanisms(w, c, rep, o.Verbose)
	} else {
		writeMatrix(w, c, rep)
	}
	writePosture(w, c, rep.Posture, o.Verbose)
	writeAgentSandboxes(w, c, rep.AgentSandboxes)
	writeGapsSection(w, c, rep.Gaps, o.Verbose)
}

// writeNextSteps is the to-do list: what to actually do, in order.
func writeNextSteps(w io.Writer, c colors, steps []model.Step) {
	if len(steps) == 0 {
		return
	}
	rule(w, c, "WHAT TO DO")
	for i, s := range steps {
		fmt.Fprintf(w, "  %s%d.%s %s\n", c.bold, i+1, c.reset, wrap(s.Text, width-5, "     "))
		if s.Command != "" {
			fmt.Fprintf(w, "     %s$ %s%s\n", c.blue, s.Command, c.reset)
		}
	}
	fmt.Fprintln(w)
}

// matrixColumn is one configuration in the comparison table.
type matrixColumn struct {
	head  string
	id    string
	score int
	byID  map[model.ProbeID]model.ProbeResult
	note  string
	best  string
	// open counts the attempts that succeeded, for the "left open" row.
	open int
}

// writeMatrix shows every probe against every configuration in one table.
//
// The question a reader has is comparative — "what does the sandbox stop that
// I am exposed to today, and what does each option cost?" — and per-mechanism
// lists made them assemble that table in their head from a hundred lines. One
// row per probe, one column per configuration, grouped by what is at risk,
// answers it at a glance. The full sentences are one --verbose away, and every
// exposure under the recommendation is spelled out in the gaps section below.
func writeMatrix(w io.Writer, c colors, rep model.Report) {
	var cols []matrixColumn
	if rep.Baseline != nil && len(rep.Baseline.Probes) > 0 {
		head := "no sandbox"
		if rep.SelfCheck.Confined {
			head = "this shell"
		}
		col := column(head, *rep.Baseline)
		col.id = ""
		cols = append(cols, col)
	}
	var unavailable []model.MechanismReport
	for _, m := range rep.Mechanisms {
		if len(m.Probes) == 0 {
			unavailable = append(unavailable, m)
			continue
		}
		col := column(shortName(m.ID), m)
		if m.ID == rep.RecommendedNetwork {
			// The configuration the WHAT TO DO list points at.
			col.head = "★ " + col.head
		}
		cols = append(cols, col)
	}
	if len(cols) == 0 {
		writeMechanisms(w, c, rep, false)
		return
	}

	rule(w, c, "WHAT EACH OPTION STOPS")
	writeColumnKey(w, c, cols, rep)
	// Labels are never truncated: a cut-off row name is unreadable. On a
	// narrow terminal the columns shrink instead, down to the width of the
	// widest cell.
	labelW := 0
	for _, col := range cols {
		for id := range col.byID {
			labelW = max(labelW, len(id.Label())+3)
		}
	}
	cw := (width - 2 - labelW) / len(cols)
	cw = min(max(cw, 10), 12)

	// Header: configuration names, then network posture, then score.
	fmt.Fprintf(w, "  %-*s", labelW, "")
	for _, col := range cols {
		fmt.Fprintf(w, "%s%*s%s", c.bold, cw, col.head, c.reset)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s%-*s%s", c.dim, labelW, "network", c.reset)
	for _, col := range cols {
		fmt.Fprintf(w, "%s%*s%s", c.dim, cw, col.note, c.reset)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-*s", labelW, "score")
	for _, col := range cols {
		fmt.Fprintf(w, "%s%*s%s", scoreColor(c, col.score), cw, fmt.Sprintf("%d/100", col.score), c.reset)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-*s", labelW, "left open")
	for _, col := range cols {
		cell := "nothing"
		colr := c.green
		if col.open > 0 {
			cell, colr = fmt.Sprintf("%d", col.open), c.red
		}
		fmt.Fprintf(w, "%s%*s%s", colr, cw, cell, c.reset)
	}
	fmt.Fprintf(w, "\n\n")

	// Rows, grouped by category, in a fixed order. A probe nobody ran (a
	// macOS-only one on Linux) has no row.
	present := map[model.ProbeID]bool{}
	for _, col := range cols {
		for id := range col.byID {
			present[id] = true
		}
	}
	var ids []model.ProbeID
	for id := range present {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Order() < ids[j].Order() })

	for _, cat := range model.ProbeCategories {
		var rows []model.ProbeID
		for _, id := range ids {
			if id.Category() == cat {
				rows = append(rows, id)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s%s%s\n", c.bold, cat, c.reset)
		for _, id := range rows {
			fmt.Fprintf(w, "    %-*s", labelW-2, id.Label())
			for _, col := range cols {
				cell, colr := matrixCell(c, col.byID[id], col.byID != nil)
				fmt.Fprintf(w, "%s%*s%s", colr, cw, cell, c.reset)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "  %s%s%s\n", c.dim, wrap(matrixLegend(), width-2, "  "), c.reset)
	writeHowToUse(w, c, rep)
	for _, m := range unavailable {
		g, col := glyph(c, m.Availability.Status)
		fmt.Fprintf(w, "\n  %s%s %s%s %s%s%s\n", col, g, m.ID, c.reset, col, strings.ToLower(string(m.Availability.Status)), c.reset)
		if m.Availability.Detail != "" {
			fmt.Fprintf(w, "      %s%s%s\n", c.dim, wrap(m.Availability.Detail, width-6, "      "), c.reset)
		}
		for _, n := range m.Notes {
			fmt.Fprintf(w, "      %s%s %s%s\n", c.dim, bullet, wrap(n, width-8, "        "), c.reset)
		}
	}
	fmt.Fprintln(w)
}

func column(head string, m model.MechanismReport) matrixColumn {
	col := matrixColumn{head: head, id: m.ID, score: m.Score, best: m.BestFor,
		byID: map[model.ProbeID]model.ProbeResult{}}
	for _, p := range m.Probes {
		col.byID[p.ID] = p
		if p.Want == model.VerdictBlocked && p.Verdict == model.VerdictAllowed && p.ID != model.ProbeProcExec {
			col.open++
		}
	}
	switch m.Egress {
	case "none":
		col.note = "none"
	case "proxy":
		col.note = "allowlist"
	case "open":
		col.note = "open"
	}
	if !m.Usable && len(m.Probes) > 0 {
		col.note = "UNUSABLE"
	}
	return col
}

// matrixCell renders one result. Words, not only symbols, so the table reads
// the same without colour and in ASCII mode.
func matrixCell(c colors, p model.ProbeResult, ran bool) (string, string) {
	if !ran || p.ID == "" {
		return "", c.dim
	}
	if p.ID == model.ProbeCanaryDetection {
		switch p.Verdict {
		case model.VerdictAllowed:
			return symPass + " verified", c.green
		case model.VerdictSkipped:
			return "n/a", c.dim
		default:
			return "? unverified", c.yellow
		}
	}
	if p.Want == model.VerdictAllowed {
		// Positive controls: success is what we want.
		switch p.Verdict {
		case model.VerdictAllowed:
			return symPass + " works", c.green
		case model.VerdictSkipped:
			return "n/a", c.dim
		default:
			return symFail + " BROKEN", c.red
		}
	}
	if p.ID == model.ProbeProcExec {
		if p.Verdict == model.VerdictAllowed {
			return "yes", c.dim
		}
		return "no", c.dim
	}
	// For a privacy grant "stops" reads oddly in the no-sandbox column —
	// nothing stopped anything, the grant simply is not held.
	grant := p.ID == model.ProbeTCCFullDisk
	switch p.Verdict {
	case model.VerdictBlocked:
		if grant {
			return symPass + " no", c.green
		}
		return symPass + " stops", c.green
	case model.VerdictAllowed:
		if grant {
			return symFail + " GRANTED", c.red
		}
		return symFail + " OPEN", c.red
	case model.VerdictSkipped:
		return "n/a", c.dim
	default:
		return "? unsure", c.yellow
	}
}

// writeColumnKey says what each column IS before the reader meets the grid.
// Without it, "proxy" and "strict" are jargon, and nothing tells the reader
// that every column but the first is a sandbox SandboxCheckr will build.
func writeColumnKey(w io.Writer, c colors, cols []matrixColumn, rep model.Report) {
	// The key carries the full mechanism name, because that is what --emit
	// takes; the grid uses the short form only to stay narrow.
	name := func(col matrixColumn) string {
		if col.id == "" || col.id == "none" {
			return col.head
		}
		return col.id
	}
	keyW := 0
	for _, col := range cols {
		keyW = max(keyW, len(name(col))+2)
	}
	for _, col := range cols {
		star := "  "
		if strings.HasPrefix(col.head, "★") {
			star = "★ "
		}
		fmt.Fprintf(w, "  %s%s%-*s%s  %s\n", c.bold, star, keyW-2, name(col), c.reset,
			wrap(col.best, width-keyW-4, strings.Repeat(" ", keyW+4)))
	}
	built := "Every column after the first is a sandbox SandboxCheckr generates and has just tested on this machine."
	if rep.Host.OS == "darwin" {
		built += " They use macOS's built-in sandbox (sandbox-exec); nothing extra to install."
	}
	if rep.Host.OS == "linux" {
		built += " They use bubblewrap (bwrap)."
	}
	fmt.Fprintf(w, "\n  %s%s%s\n\n", c.dim, wrap(built, width-2, "  "), c.reset)
}

// writeHowToUse closes the table with the two commands that turn a column into
// a running sandbox, for the recommended configuration.
func writeHowToUse(w io.Writer, c colors, rep model.Report) {
	id := rep.RecommendedNetwork
	if id == "" {
		id = rep.Recommended
	}
	if id == "" || rep.SelfCheck.Confined {
		return
	}
	fmt.Fprintf(w, "\n  %sTo use a column%s (★ is the recommended one):\n", c.bold, c.reset)
	fmt.Fprintf(w, "    %s$ sandboxcheckr --emit %s --workdir ~/code/myproject%s\n", c.blue, id, c.reset)
	fmt.Fprintf(w, "    %s$ sh %s.sh claude%s          %s# or any command: npm install, pytest, …%s\n",
		c.blue, id, c.reset, c.dim, c.reset)
	text := "The first writes a runner script and profile; the second runs your command inside it, able " +
		"to write only to that project directory (--workdir). Use any name from the key above in place of " + id + "."
	for _, m := range rep.Mechanisms {
		if m.ID == id && m.Egress == "proxy" {
			text += " The proxied runner allows only api.anthropic.com by default; add hosts with " +
				"ALLOW=\"--allow api.anthropic.com --allow github.com\", or discover them first with " +
				"`sandboxcheckr proxy --observe`."
		}
	}
	fmt.Fprintf(w, "    %s%s%s\n", c.dim, wrap(text, width-4, "    "), c.reset)
}

func matrixLegend() string {
	return symPass + " stops = attempt refused.  " + symFail + " OPEN = it worked, so untrusted code could " +
		"do this.  ? unsure = could not tell (e.g. a timeout); never counted as protection.  n/a = nothing " +
		"to test on this machine.  Use --verbose for the detail behind every cell, or --json."
}

func shortName(id string) string {
	for _, p := range []string{"seatbelt-", "bubblewrap-"} {
		if strings.HasPrefix(id, p) {
			return strings.TrimPrefix(id, p)
		}
	}
	return id
}

func scoreColor(c colors, score int) string {
	switch {
	case score >= 80:
		return c.green
	case score >= 50:
		return c.yellow
	default:
		return c.red
	}
}

// writeAgentSandboxes reports sandboxes other agent tools have installed on this
// host, with the linter's verdict. It runs before MECHANISMS because "you
// already have this sandbox, and here is how good it is" is the most immediately
// useful thing when it applies.
func writeAgentSandboxes(w io.Writer, c colors, sandboxes []model.AgentSandbox) {
	if len(sandboxes) == 0 {
		return
	}
	rule(w, c, "AGENT SANDBOXES ON THIS HOST")
	for _, s := range sandboxes {
		fmt.Fprintf(w, "  %s%s%s  %s%s%s\n", c.bold, s.Tool, c.reset, c.dim, s.Path, c.reset)
		fmt.Fprintf(w, "    egress %s   reads %s\n", egressLabel(c, s.Egress), readsLabel(c, s.ReadsOpen))
		for _, f := range s.Findings {
			fmt.Fprintf(w, "    %s%-6s%s %s\n", sevColor(c, f.Severity),
				strings.ToLower(f.Severity), c.reset, wrap(f.Title, width-12, "           "))
		}
		fmt.Fprintln(w)
	}
}

func egressLabel(c colors, posture string) string {
	switch posture {
	case "open":
		return c.red + "OPEN (bypassable)" + c.reset
	case "proxied":
		return c.green + "proxied (enforced)" + c.reset
	case "denied":
		return c.green + "denied" + c.reset
	default:
		return c.dim + posture + c.reset
	}
}

func readsLabel(c colors, open bool) string {
	if open {
		return c.red + "OPEN" + c.reset
	}
	return c.green + "restricted" + c.reset
}

func writeHeader(w io.Writer, c colors, rep model.Report) {
	host := rep.Host.OS
	if rep.Host.Version != "" {
		host += " " + rep.Host.Version
	}
	fmt.Fprintf(w, "%sSandboxCheckr%s %s   %s%s (%s)%s\n\n",
		c.bold, c.reset, rep.Version, c.dim, host, rep.Host.Arch, c.reset)
}

// writeTrust states up front whether the rest of the report can be believed.
// This precedes the verdict because a reader who acts on findings gathered from
// inside a sandbox will reach the wrong conclusion no matter how good the
// findings look.
func writeTrust(w io.Writer, c colors, sc model.Confinement) {
	if !sc.Confined {
		return
	}
	fmt.Fprintf(w, "%s%s  RESULTS UNRELIABLE — SandboxCheckr is itself sandboxed (%s)%s\n",
		c.yellow, symWarn, sc.Kind, c.reset)
	fmt.Fprintf(w, "   %s\n", wrap(
		"A confined process cannot evaluate sandboxing: the operations required are the ones "+
			"being blocked. Nothing below is evidence that this host lacks confinement. "+
			"Re-run from an unconfined shell.", width-3, "   "))
	for _, e := range sc.Evidence {
		fmt.Fprintf(w, "   %s%s %s%s\n", c.dim, bullet, wrap(e, width-5, "     "), c.reset)
	}
	fmt.Fprintln(w)
}

func rule(w io.Writer, c colors, title string) {
	bar := strings.Repeat(ruleRune, max(0, width-len(title)-4))
	fmt.Fprintf(w, "%s%s%s %s%s%s %s%s\n\n", c.dim, ruleRune+ruleRune, c.reset, c.bold, title, c.reset, c.dim+bar, c.reset)
}

// writeVerdict is the answer, placed where the answer belongs.
func writeVerdict(w io.Writer, c colors, rep model.Report) {
	rule(w, c, "VERDICT")

	byID := map[string]model.MechanismReport{}
	for _, m := range rep.Mechanisms {
		byID[m.ID] = m
	}

	if rep.Recommended == "" {
		if rep.SelfCheck.Confined {
			fmt.Fprintf(w, "  %sInconclusive.%s Could not evaluate this host from inside a sandbox.\n\n",
				c.yellow, c.reset)
			return
		}
		fmt.Fprintf(w, "  %sNo usable confinement found.%s Running untrusted code here exposes the\n"+
			"  full authority of your account.\n\n", c.red, c.reset)
		return
	}

	row := func(label, id, score, egress string, sc int) {
		fmt.Fprintf(w, "  %-15s %s%-20s%s %s %s  %s%s%s\n",
			label, c.bold, id, c.reset, scoreBar(c, sc), score, c.dim, egress, c.reset)
	}
	egressWord := map[string]string{"none": "no network", "proxy": "allow-listed network", "open": "unrestricted network"}

	// The baseline first: the score only means something next to what you
	// have today.
	if b := rep.Baseline; b != nil && len(b.Probes) > 0 {
		row("today", "no sandbox", scoreText(c, b.Score), "everything open", b.Score)
	}
	if m, ok := byID[rep.Recommended]; ok {
		row("strongest", m.ID, scoreText(c, m.Score), egressWord[m.Egress], m.Score)
	}
	if m, ok := byID[rep.RecommendedNetwork]; ok && rep.RecommendedNetwork != rep.Recommended {
		row("with network", m.ID, scoreText(c, m.Score), egressWord[m.Egress], m.Score)
	}
	fmt.Fprintln(w)

	if rep.RecommendedNetwork == "" {
		fmt.Fprintf(w, "  %s%s No configuration permits network access — a coding agent cannot\n"+
			"     run under any of these.%s\n\n", c.yellow, symWarn, c.reset)
	}
}

// writePosture prints one line per finding, expanding only what needs
// attention. Sorted worst-first so a problem is never below the fold.
func writePosture(w io.Writer, c colors, findings []model.PostureFinding, verbose bool) {
	if len(findings) == 0 {
		return
	}
	rule(w, c, "HOST POSTURE")

	sorted := append([]model.PostureFinding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Status) < severityRank(sorted[j].Status)
	})

	for _, f := range sorted {
		g, col := glyph(c, f.Status)
		fmt.Fprintf(w, "  %s%s%s %-32s %s%s%s\n",
			col, g, c.reset, f.Name, col, f.Value, c.reset)

		// A passing check does not need a paragraph. Problems do.
		if f.Impact != "" && (verbose || f.Status != model.StatusPass) {
			fmt.Fprintf(w, "      %s%s%s\n", c.dim, wrap(f.Impact, width-6, "      "), c.reset)
		}
		if verbose && f.Raw != "" {
			fmt.Fprintf(w, "      %sraw: %s%s\n", c.dim, f.Raw, c.reset)
		}
	}
	fmt.Fprintln(w)
}

// writeBaseline shows what a program can do with no sandbox at all — the
// situation most agents are actually run in. Shown in --verbose; the default
// view puts it as the first column of the comparison table.
func writeBaseline(w io.Writer, c colors, rep model.Report) {
	b := rep.Baseline
	if b == nil {
		return
	}
	title := "WITHOUT A SANDBOX"
	if rep.SelfCheck.Confined {
		// We are inside someone else's sandbox, so "unsandboxed" here means
		// "under whatever is already confining this shell".
		title = "INSIDE THE SANDBOX THIS SHELL ALREADY RUNS IN"
	}
	rule(w, c, title)
	from := "this shell"
	if rep.LaunchedFrom != nil && rep.LaunchedFrom.Name != "" {
		from = rep.LaunchedFrom.Name
	}
	intro := "What any program started directly from " + from + " can do — including a coding agent you " +
		"run without a wrapper. It inherits your environment, your files, and every privacy grant " + from + " holds."
	if rep.SelfCheck.Confined {
		intro = "What a program started from this shell can do under the sandbox it is already in. " +
			"This measures that existing sandbox, not this host."
	}
	fmt.Fprintf(w, "  %s%s%s\n\n", c.dim, wrap(intro, width-2, "  "), c.reset)
	if len(b.Probes) > 0 {
		fmt.Fprintf(w, "  %s%-44s%s %s %s\n", c.bold, "containment", c.reset, scoreBar(c, b.Score), scoreText(c, b.Score))
		writeProbes(w, c, b.Probes)
	}
	for _, n := range b.Notes {
		fmt.Fprintf(w, "      %s%s %s%s\n", c.dim, bullet, wrap(n, width-8, "        "), c.reset)
	}
	fmt.Fprintln(w)
}

func writeMechanisms(w io.Writer, c colors, rep model.Report, verbose bool) {
	rule(w, c, "MECHANISMS")
	if len(rep.Mechanisms) == 0 {
		fmt.Fprintf(w, "  %s(none implemented for %s yet)%s\n\n", c.dim, rep.Host.OS, c.reset)
		return
	}

	for _, m := range rep.Mechanisms {
		g, col := glyph(c, m.Availability.Status)
		fmt.Fprintf(w, "  %s%s%s %s%-44s%s", col, g, c.reset, c.bold, m.ID, c.reset)
		if len(m.Probes) > 0 {
			fmt.Fprintf(w, " %s %s", scoreBar(c, m.Score), scoreText(c, m.Score))
		} else {
			fmt.Fprintf(w, " %s%s%s", col, strings.ToLower(string(m.Availability.Status)), c.reset)
		}
		fmt.Fprintln(w)

		if m.Availability.Status != model.StatusPass && m.Availability.Detail != "" {
			fmt.Fprintf(w, "      %s%s%s\n", c.dim, wrap(m.Availability.Detail, width-6, "      "), c.reset)
		}
		if verbose {
			fmt.Fprintf(w, "      %s%s%s\n", c.dim, wrap(m.Summary, width-6, "      "), c.reset)
		}
		for _, n := range m.Notes {
			fmt.Fprintf(w, "      %s%s %s%s\n", c.dim, bullet, wrap(n, width-8, "        "), c.reset)
		}
		if len(m.Probes) > 0 {
			writeProbes(w, c, m.Probes)
		}
		if len(m.PeerChannels) > 0 {
			writePeerChannels(w, c, m.PeerChannels)
		}
		fmt.Fprintln(w)
	}
}

// writeProbes groups results by outcome rather than listing every probe with
// equal weight. Contained probes only need their names; exposures need the
// sentence explaining what is actually at risk.
func writeProbes(w io.Writer, c colors, probes []model.ProbeResult) {
	var contained, exposed, unverified, na, info []model.ProbeResult
	var control *model.ProbeResult
	var canary *model.ProbeResult

	for _, p := range probes {
		// The positive control is reported on its own line. It wants ALLOWED,
		// so grouping it with the containment probes would label a successful
		// write as "contained" — the exact opposite of what happened.
		if p.ID == model.ProbeFSWriteAllowed {
			pc := p
			control = &pc
			continue
		}
		if p.ID == model.ProbeProxyControl {
			if !p.OK() {
				exposed = append(exposed, p)
			}
			continue
		}
		if p.ID == model.ProbeCanaryDetection {
			cp := p
			canary = &cp
			continue
		}
		switch {
		case p.ID == model.ProbeProcExec:
			// Informational and unscored: a coding agent must be able to run
			// commands, so this is context, not an exposure.
			info = append(info, p)
		case p.Verdict == model.VerdictSkipped:
			na = append(na, p)
		case p.Verdict == model.VerdictErrored:
			unverified = append(unverified, p)
		case p.OK():
			contained = append(contained, p)
		default:
			exposed = append(exposed, p)
		}
	}

	if control != nil {
		if control.OK() {
			fmt.Fprintf(w, "      %susable%s      the workdir is writable, so a program can still work\n",
				c.green, c.reset)
		} else {
			fmt.Fprintf(w, "      %sUNUSABLE%s    %s\n", c.red, c.reset,
				wrap("cannot write inside the permitted workdir; this sandbox would break "+
					"the program you want to run", width-18, "                  "))
		}
	}
	if canary != nil {
		if canary.Verdict == model.VerdictAllowed {
			fmt.Fprintf(w, "      %sverified%s    canary.detection: the proxy recorded and denied the deliberate trip\n", c.green, c.reset)
		} else {
			fmt.Fprintf(w, "      %sunverified%s  canary.detection: %s\n", c.yellow, c.reset, canary.Detail)
		}
	}

	names := func(rs []model.ProbeResult) string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = string(r.ID)
		}
		return strings.Join(out, ", ")
	}

	if len(contained) > 0 {
		fmt.Fprintf(w, "      %scontained%s   %s\n", c.green, c.reset,
			wrap(names(contained), width-18, "                  "))
	}
	for _, p := range exposed {
		fmt.Fprintf(w, "      %sEXPOSED%s     %s%s%s %s(%s)%s\n", c.red, c.reset, c.bold, p.ID.Label(), c.reset, c.dim, p.ID, c.reset)
		fmt.Fprintf(w, "                  %s%s%s\n", c.dim, wrap(p.Detail, width-18, "                  "), c.reset)
	}
	for _, p := range unverified {
		fmt.Fprintf(w, "      %sunverified%s  %s %s(%s)%s\n", c.yellow, c.reset, p.ID.Label(), c.dim, p.ID, c.reset)
		fmt.Fprintf(w, "                  %s%s%s\n", c.dim, wrap(p.Detail, width-18, "                  "), c.reset)
	}
	if len(na) > 0 {
		fmt.Fprintf(w, "      %sn/a         %s%s\n", c.dim, names(na), c.reset)
	}
	for _, p := range info {
		fmt.Fprintf(w, "      %sinfo        %s: %s%s\n", c.dim, p.ID, p.Detail, c.reset)
	}
}

// writePeerChannels reports whether two processes confined by this mechanism
// could still reach each other.
//
// Kept visually distinct from the probe list because it answers a different
// question. The battery asks whether one process is contained from the host;
// this asks whether two are contained from each other, and a mechanism can
// score perfectly on the first while failing the second completely.
func writePeerChannels(w io.Writer, c colors, channels []model.PeerChannel) {
	var carried, isolated, untested []model.PeerChannel
	for _, ch := range channels {
		switch {
		case ch.Carried:
			carried = append(carried, ch)
		case ch.Inconclusive:
			// Never fold these in with isolated: "we could not test it" is not
			// "it is closed", and presenting them together would overstate
			// containment in exactly the way this tool exists to avoid.
			untested = append(untested, ch)
		default:
			isolated = append(isolated, ch)
		}
	}
	ids := func(cs []model.PeerChannel) string {
		out := make([]string, len(cs))
		for i, ch := range cs {
			out[i] = ch.ID
		}
		return strings.Join(out, "  ")
	}

	for _, ch := range carried {
		fmt.Fprintf(w, "      %sPEER LEAK%s   %s%s%s\n", c.red, c.reset, c.bold, ch.Name, c.reset)
		fmt.Fprintf(w, "                  %s%s%s\n", c.dim, wrap(ch.Detail, width-18, "                  "), c.reset)
	}
	if len(isolated) > 0 {
		fmt.Fprintf(w, "      %speers%s       isolated: %s\n", c.green, c.reset, ids(isolated))
	}
	if len(untested) > 0 {
		fmt.Fprintf(w, "      %speers%s       %suntested (not isolation): %s%s\n",
			c.yellow, c.reset, c.dim, ids(untested), c.reset)
	}
}

func writeGapsSection(w io.Writer, c colors, gaps []model.Gap, verbose bool) {
	var found, limits []model.Gap
	for _, g := range gaps {
		if g.Source == "documented" {
			limits = append(limits, g)
		} else {
			found = append(found, g)
		}
	}
	rule(w, c, "WHAT THIS STILL DOES NOT PROTECT AGAINST")
	if len(found) > 0 || len(limits) == 0 {
		writeGaps(w, c, found)
	}
	if len(limits) == 0 {
		return
	}
	if verbose {
		fmt.Fprintf(w, "  %sKnown limits of this mechanism:%s\n\n", c.bold, c.reset)
		writeGaps(w, c, limits)
		return
	}
	// Documented limits are true on every run and identical every time, so
	// after the first read they are noise. Titles only; --verbose expands.
	fmt.Fprintf(w, "  %sKnown limits of this mechanism (--verbose for detail):%s\n", c.bold, c.reset)
	sort.SliceStable(limits, func(i, j int) bool { return sevRank(limits[i].Severity) < sevRank(limits[j].Severity) })
	for _, g := range limits {
		fmt.Fprintf(w, "  %s%-6s%s %s\n", sevColor(c, g.Severity), strings.ToLower(g.Severity), c.reset,
			wrap(g.Title, width-10, "         "))
	}
	fmt.Fprintln(w)
}

func writeGaps(w io.Writer, c colors, gaps []model.Gap) {
	if len(gaps) == 0 {
		fmt.Fprintf(w, "  %s(nothing recorded)%s\n", c.dim, c.reset)
		return
	}
	sorted := append([]model.Gap(nil), gaps...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sevRank(sorted[i].Severity) < sevRank(sorted[j].Severity)
	})
	for _, g := range sorted {
		fmt.Fprintf(w, "  %s%-6s%s %s\n", sevColor(c, g.Severity),
			strings.ToLower(g.Severity), c.reset, wrap(g.Title, width-10, "         "))
		fmt.Fprintf(w, "         %s%s%s\n", c.dim, wrap(g.Detail, width-9, "         "), c.reset)
		if g.Fix != "" {
			fmt.Fprintf(w, "         %sfix: $ %s%s\n", c.blue, g.Fix, c.reset)
		}
		fmt.Fprintln(w)
	}
}

// scoreBar renders containment as a ten-cell bar. A number alone makes the
// reader do the comparison; a bar makes two options comparable at a glance.
func scoreBar(c colors, score int) string {
	filled := score / 10
	if score > 0 && filled == 0 {
		filled = 1
	}
	col := c.red
	switch {
	case score >= 80:
		col = c.green
	case score >= 50:
		col = c.yellow
	}
	if filled >= 10 {
		return col + strings.Repeat(barFill, 10) + c.reset
	}
	return col + strings.Repeat(barFill, filled) + c.dim + strings.Repeat(barEmpty, 10-filled) + c.reset
}

func scoreText(c colors, score int) string {
	return fmt.Sprintf("%s%3d/100%s", c.dim, score, c.reset)
}

// Glyph set. Defaults to Unicode; applyGlyphs swaps in ASCII equivalents for
// terminals that cannot render check marks and box drawing. These are
// package-level so the many small render helpers can read them without a theme
// threaded through every signature — acceptable because a run renders exactly
// one report, and applyGlyphs resets them at the top of every Terminal call so
// no state leaks between renders.
var (
	symPass  = "✓"
	symWarn  = "▲"
	symFail  = "✗"
	symUnk   = "?"
	symNone  = "·"
	bullet   = "·"
	barFill  = "█"
	barEmpty = "░"
	ruleRune = "─"
)

// applyGlyphs selects the Unicode or ASCII glyph set. The ASCII forms are all
// single display cells so column alignment is preserved either way.
func applyGlyphs(ascii bool) {
	if ascii {
		symPass, symWarn, symFail, symUnk, symNone = "+", "!", "x", "?", "."
		bullet = "-"
		barFill, barEmpty, ruleRune = "#", ".", "-"
		return
	}
	symPass, symWarn, symFail, symUnk, symNone = "✓", "▲", "✗", "?", "·"
	bullet = "·"
	barFill, barEmpty, ruleRune = "█", "░", "─"
}

func glyph(c colors, s model.Status) (string, string) {
	switch s {
	case model.StatusPass:
		return symPass, c.green
	case model.StatusFail:
		return symFail, c.red
	case model.StatusDegraded:
		return symWarn, c.yellow
	case model.StatusIndeterminate:
		return symUnk, c.yellow
	default:
		return symNone, c.dim
	}
}

// severityRank orders findings worst-first so problems surface.
func severityRank(s model.Status) int {
	switch s {
	case model.StatusFail:
		return 0
	case model.StatusDegraded:
		return 1
	case model.StatusIndeterminate:
		return 2
	case model.StatusAbsent:
		return 3
	default:
		return 4
	}
}

func sevRank(sev string) int {
	switch strings.ToLower(sev) {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func sevColor(c colors, sev string) string {
	switch strings.ToLower(sev) {
	case "high":
		return c.red
	case "medium":
		return c.yellow
	default:
		return c.dim
	}
}

// wrap hard-wraps text, indenting continuation lines so multi-line values stay
// aligned under their column.
func wrap(s string, w int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, word := range words {
		if line > 0 && line+1+len(word) > w {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 && line > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(word)
		line += len(word)
	}
	return b.String()
}

type colors struct {
	bold, dim, red, green, yellow, blue, reset string
}

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{
		bold:   "\x1b[1m",
		dim:    "\x1b[2m",
		red:    "\x1b[31m",
		green:  "\x1b[32m",
		yellow: "\x1b[33m",
		blue:   "\x1b[36m",
		reset:  "\x1b[0m",
	}
}
