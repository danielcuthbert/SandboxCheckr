package main

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
)

// The egress proxy sees destinations. It cannot see the refusals that stop a
// program before it reaches the network: an ioctl on the terminal, a write
// outside the workdir, a connect to a unix socket. Those are decided by the
// sandbox itself, and on macOS the kernel writes them to the unified log, which
// is where --explain looks. The parse and the report live here so they can be
// tested everywhere; the log query itself is in explain_darwin.go.

// explainWindowCap bounds how far back the log query reaches. A long-running
// agent produces a log the tool would spend minutes searching, and the refusals
// that matter are the ones near the start and the failure.
const explainWindowCap = 900

// errExplainUnsupported is returned by platforms whose sandbox says nothing.
var errExplainUnsupported = errors.New("unsupported")

// safeProcessName guards the log predicate. A command name goes into a quoted
// predicate string, so anything but an ordinary executable name is refused.
var safeProcessName = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// denial is one distinct refusal, counted over the run.
type denial struct {
	op     string
	target string
	count  int
}

// routineDenials are refusals we have watched a real program shrug off. They are
// counted and hidden rather than dropped, so the number stays in the report.
// Each entry needs a run behind it: an innocent list without evidence teaches
// people to stop reading the table.
var routineDenials = []struct {
	op, targetPrefix, why string
}{
	// codex under SandboxCheckr on 2026-11-22: denying this changed nothing,
	// and the A/B run that found the terminal ioctl died with it refused too.
	{"user-preference-read", "com.apple.universalaccess", "the VoiceOver check most programs ignore"},
	// Same run, 14 reads refused and codex carried on to finish the session.
	{"user-preference-read", "kcfpreferencesanyapplication", "a preference sweep every program makes"},
	{"user-preference-read", "com.apple.security", "a preference read about the keychain, not the keychain itself"},
}

// parseDenialLine turns one unified-log line into an operation and a target.
// The lines are written by sandboxd, not by us, and look like:
//
//	Sandbox: codex(18451) deny(1) user-preference-read com.apple.universalaccess
//	Sandbox: codex(18451) deny(1) file-ioctl path:/dev/ttys003 ioctl-command:(0x540d 'TIOCSETA' { length: 128 })
//	Sandbox: codex(19463) deny(1) network-outbound /private/var/run/mDNSResponder
//	Sandbox: codex(21071) deny(1) file-write-create deny file-mode-mask (path:file-write-create /Users/d/.cache/x.txt (mode:0100644))
//
// Anything else, including the allow counterpart and lines about other
// processes, is rejected.
func parseDenialLine(line, procName string) (op, target string, ok bool) {
	i := strings.Index(line, "Sandbox: ")
	if i < 0 || !safeProcessName.MatchString(procName) {
		return "", "", false
	}
	rest := strings.TrimSpace(line[i+len("Sandbox: "):])
	open := strings.IndexByte(rest, '(')
	// The name is followed by (pid); a longer name that merely starts with the
	// command (codex vs codex-helper) is a different process.
	if open <= 0 || rest[:open] != procName {
		return "", "", false
	}
	end := strings.IndexByte(rest[open:], ')')
	if end < 0 {
		return "", "", false
	}
	rest = strings.TrimSpace(rest[open+end+1:])
	if !strings.HasPrefix(rest, "deny") {
		return "", "", false
	}
	rest = rest[len("deny"):]
	if strings.HasPrefix(rest, "(") {
		stop := strings.IndexByte(rest, ')')
		if stop < 0 {
			return "", "", false
		}
		rest = strings.TrimSpace(rest[stop+1:])
	}
	fields := strings.SplitN(rest, " ", 2)
	op = fields[0]
	if op == "" {
		return "", "", false
	}
	target = ""
	if len(fields) > 1 {
		target = cleanDenialTarget(fields[1])
	}
	return op, target, true
}

// cleanDenialTarget pulls the interesting thing out of the text after the
// operation. Kernel messages wrap paths in "path:" and in "deny file-mode-mask
// (path:file-write-create /abs (mode:...))", so the absolute path is what
// survives; anything else keeps its first token.
func cleanDenialTarget(s string) string {
	s = strings.TrimSpace(s)
	if j := strings.Index(s, " /"); j >= 0 {
		s = s[j+1:]
	}
	s = strings.TrimPrefix(s, "path:")
	if strings.HasPrefix(s, "/") {
		if j := strings.IndexByte(s, ' '); j > 0 {
			s = s[:j]
		}
	}
	if j := strings.IndexByte(s, ')'); j >= 0 {
		s = s[:j]
	}
	return strings.TrimRight(s, " ,.")
}

// routineWhy returns why a refusal is treated as background noise, or "" when
// it is not on the innocent list.
func routineWhy(op, target string) string {
	for _, r := range routineDenials {
		if op == r.op && strings.HasPrefix(target, r.targetPrefix) {
			return r.why
		}
	}
	return ""
}

// aggregateDenials collapses parsed lines into distinct refusals, counted, most
// refused first so the thing that stopped the program is at the top. The second
// result is why each routine refusal was folded away, one entry per line.
func aggregateDenials(lines []string, procName string) (shown []denial, hidden []string) {
	counts := map[string]int{}
	order := []string{}
	for _, line := range lines {
		op, target, ok := parseDenialLine(line, procName)
		if !ok {
			continue
		}
		if why := routineWhy(op, target); why != "" {
			hidden = append(hidden, why)
			continue
		}
		key := op + "\x00" + target
		if counts[key] == 0 {
			order = append(order, key)
		}
		counts[key]++
	}
	for _, key := range order {
		parts := strings.SplitN(key, "\x00", 2)
		shown = append(shown, denial{op: parts[0], target: parts[1], count: counts[key]})
	}
	sort.SliceStable(shown, func(i, j int) bool {
		if shown[i].count != shown[j].count {
			return shown[i].count > shown[j].count
		}
		if shown[i].op != shown[j].op {
			return shown[i].op < shown[j].op
		}
		// Same count and operation: order the targets so rows that differ only
		// in path sit together and read as one block.
		return shown[i].target < shown[j].target
	})
	return shown, hidden
}

// noteLevel says how a refusal should read: a grant you can add, something the
// profile refuses on purpose, or something with nothing sensible to say about it.
type noteLevel int

const (
	notePlain noteLevel = iota
	noteAction
	noteExpected
)

// adviceFor says something only where the answer is known. A guess in this
// column costs more than an empty one: the reader cannot tell them apart.
func adviceFor(op, target string) (string, noteLevel) {
	switch {
	case op == "file-ioctl" && strings.HasPrefix(target, "/dev/"):
		return "terminal control; this run did not inherit that device", notePlain
	case (op == "network-outbound" || op == "network-bind") &&
		(strings.HasSuffix(target, ".sock") || strings.HasPrefix(target, "/private/var/run/")):
		return "unix socket, refused by design", noteExpected
	case op == "system-socket":
		return "socket family the profile refuses", noteExpected
	case op == "network-bind":
		return "a listener; only the proxy's own port may bind", noteExpected
	case strings.HasPrefix(op, "file-write") && strings.HasPrefix(target, "/"):
		return "outside the workdir; add --rw <dir>", noteAction
	case strings.HasPrefix(op, "file-read") && strings.HasPrefix(target, "/"):
		return "outside the workdir; add --ro <dir>", noteAction
	}
	return "", notePlain
}

// truncTarget keeps a long path readable by its tail, which is the part that
// names the file. Widths are counted in runes: the ellipsis is one column on
// screen and three bytes in the string, and a table padded by bytes drifts.
func truncTarget(s string) string {
	const keep = 48
	r := []rune(s)
	if len(r) <= keep {
		return s
	}
	return "…" + string(r[len(r)-(keep-1):])
}

// displayWidth counts columns, not bytes.
func displayWidth(s string) int { return utf8.RuneCountInString(s) }

func padRight(s string, width int) string {
	if n := width - displayWidth(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

func padLeft(s string, width int) string {
	if n := width - displayWidth(s); n > 0 {
		return strings.Repeat(" ", n) + s
	}
	return s
}

// formatDenials is the report. It matches the shape of the destination table
// the runner prints, so the two read as one summary: a counted column on the
// left so the rows rank, target and note columns wide enough for their longest
// entry, and the last thing on a line never padded, so nothing ragged reaches
// the margin. Colour goes around whole fields, and widths are measured on the
// plain text, so escape sequences cannot shift a column.
func formatDenials(ds []denial, hidden []string, procName string, since, until time.Time, st emit.Styles) string {
	const stamp = "15:04:05"
	dim, yellow, green := st.Dim, st.Yellow, st.Green
	var b strings.Builder
	b.WriteString("\n")
	head := "── refused by the sandbox (kernel log, " + procName + ", " +
		since.Local().Format(stamp) + " to " + until.Local().Format(stamp) + ") ──"
	b.WriteString(dim + head + st.Reset + "\n")
	if len(ds) == 0 {
		b.WriteString(green + "  nothing was refused for " + procName + " in this window." + st.Reset + "\n")
		b.WriteString(dim + "  So the failure is not the sandbox: look at what the program printed." + st.Reset + "\n")
		return b.String()
	}
	dropped := 0
	if len(ds) > maxExplainRows {
		dropped = len(ds) - maxExplainRows
		ds = ds[:maxExplainRows]
	}
	// Widths in runes, counted once on the plain text, so every row lines up
	// without a second pass and colour cannot disturb them.
	countW, opW, targetW := displayWidth("count"), displayWidth("operation"), displayWidth("target")
	targets := make([]string, len(ds))
	counts := make([]string, len(ds))
	notes := make([]string, len(ds))
	levels := make([]noteLevel, len(ds))
	for i, d := range ds {
		counts[i] = fmt.Sprintf("%d", d.count)
		countW = max(countW, displayWidth(counts[i]))
		opW = max(opW, displayWidth(d.op))
		targets[i] = truncTarget(d.target)
		if targets[i] == "" {
			targets[i] = "(no target)"
		}
		targetW = max(targetW, displayWidth(targets[i]))
		notes[i], levels[i] = adviceFor(d.op, d.target)
	}
	const gap = "  "
	writeRow := func(rowStyle, count, op, target, note, noteStyle string) {
		b.WriteString("  " + rowStyle + padLeft(count, countW) + gap + padRight(op, opW) + gap)
		if note == "" {
			b.WriteString(target)
		} else {
			b.WriteString(padRight(target, targetW) + gap + noteStyle + note)
		}
		if rowStyle != "" || (note != "" && noteStyle != "") {
			b.WriteString(st.Reset)
		}
		b.WriteString("\n")
	}
	writeRow(dim, "count", "operation", "target", "notes", "")
	prevNote := ""
	for i, d := range ds {
		// A note repeated under the same operation reads as clutter; once is
		// enough to say what to do about the whole run of rows.
		note := notes[i]
		if i > 0 && note != "" && note == prevNote && d.op == ds[i-1].op {
			note = ""
		}
		prevNote = notes[i]
		// Yellow for something a flag can fix, dim for a refusal the profile
		// makes on purpose, so the rows worth reading stand out without a legend.
		rowStyle, noteStyle := "", ""
		switch levels[i] {
		case noteAction:
			noteStyle = yellow
		case noteExpected:
			rowStyle = dim
		}
		writeRow(rowStyle, counts[i], d.op, targets[i], note, noteStyle)
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "%s  and %d more, least refused first%s\n", dim, dropped, st.Reset)
	}
	if n := len(hidden); n > 0 {
		// Say what was folded away and how much of it, so anyone who disagrees
		// with the innocent list can check the count against it.
		fmt.Fprintf(&b, "%s  %d routine refusal%s hidden: %s%s\n",
			dim, n, plural(n), summariseReasons(hidden), st.Reset)
	}
	return b.String()
}

// summariseReasons collapses the reasons routine refusals were hidden for into
// "14 why; 1 why", most frequent first.
func summariseReasons(reasons []string) string {
	counts := map[string]int{}
	for _, r := range reasons {
		counts[r]++
	}
	distinct := unique(reasons)
	sort.SliceStable(distinct, func(i, j int) bool { return counts[distinct[i]] > counts[distinct[j]] })
	parts := make([]string, 0, len(distinct))
	for _, r := range distinct {
		parts = append(parts, fmt.Sprintf("%d %s", counts[r], r))
	}
	return strings.Join(parts, "; ")
}

// maxExplainRows bounds the table. Past this the tail is rarer than what is
// already listed, and the summary has outstayed its welcome under the run.
const maxExplainRows = 20

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// queryKernelLog is the log query, a variable so the report can be tested on a
// platform that has no unified log.
var queryKernelLog = kernelLogDenials

// printRunExplain reports what the sandbox refused during the run. It runs
// after the child has exited and after the proxy's own summary, so it is the
// last thing a failed run prints.
func printRunExplain(w io.Writer, commandName string, since, until time.Time, st emit.Styles) {
	// Whatever follows the proxy's own summary needs a line to itself first.
	note := func(format string, args ...any) {
		fmt.Fprint(w, "\n")
		// Each line carries its own pair of escapes rather than one span over
		// the paragraph, so a terminal that resets mid-scroll cannot leak colour
		// into whatever the shell prints next.
		for _, line := range strings.Split(fmt.Sprintf(format, args...), "\n") {
			fmt.Fprintf(w, "%s%s%s\n", st.Dim, line, st.Reset)
		}
	}
	procName := commandName
	if !safeProcessName.MatchString(procName) {
		note("cannot search the kernel log for a process named %q; a name has to be a plain executable name", procName)
		return
	}
	lines, err := queryKernelLog(procName, since, until)
	switch {
	case errors.Is(err, errExplainUnsupported):
		note("%s", "--explain reads the macOS kernel log, and the Linux sandbox has none: bubblewrap\n"+
			"  refuses inside a namespace and a seccomp filter that log nothing, so the program\n"+
			"  simply gets EPERM. The proxy's table above is what this platform can tell you.")
		return
	case err != nil:
		note("could not read the kernel log: %v", err)
		return
	}
	ds, hidden := aggregateDenials(lines, procName)
	fmt.Fprint(w, formatDenials(ds, hidden, procName, since, until, st))
}
