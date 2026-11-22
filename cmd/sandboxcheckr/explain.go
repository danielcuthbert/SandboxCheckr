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

// isRoutineDenial reports whether the refusal is on the innocent list.
func isRoutineDenial(op, target string) bool {
	for _, r := range routineDenials {
		if op == r.op && strings.HasPrefix(target, r.targetPrefix) {
			return true
		}
	}
	return false
}

// aggregateDenials collapses parsed lines into distinct refusals, counted, most
// refused first so the thing that stopped the program is at the top.
func aggregateDenials(lines []string, procName string) (shown []denial, hidden int) {
	counts := map[string]int{}
	order := []string{}
	for _, line := range lines {
		op, target, ok := parseDenialLine(line, procName)
		if !ok {
			continue
		}
		if isRoutineDenial(op, target) {
			hidden++
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
		return shown[i].op < shown[j].op
	})
	return shown, hidden
}

// adviceFor says something only where the answer is known. A guess in this
// column costs more than an empty one: the reader cannot tell them apart.
func adviceFor(op, target string) string {
	switch {
	case op == "file-ioctl" && strings.HasPrefix(target, "/dev/"):
		return "terminal control; this run did not inherit that device"
	case (op == "network-outbound" || op == "network-bind") &&
		(strings.HasSuffix(target, ".sock") || strings.HasPrefix(target, "/private/var/run/")):
		return "unix socket, refused by design"
	case op == "system-socket":
		return "socket family the profile refuses"
	case strings.HasPrefix(op, "file-write") && strings.HasPrefix(target, "/"):
		return "outside the workdir; add --rw <dir>"
	case strings.HasPrefix(op, "file-read") && strings.HasPrefix(target, "/"):
		return "outside the workdir; add --ro <dir>"
	}
	return ""
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
// the runner prints, so the two read as one summary: columns wide enough for
// their longest entry, counts right-aligned, advice last.
func formatDenials(ds []denial, hidden int, procName string, since, until time.Time) string {
	const stamp = "15:04:05"
	var b strings.Builder
	fmt.Fprintf(&b, "── refused by the sandbox (kernel log, %s, %s to %s) ──\n",
		procName, since.Local().Format(stamp), until.Local().Format(stamp))
	if len(ds) == 0 {
		b.WriteString("  nothing was refused for " + procName + " in this window.\n")
		b.WriteString("  So the failure is not the sandbox: look at what the program printed.\n")
		return b.String()
	}
	opW, targetW, countW := displayWidth("operation"), displayWidth("target"), displayWidth("count")
	targets := make([]string, len(ds))
	counts := make([]string, len(ds))
	for i, d := range ds {
		if n := displayWidth(d.op); n > opW {
			opW = n
		}
		targets[i] = truncTarget(d.target)
		if targets[i] == "" {
			targets[i] = "(no target)"
		}
		if n := displayWidth(targets[i]); n > targetW {
			targetW = n
		}
		counts[i] = fmt.Sprintf("%d", d.count)
		if n := displayWidth(counts[i]); n > countW {
			countW = n
		}
	}
	const gap = "  "
	b.WriteString("  " + padRight("operation", opW) + gap + padRight("target", targetW) + gap + padLeft("count", countW) + "\n")
	for i, d := range ds {
		line := "  " + padRight(d.op, opW) + gap + padRight(targets[i], targetW) + gap + padLeft(counts[i], countW)
		if why := adviceFor(d.op, d.target); why != "" {
			line += gap + why
		}
		b.WriteString(line + "\n")
	}
	if hidden > 0 {
		fmt.Fprintf(&b, "  %d routine refusal%s hidden: %s\n",
			hidden, plural(hidden), routineDenials[0].why)
	}
	return b.String()
}

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
func printRunExplain(w io.Writer, commandName string, since, until time.Time) {
	procName := commandName
	if !safeProcessName.MatchString(procName) {
		fmt.Fprintf(w, "note: --explain cannot search the kernel log for a process named %q\n", procName)
		return
	}
	lines, err := queryKernelLog(procName, since, until)
	switch {
	case errors.Is(err, errExplainUnsupported):
		fmt.Fprintln(w, "note: --explain reads the macOS kernel log. The Linux sandbox refuses in a")
		fmt.Fprintln(w, "  namespace and seccomp filter that log nothing, so the program just gets EPERM;")
		fmt.Fprintln(w, "  the proxy's table above is what this platform can tell you.")
		return
	case err != nil:
		fmt.Fprintln(w, "note: could not read the kernel log:", err)
		return
	}
	ds, hidden := aggregateDenials(lines, procName)
	fmt.Fprint(w, formatDenials(ds, hidden, procName, since, until))
}
