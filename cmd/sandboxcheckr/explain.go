package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielcuthbert/sandboxcheckr/internal/denials"
	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
	"github.com/danielcuthbert/sandboxcheckr/internal/events"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
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

// denial is one distinct refusal, counted over the run. proc is empty for the
// program --explain was asked about and set for a refusal logged against another
// process in the same window, which the sandbox confined just as hard.
type denial struct {
	proc   string
	op     string
	target string
	count  int
}

// routineDenials are refusals we have watched a real program shrug off. They are
// counted and hidden rather than dropped, so the number stays in the report.
// Each entry needs a run behind it: an innocent list without evidence teaches
// people to stop reading the table. An empty operation matches that target under
// any operation, for the paths the kernel logs two ways.
var routineDenials = []struct {
	op, targetPrefix, why string
}{
	// codex under SandboxCheckr on 2026-11-22: denying this changed nothing,
	// and the A/B run that found the terminal ioctl died with it refused too.
	{"user-preference-read", "com.apple.universalaccess", "the VoiceOver check most programs ignore"},
	// Same run, 14 reads refused and codex carried on to finish the session.
	{"user-preference-read", "kcfpreferencesanyapplication", "a preference sweep every program makes"},
	{"user-preference-read", "com.apple.security", "a preference read about the keychain, not the keychain itself"},
	// raptor under SandboxCheckr on 2026-11-22: 60 of these from six helper
	// processes, and the script ran on to the refusal that mattered.
	{"file-ioctl", "/dev/dtracehelper", "the probe every linked program touches"},
	// Same window: python asked four times and imported anyway. The empty
	// operation matches either shape the kernel logs it in.
	{"", "/dev/autofs_nowait", "the automounter check the C library makes"},
}

// parseDenialLine turns one unified-log line into a process, an operation and a
// target. The lines are written by sandboxd, not by us, and look like:
//
//	Sandbox: codex(18451) deny(1) user-preference-read com.apple.universalaccess
//	Sandbox: codex(18451) deny(1) file-ioctl path:/dev/ttys003 ioctl-command:(0x540d 'TIOCSETA' { length: 128 })
//	Sandbox: codex(19463) deny(1) network-outbound /private/var/run/mDNSResponder
//	Sandbox: codex(21071) deny(1) file-write-create deny file-mode-mask (path:file-write-create /Users/d/.cache/x.txt (mode:0100644))
//
// Every process the sandbox confined writes lines in this shape, so the name is
// kept rather than matched away: a shell script is logged as bash, and the helper
// that actually asked for the blocked file is logged under its own name.
// Anything else, including the allow counterpart, is rejected.
func parseDenialLine(line string) (proc, op, target string, ok bool) {
	i := strings.Index(line, "Sandbox: ")
	if i < 0 {
		return "", "", "", false
	}
	rest := strings.TrimSpace(line[i+len("Sandbox: "):])
	open := strings.IndexByte(rest, '(')
	// The name is followed by (pid).
	if open <= 0 {
		return "", "", "", false
	}
	proc = rest[:open]
	if !safeProcessName.MatchString(proc) {
		return "", "", "", false
	}
	end := strings.IndexByte(rest[open:], ')')
	if end < 0 {
		return "", "", "", false
	}
	rest = strings.TrimSpace(rest[open+end+1:])
	if !strings.HasPrefix(rest, "deny") {
		return "", "", "", false
	}
	rest = rest[len("deny"):]
	if strings.HasPrefix(rest, "(") {
		stop := strings.IndexByte(rest, ')')
		if stop < 0 {
			return "", "", "", false
		}
		rest = strings.TrimSpace(rest[stop+1:])
	}
	fields := strings.SplitN(rest, " ", 2)
	op = fields[0]
	if op == "" {
		return "", "", "", false
	}
	target = ""
	if len(fields) > 1 {
		target = cleanDenialTarget(fields[1])
	}
	return proc, op, target, true
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
		if (r.op == "" || op == r.op) && strings.HasPrefix(target, r.targetPrefix) {
			return r.why
		}
	}
	return ""
}

// aggregateDenials collapses parsed lines into distinct refusals, counted, most
// refused first so the thing that stopped the program is at the top. Refusals
// logged against the program itself come back first; those logged against any
// other process the sandbox confined in the same window come back separately,
// with the name that was logged, because a run is a tree and the kernel names the
// process that asked. The middle result is why each routine refusal was folded
// away, one entry per line.
func aggregateDenials(lines []string, procName string) (own []denial, hidden []string, others []denial) {
	counts := map[string]int{}
	order := []string{}
	for _, line := range lines {
		proc, op, target, ok := parseDenialLine(line)
		if !ok {
			continue
		}
		if why := routineWhy(op, target); why != "" {
			hidden = append(hidden, why)
			continue
		}
		key := proc + "\x00" + op + "\x00" + target
		if counts[key] == 0 {
			order = append(order, key)
		}
		counts[key]++
	}
	for _, key := range order {
		parts := strings.Split(key, "\x00")
		d := denial{proc: parts[0], op: parts[1], target: parts[2], count: counts[key]}
		if d.proc == procName {
			d.proc = ""
			own = append(own, d)
		} else {
			others = append(others, d)
		}
	}
	byRank := func(ds []denial) func(i, j int) bool {
		return func(i, j int) bool {
			if ds[i].count != ds[j].count {
				return ds[i].count > ds[j].count
			}
			if ds[i].proc != ds[j].proc {
				return ds[i].proc < ds[j].proc
			}
			if ds[i].op != ds[j].op {
				return ds[i].op < ds[j].op
			}
			// Same count, process and operation: order the targets so rows that
			// differ only in path sit together and read as one block.
			return ds[i].target < ds[j].target
		}
	}
	sort.SliceStable(own, byRank(own))
	sort.SliceStable(others, byRank(others))
	return own, hidden, others
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
	// A row carrying a process name means this table is not about the program
	// --explain was asked about but about everything the sandbox confined, which
	// the header has to say: the names a reader sees will not match the one they
	// typed, and silence about that reads as a bug.
	showsProc := false
	for _, d := range ds {
		if d.proc != "" {
			showsProc = true
			break
		}
	}
	scope := procName + ", kernel log, "
	if showsProc {
		// Short enough that the rule still reaches the column width; the
		// sentence under the table says what "all confined" means.
		scope = "kernel log, all confined, "
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(emit.SectionNote(st, st.Dim, runColumns(), "sandbox refusals",
		scope+since.Local().Format(stamp)+" to "+until.Local().Format(stamp)))
	if len(ds) == 0 {
		b.WriteString(green + "  nothing was refused for " + procName + " in this window." + st.Reset + "\n")
		b.WriteString(dim + "  No other confined process was refused either, so the failure is not the" +
			" sandbox: look at what the program printed." + st.Reset + "\n")
		return b.String()
	}
	dropped := 0
	if len(ds) > maxExplainRows {
		dropped = len(ds) - maxExplainRows
		ds = ds[:maxExplainRows]
	}
	// Widths in runes, counted once on the plain text, so every row lines up
	// without a second pass and colour cannot disturb them.
	countW, procW, opW, targetW := displayWidth("count"), displayWidth("process"), displayWidth("operation"), displayWidth("target")
	procs := make([]string, len(ds))
	targets := make([]string, len(ds))
	counts := make([]string, len(ds))
	notes := make([]string, len(ds))
	levels := make([]noteLevel, len(ds))
	for i, d := range ds {
		counts[i] = fmt.Sprintf("%d", d.count)
		countW = max(countW, displayWidth(counts[i]))
		procs[i] = d.proc
		if showsProc {
			procW = max(procW, displayWidth(procs[i]))
		}
		opW = max(opW, displayWidth(d.op))
		targets[i] = truncTarget(d.target)
		if targets[i] == "" {
			targets[i] = "(no target)"
		}
		targetW = max(targetW, displayWidth(targets[i]))
		notes[i], levels[i] = adviceFor(d.op, d.target)
	}
	const gap = "  "
	writeRow := func(rowStyle, count, proc, op, target, note, noteStyle string) {
		head := padLeft(count, countW) + gap
		if showsProc {
			head += padRight(proc, procW) + gap
		}
		b.WriteString("  " + rowStyle + head + padRight(op, opW) + gap)
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
	writeRow(dim, "count", "process", "operation", "target", "notes", "")
	prevNote := ""
	for i, d := range ds {
		// A note repeated under the same operation reads as clutter; once is
		// enough to say what to do about the whole run of rows.
		note := notes[i]
		if i > 0 && note != "" && note == prevNote && d.op == ds[i-1].op && d.proc == ds[i-1].proc {
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
		writeRow(rowStyle, counts[i], procs[i], d.op, targets[i], note, noteStyle)
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
	// One reason is already counted by the phrase this sits in ("15 routine
	// refusals hidden:"), so repeating the number reads as a typo.
	if len(distinct) == 1 {
		return distinct[0]
	}
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

// explainRequest is what --explain knows about the run it is reporting on.
type explainRequest struct {
	command string // the name the kernel logs for the program
	// argv is the command as the user typed it, and baseFlags the flags already
	// in effect, so the next-run line can be pasted as it stands. Secrets stay
	// out of it: --canary-token and --pass-env are deliberately not
	// reconstructed into a line the reader will paste into their history.
	argv      []string
	baseFlags []string
	workdir   string // a refusal inside it is a protected path, not a missing grant
	// eventsPath and agent name this run's own lines in the event log, which is
	// where the destinations came from: the proxy decided them, not the kernel.
	eventsPath string
	agent      string
	// denialsPath is the project's record of what earlier runs saw refused, and
	// across how far back into it the plan reaches. One run is one sample; the
	// union is the specification. Zero across means plan from this run alone.
	denialsPath string
	across      time.Duration
	since       time.Time
	until       time.Time
}

// maxPlanGrants bounds the paste line. Past this the program wants the machine,
// and a longer command is not the answer to that.
const maxPlanGrants = 8

// grantPlan is the actionable half of --explain: the flags that would have
// stopped each refusal, derived from what the program actually asked for rather
// than from what the reader guessed it would need.
type grantPlan struct {
	ro, rw        []string
	mkdir         []string // write grants that do not exist yet, so --rw would refuse them
	notGrantable  int      // sockets, listeners, ioctls: no flag opens these
	insideWorkdir int      // already writable; the profile protects them on purpose
	inTemp        int      // /tmp is the run's own scratch, a decision of its own
	systemSpace   int      // a daemon's own files, which no run of yours should grant
	overCap       int      // paths left out to keep the line readable
	// drawnFrom says what the plan was built from, so a union over ten runs is
	// never mistaken for what this run saw.
	drawnFrom string
}

// grantKind says whether an operation is a path the reader can grant at all.
// Everything else (an ioctl on a terminal, a unix socket, a listener, a mach
// lookup) is refused by the shape of the profile, and no flag should open it.
func grantKind(op string) (string, bool) {
	switch {
	case strings.HasPrefix(op, "file-read"), op == "file-test-existence":
		return "ro", true
	case strings.HasPrefix(op, "file-write"), strings.HasPrefix(op, "file-setmode"), op == "file-mknod":
		return "rw", true
	}
	return "", false
}

// grantable reports whether run would accept the path as a grant. The tool's own
// guard answers the broad ones; the depth floor is the same idea for the paths it
// does not cover: /usr on its own is not something to grant to a program.
func grantable(path string) bool {
	if path == "" || !filepath.IsAbs(path) || mechanism.TooBroadToGrant(path) {
		return false
	}
	return strings.Count(strings.TrimPrefix(filepath.Clean(path), "/"), "/") >= 1
}

// under reports whether path sits at or below root.
func under(path, root string) bool {
	if root == "" {
		return false
	}
	path, root = filepath.Clean(path), filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// pathExists is the only question the plan asks the filesystem. It is a
// variable so the plan can be tested, and so the guide can render a macOS
// sample on a machine that has none of those paths.
var pathExists = os.Stat

// grantFor answers the only question the table leaves open: what do I pass so
// this stops being refused. A directory is granted as itself, a file by its
// containing directory (the sibling files are what make a directory usable, and
// one dylib is never wanted alone), and where that is too broad to grant, the
// file alone. Where the path does not exist the program was trying to create it,
// so the answer is the nearest directory that does exist plus the mkdir that
// fills the gap: run refuses a grant on a path that is not there.
func grantFor(target string) (grant, mkdirOf string) {
	candidate := filepath.Dir(target)
	if fi, err := pathExists(target); err == nil && fi.IsDir() {
		candidate = target
	}
	for d := candidate; ; d = filepath.Dir(d) {
		if !grantable(d) {
			break
		}
		if _, err := pathExists(d); err != nil {
			continue // the program was trying to create this level too
		}
		if d == candidate {
			return d, ""
		}
		return d, candidate
	}
	if grantable(target) {
		return target, ""
	}
	return "", ""
}

// privateTempDirs are the world-writable scratch directories the sandbox keeps
// to itself. A program refused there is not missing a grant: the run already
// gave it a private TMPDIR, and --rw /tmp would open the shared one to every
// other process on the machine, so the plan reports it rather than offering it.
var privateTempDirs = []string{"/tmp", "/private/tmp"}

func inPrivateTemp(target string) bool {
	for _, dir := range privateTempDirs {
		if under(target, dir) {
			return true
		}
	}
	return false
}

// outsideHomePrefixes are the trees beyond your own where a program of yours can
// legitimately have files: the package managers that install to a fixed prefix,
// the system's read-only data, and the one firmlink macOS keeps its timezones
// behind. Nothing else belongs here.
var outsideHomePrefixes = []string{
	"/opt/homebrew", "/opt/local", "/nix", "/usr/local", "/usr/share", "/usr/lib", "/etc",
	"/private/var/db/timezone",
}

// inUserSpace answers whether a refusal is this run's business at all. A confined
// window collects every process the sandbox holds, including the daemons that
// were already being refused before you ran anything: another service's temp
// folder, /private/var/db/locationd, /Library. Those are not what stopped your
// program, and offering --rw for them would have the tool ask for write access to
// the machine on somebody else's behalf. Writes are held to your own trees for
// the same reason; reads can also come from a package prefix, which is where a
// dylib the program will not start without usually lives.
func inUserSpace(target, workdir string, writable bool) bool {
	if under(target, workdir) {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && under(target, home) {
		return true
	}
	if writable {
		return false
	}
	for _, prefix := range outsideHomePrefixes {
		if under(target, prefix) {
			return true
		}
	}
	return false
}

// planGrants turns refusals into the least set of flags that covers them.
func planGrants(ds []denial, workdir string) grantPlan {
	var p grantPlan
	reads, writes := map[string]bool{}, map[string]bool{}
	mkdirOf := map[string]string{}
	for _, d := range ds {
		kind, ok := grantKind(d.op)
		if !ok || !strings.HasPrefix(d.target, "/") {
			p.notGrantable++
			continue
		}
		if strings.ContainsAny(d.target, " \t\r\n*?[]") {
			// The runner cannot pass it safely, so it is not a grant either.
			p.notGrantable++
			continue
		}
		if under(d.target, workdir) {
			p.insideWorkdir++
			continue
		}
		if inPrivateTemp(d.target) {
			p.inTemp++
			continue
		}
		if !inUserSpace(d.target, workdir, kind == "rw") {
			p.systemSpace++
			continue
		}
		grant, mkdir := grantFor(d.target)
		if grant == "" {
			p.notGrantable++
			continue
		}
		if kind == "ro" {
			reads[grant] = true
			continue
		}
		writes[grant] = true
		if mkdir != "" && mkdirOf[grant] == "" {
			mkdirOf[grant] = mkdir
		}
	}
	// One cap across both lists, taken alternately: eight of each would be a
	// sixteen flag line, and a program that needs a read and a write should keep
	// both halves of the answer rather than lose one to whichever sorted last.
	roAll, rwAll := sortedSet(reads), sortedSet(writes)
	for readsNext := true; len(p.ro)+len(p.rw) < maxPlanGrants; readsNext = !readsNext {
		if readsNext {
			if len(roAll) > 0 {
				p.ro, roAll = append(p.ro, roAll[0]), roAll[1:]
				continue
			}
		} else if len(rwAll) > 0 {
			p.rw, rwAll = append(p.rw, rwAll[0]), rwAll[1:]
			continue
		}
		if len(roAll) == 0 && len(rwAll) == 0 {
			break
		}
	}
	p.overCap = len(roAll) + len(rwAll)
	for _, grant := range p.rw {
		if m := mkdirOf[grant]; m != "" {
			p.mkdir = append(p.mkdir, m)
		}
	}
	slices.Sort(p.mkdir)
	p.mkdir = slices.Compact(p.mkdir)
	return p
}

// quoteArg single-quotes what the shell would otherwise expand, the same
// discipline the observe summary uses for its ALLOW line.
func quoteArg(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\"'\\$&|;()<>") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// paired glues each flag to the value it took so the two travel as one piece:
// a line break may fall between options, but never between --ro and the path it
// grants, which would leave the reader with a flag that reads the next option as
// its argument. A value never starts with a dash, so that is the test.
func paired(flags []string) []string {
	var out []string
	for i := 0; i < len(flags); i++ {
		f := flags[i]
		if strings.HasPrefix(f, "--") && i+1 < len(flags) && !strings.HasPrefix(flags[i+1], "--") {
			out = append(out, quoteArg(f)+" "+quoteArg(flags[i+1]))
			i++
			continue
		}
		out = append(out, quoteArg(f))
	}
	return out
}

// wrapCommand breaks an already quoted command between pieces rather than inside
// one, so a path with a space in it cannot be cut in half. A broken line ends in
// a backslash and the next opens indented, which is what a shell wants and what
// makes the whole block pasteable as printed. The lines come back carrying their
// own place in the report, two columns in, so nothing else has to know the indent.
func wrapCommand(parts []string, width int) []string {
	const block, indent = "  ", "      "
	if width < len(indent)+10 {
		width = len(indent) + 10
	}
	var lines []string
	cur := block
	for _, p := range parts {
		if cur != block {
			if len(cur)+1+len(p) > width {
				lines = append(lines, cur+` \`)
				cur = indent + p
				continue
			}
			cur += " "
		}
		cur += p
	}
	if cur != block {
		lines = append(lines, cur)
	}
	return lines
}

// maxPlanHosts bounds the recommended allow-list for the same reason as
// maxPlanGrants: past a handful the answer is not a longer command line.
const maxPlanHosts = 8

// hostPlan is the network half of the next run: the destinations this run's own
// proxy events say the program reached for. It is read from the event log rather
// than guessed at, because the proxy decided every one of them and wrote it down.
type hostPlan struct {
	allows, ports, privHosts []string
	// refused counts destinations that were never grantable in the first place:
	// canary and redirector hosts the proxy singled out, and loopback, which the
	// sandbox keeps to itself. Recommending them would undo the point.
	refused int
	overCap int
}

// planAllows reads this run's events and answers what to pass --allow next time.
// Only connect decisions count: a name the program looked up and never dialled is
// not something to open. Anything already in baseFlags is left out, so the line
// adds what is missing instead of repeating what was there.
func planAllows(req explainRequest) hostPlan {
	var p hostPlan
	f, err := os.Open(req.eventsPath)
	if err != nil {
		return p
	}
	defer f.Close()
	evs, _ := events.Read(f)
	want, wantPort, wantPriv := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range evs {
		if e.Kind != events.KindConnect || e.Host == "" {
			continue
		}
		if req.agent != "" && e.Agent != req.agent {
			continue
		}
		if e.Time.Before(req.since.Add(-2*time.Second)) || e.Time.After(req.until.Add(2*time.Second)) {
			continue
		}
		if e.Canary != "" || e.Relay != "" || strings.Contains(e.Reason, "canary") {
			p.refused++
			continue
		}
		if isLoopbackName(e.Host) {
			p.refused++
			continue
		}
		want[e.Host] = true
		if e.Port != "" && e.Port != "443" && e.Port != "80" {
			wantPort[e.Port] = true
		}
		if strings.HasPrefix(e.Reason, "resolved to non-public") {
			wantPriv[e.Host] = true
		}
	}
	var over int
	p.allows, over = capped(sortedSet(want), over)
	for h := range wantPriv {
		if !want[h] {
			delete(wantPriv, h)
		}
	}
	p.privHosts, over = capped(sortedSet(wantPriv), over)
	p.ports, over = capped(sortedSet(wantPort), over)
	p.overCap = over
	return p
}

// isLoopbackName reports the hostnames that mean this machine. Binding or
// dialling loopback is refused whatever the allow-list says, so a grant is the
// wrong answer to it.
func isLoopbackName(host string) bool {
	switch host {
	case "localhost", "localhost.", "ip6-localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// denialRows turns what this run saw into rows for the project's record.
// Refusals folded as routine are already out of both sets, so what is kept is
// what a person would have read; the process name goes with them because the
// kernel, not the reader, is what attributed them.
func denialRows(own, others []denial, req explainRequest) []denials.Row {
	runID := req.agent
	if runID == "" {
		runID = req.command
	}
	runID += "@" + strconv.FormatInt(req.since.Unix(), 10)
	var out []denials.Row
	for _, set := range [][]denial{own, others} {
		for _, d := range set {
			out = append(out, denials.Row{Time: req.until, Command: req.command, Agent: req.agent,
				RunID: runID, Proc: d.proc, Op: d.op, Target: d.target, Count: d.count})
		}
	}
	return out
}

// planFromRefusals records this run's refusals beside the event log and plans
// from the union of everything the same program has been refused in the window.
// A file that cannot be read is said out loud in the plan's own line rather
// than quietly shrinking the evidence.
func planFromRefusals(own, others []denial, req explainRequest) grantPlan {
	thisRun := denialRows(own, others, req)
	rows := thisRun
	if req.across > 0 && req.denialsPath != "" {
		stored, err := appendAndRead(req, thisRun)
		if err != nil {
			p := planGrants(fromRows(thisRun), req.workdir)
			p.drawnFrom = fmt.Sprintf("planned from this run only: the project's refusal log could not be read (%v)", err)
			return p
		}
		rows = stored
	}
	p := planGrants(fromRows(rows), req.workdir)
	if req.across <= 0 {
		if len(thisRun) > 0 {
			p.drawnFrom = "planned from this run only (--across 0)"
		}
		return p
	}
	runs, refusals := denials.Runs(rows), 0
	for _, r := range rows {
		refusals += max(r.Count, 1)
	}
	if refusals == 0 {
		return p
	}
	p.drawnFrom = fmt.Sprintf("planned from %d refusal%s across %d run%s of %s (--across %s, --across 0 for this run only)",
		refusals, plural(refusals), runs, plural(runs), req.command, formatWindow(req.across))
	return p
}

// appendAndRead writes this run's rows and reads the window back, so the plan
// sees the earlier runs as well as this one. The append is the point; a read
// failure is reported because the plan is about to be narrower than the reader
// thinks.
func appendAndRead(req explainRequest, thisRun []denials.Row) ([]denials.Row, error) {
	if len(thisRun) > 0 {
		f, err := proxy.OpenAppendNoFollow(req.denialsPath, 0o600)
		if err != nil {
			return nil, err
		}
		err = denials.Write(f, thisRun)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	f, err := os.Open(req.denialsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, _ := denials.Read(f)
	return denials.Select(rows, req.command, req.until.Add(-req.across)), nil
}

// fromRows turns stored refusals back into the shape the planner takes. Distinct
// targets are what the plan is about, so rows from different processes that name
// the same operation and path add up rather than repeat.
func fromRows(rows []denials.Row) []denial {
	by := map[string]*denial{}
	order := make([]string, 0, len(rows))
	for _, r := range rows {
		key := r.Op + "\x00" + r.Target
		d, ok := by[key]
		if !ok {
			d = &denial{proc: r.Proc, op: r.Op, target: r.Target}
			by[key] = d
			order = append(order, key)
		}
		d.count += max(r.Count, 1)
	}
	out := make([]denial, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out
}

// formatWindow is a duration a person reads rather than counts.
func formatWindow(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", int64(d/24/time.Hour))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	}
	return d.String()
}

// capped keeps the first max of a sorted list and carries the count that fell off.
func capped(all []string, already int) ([]string, int) {
	if len(all) > maxPlanHosts {
		return all[:maxPlanHosts], already + len(all) - maxPlanHosts
	}
	return all, already
}

// flagsValues pulls the values a repeatable flag took out of a reconstructed
// command line, so the plan does not offer what the run already had.
func flagsValues(flags []string, flag string) map[string]bool {
	out := map[string]bool{}
	for i, f := range flags {
		if f == flag && i+1 < len(flags) {
			out[flags[i+1]] = true
		}
	}
	return out
}

// formatNextRun prints the pasteable answer. It reads as the proxy's observe
// tail does, because the two are the same act on the two planes the sandbox
// enforces: destinations there, paths here.
func formatNextRun(g grantPlan, h hostPlan, req explainRequest, st emit.Styles) string {
	var b strings.Builder
	b.WriteString("\n")
	existing := flagsValues(req.baseFlags, "--ro")
	ro := make([]string, 0, len(g.ro))
	for _, p := range g.ro {
		if !existing[p] {
			ro = append(ro, p)
		}
	}
	existingRw := flagsValues(req.baseFlags, "--rw")
	rw := make([]string, 0, len(g.rw))
	for _, p := range g.rw {
		if !existingRw[p] {
			rw = append(rw, p)
		}
	}
	have := flagsValues(req.baseFlags, "--allow")
	allows := make([]string, 0, len(h.allows))
	for _, host := range h.allows {
		if !have[host] {
			allows = append(allows, host)
		}
	}
	total := len(ro) + len(rw) + len(allows) + len(h.ports) + len(h.privHosts)
	note := fmt.Sprintf("%d grant%s, %d host%s", len(ro)+len(rw), plural(len(ro)+len(rw)),
		len(allows)+len(h.ports)+len(h.privHosts), plural(len(allows)+len(h.ports)+len(h.privHosts)))
	noteStyle := st.Yellow // this is the part the reader can act on
	if total == 0 {
		note, noteStyle = "nothing to add", st.Dim
	}
	b.WriteString(emit.SectionNote(st, noteStyle, runColumns(), "next run", note))
	if g.drawnFrom != "" {
		line(&b, st, "  %s", g.drawnFrom)
	}
	if total == 0 {
		line(&b, st, "  Nothing above is one flag away; what follows says why each refusal is not.")
	} else {
		line(&b, st, "  The least that covers everything above, as one command:")
		cmd := []string{"sandboxcheckr", "run", "--explain"}
		cmd = append(cmd, paired(req.baseFlags)...)
		for _, host := range allows {
			cmd = append(cmd, "--allow "+quoteArg(host))
		}
		for _, port := range h.ports {
			cmd = append(cmd, "--allow-port "+quoteArg(port))
		}
		for _, host := range h.privHosts {
			cmd = append(cmd, "--allow-private-host "+quoteArg(host))
		}
		for _, p := range ro {
			cmd = append(cmd, "--ro "+quoteArg(p))
		}
		for _, p := range rw {
			cmd = append(cmd, "--rw "+quoteArg(p))
		}
		for _, a := range req.argv {
			cmd = append(cmd, quoteArg(a))
		}
		// A grant list this long outgrows a terminal, so the line breaks between
		// pieces: a trailing backslash keeps the block pasteable as it stands.
		for _, l := range wrapCommand(cmd, runColumns()) {
			b.WriteString(st.Bold + l + st.Reset + "\n")
		}
	}
	for _, m := range g.mkdir {
		line(&b, st, "  a --rw path has to exist first: mkdir -p %s", quoteArg(m))
	}
	if g.notGrantable > 0 {
		line(&b, st, "  %d refusal%s %s refused by design: a socket, a listener, a terminal ioctl.",
			g.notGrantable, plural(g.notGrantable), isAre(g.notGrantable))
	}
	if g.insideWorkdir > 0 {
		line(&b, st, "  %d refusal%s %s inside the workdir, where .git and .env are protected on purpose.",
			g.insideWorkdir, plural(g.insideWorkdir), isAre(g.insideWorkdir))
	}
	if g.inTemp > 0 {
		line(&b, st, "  %d refusal%s %s in the shared /tmp: the run has a private TMPDIR, and --rw /tmp "+
			"would open that one.", g.inTemp, plural(g.inTemp), isAre(g.inTemp))
	}
	if g.systemSpace > 0 {
		line(&b, st, "  %d refusal%s %s a service's own files: daemons the sandbox holds too were refused "+
			"before this run started, and a grant would open those paths to your program as well.",
			g.systemSpace, plural(g.systemSpace), isAre(g.systemSpace))
	}
	if g.overCap > 0 {
		line(&b, st, "  %d further path%s %s, left out of the line.",
			g.overCap, plural(g.overCap), isAre(g.overCap))
	}
	if h.refused > 0 {
		line(&b, st, "  %d destination%s %s a canary, a redirector or loopback: those stay refused.",
			h.refused, plural(h.refused), wasWere(h.refused))
	}
	if h.overCap > 0 {
		line(&b, st, "  %d more host%s %s in the destinations table, left out of the line.",
			h.overCap, plural(h.overCap), isAre(h.overCap))
	}
	return b.String()
}

// isAre and wasWere agree with the count each footnote starts with. "1 refusal
// are" is the kind of thing a reader notices more than the fact they came to
// read, and these lines are read one at a time, not against a legend.
func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// queryKernelLog is the log query, a variable so the report can be tested on a
// platform that has no unified log.
var queryKernelLog = kernelLogDenials

// printRunExplain reports what the sandbox refused during the run, and what to
// do about it. It runs after the child has exited and after the proxy's own
// summary, so it is the last thing a failed run prints.
func printRunExplain(w io.Writer, req explainRequest, st emit.Styles) {
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
	procName := req.command
	// The proxy decided the destinations on every platform, so the half of the
	// answer that comes from its log does not depend on the kernel log existing.
	destinations := planAllows(req)
	destinationsOnly := func() {
		if len(destinations.allows)+len(destinations.ports)+len(destinations.privHosts) > 0 {
			fmt.Fprint(w, formatNextRun(grantPlan{}, destinations, req, st))
		}
	}
	if !safeProcessName.MatchString(procName) {
		note("cannot search the kernel log for a process named %q; a name has to be a plain executable name", procName)
		destinationsOnly()
		return
	}
	lines, err := queryKernelLog(req.since, req.until)
	switch {
	case errors.Is(err, errExplainUnsupported):
		note("%s", "--explain reads the macOS kernel log, and the Linux sandbox has none: bubblewrap\n"+
			"  refuses inside a namespace and a seccomp filter that log nothing, so the program\n"+
			"  simply gets EPERM. The proxy's table above and the allow-list below are what this\n"+
			"  platform can tell you.")
		destinationsOnly()
		return
	case err != nil:
		note("could not read the kernel log: %v", err)
		destinationsOnly()
		return
	}
	own, hidden, others := aggregateDenials(lines, procName)
	// Recorded first, then planned from: the file is this run's contribution to
	// the picture and the plan is drawn from everything the same program has
	// been refused so far.
	plan := planFromRefusals(own, others, req)
	if len(own) == 0 && len(others) > 0 {
		// The program asked for nothing itself, so the refusals that matter are
		// the ones logged against something else the sandbox confined. Saying
		// "nothing was refused" here would be the worst sentence in the output:
		// it reads as a clean bill of health for the thing that just stopped the
		// program from starting.
		fmt.Fprint(w, formatDenials(others, hidden, procName, req.since, req.until, st))
		note("%s asked for nothing itself, but the sandbox confines everything it starts and the\n"+
			"  kernel names the process that asked: a shell script is logged as bash, its helpers\n"+
			"  under their own names. These are every refusal in the window, so a process confined\n"+
			"  by something else on this machine can appear; act on the paths this program needed.", procName)
		fmt.Fprint(w, formatNextRun(plan, destinations, req, st))
		return
	}
	fmt.Fprint(w, formatDenials(own, hidden, procName, req.since, req.until, st))
	if len(own) > 0 || len(destinations.allows)+len(destinations.ports)+len(destinations.privHosts) > 0 {
		fmt.Fprint(w, formatNextRun(plan, destinations, req, st))
	}
}
