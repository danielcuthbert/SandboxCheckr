package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// Lines as sandboxd writes them to the unified log, taken from a real codex run
// on 2026-11-22. The prefix is what "log show --style compact" puts in front.
const (
	logPref   = `2026-11-22 19:41:16.493073+0000 0x1d0464   Default     0x0                  485    0    sandboxd: [com.apple.sandbox.reporting:notification] Sandbox: codex(18451) deny(1) user-preference-read com.apple.universalaccess`
	logIoctl  = `2026-11-22 20:20:32.708356+0000 0x1d383a   Default     0x0                  485    0    sandboxd: [com.apple.sandbox.reporting:violation] Sandbox: codex(21003) deny(1) file-ioctl path:/dev/ttys003 ioctl-command:(0x540d 'TIOCSETA' { length: 128 })`
	logSock   = `2026-11-22 19:43:45.935682+0000 0x1e2243   Default     0x0                  485    0    sandboxd: (libnetwork.dylib) [com.apple.sandbox.reporting:violation] Sandbox: codex(19463) deny(1) network-outbound /private/var/run/mDNSResponder`
	logWrite  = `2026-11-22 19:43:47.547426+0000 0x1d3f89   Default     0x0                  485    0    sandboxd: [com.apple.sandbox.reporting:violation] Sandbox: codex(21071) deny(1) file-write-create deny file-mode-mask (path:file-write-create /Users/daniel/.cache/codex-runtimes/codex-primary-runtime/dependencies/docs/anything.txt (mode:0100644, vpath:/Users/daniel/.cache/x))`
	logSocket = `2026-11-22 20:23:02.112233+0000 0x1d4a11   Default     0x0                  485    0    sandboxd: [com.apple.sandbox.reporting:violation] Sandbox: codex(21071) deny(1) network-outbound /Users/daniel/.codex/app-server-control/app-server-control.sock`
	logAllow  = `2026-11-22 19:41:16.112233+0000 0x1d0464   Default     0x0                  485    0    sandboxd: [com.apple.sandbox.reporting:notification] Sandbox: codex(18451) allow(2) file-read-data /usr/lib/dyld`
	logOther  = `2026-11-22 19:41:16.112233+0000 0x1d0464   Default     0x0                  485    0    sandboxd: [com.apple.sandbox.reporting:violation] Sandbox: node(99) deny(1) file-write-create /Users/daniel/x`
	logLonger = `2026-11-22 19:41:16.112233+0000 0x1d0464   Default     0x0                  485    0    sandboxd: Sandbox: codex-helper(99) deny(1) file-write-create /Users/daniel/x`
	logNoise  = `2026-11-22 19:41:16.112233+0000 0x1d0464   Default     0x0                  485    0    runningboardd: Sandbox: the report is late today`
)

func TestParseDenialLine(t *testing.T) {
	cases := []struct {
		name, line, wantProc, wantOp, wantTarget string
		ok                                       bool
	}{
		{"preference", logPref, "codex", "user-preference-read", "com.apple.universalaccess", true},
		{"ioctl", logIoctl, "codex", "file-ioctl", "/dev/ttys003", true},
		{"resolver socket", logSock, "codex", "network-outbound", "/private/var/run/mDNSResponder", true},
		{"write", logWrite, "codex", "file-write-create", "/Users/daniel/.cache/codex-runtimes/codex-primary-runtime/dependencies/docs/anything.txt", true},
		{"agent socket", logSocket, "codex", "network-outbound", "/Users/daniel/.codex/app-server-control/app-server-control.sock", true},
		{"not a refusal", logAllow, "", "", "", false},
		// A helper is a refusal the sandbox made, so it parses; which table it
		// lands in is aggregateDenials' business.
		{"other process", logOther, "node", "file-write-create", "/Users/daniel/x", true},
		{"longer name is another process", logLonger, "codex-helper", "file-write-create", "/Users/daniel/x", true},
		{"no denial here", logNoise, "", "", "", false},
		{"empty", "", "", "", "", false},
	}
	for _, c := range cases {
		proc, op, target, ok := parseDenialLine(c.line)
		if ok != c.ok || proc != c.wantProc || op != c.wantOp || target != c.wantTarget {
			t.Errorf("%s: got (%q, %q, %q, %v), want (%q, %q, %q, %v)",
				c.name, proc, op, target, ok, c.wantProc, c.wantOp, c.wantTarget, c.ok)
		}
	}
}

// explainFor is the report request a test needs: a named program in a window and
// nothing else, so what it asserts is about the refusals. The event log is left
// unset, which reads as a run that contacted nothing.
func explainFor(command string) explainRequest {
	now := time.Now()
	return explainRequest{command: command, argv: []string{command}, since: now.Add(-time.Minute), until: now}
}

func TestParseDenialLineRejectsUnsafeNames(t *testing.T) {
	// A logged name has to look like an executable name before anything is
	// printed with it, and a name with a quote or a paren in it would be the
	// kernel log saying something it did not.
	for _, name := range []string{`co"dex`, "codex (1)", "codex) deny(1", strings.Repeat("x", 65)} {
		line := `2026-11-22 20:20:32.708356+0000 sandboxd: Sandbox: ` + name + `(21003) deny(1) file-read-data /etc/hosts`
		if _, _, _, ok := parseDenialLine(line); ok {
			t.Errorf("parseDenialLine accepted the process name %q", name)
		}
	}
}

func TestAggregateDenialsCountsAndOrders(t *testing.T) {
	lines := []string{logWrite, logIoctl, logIoctl, logIoctl, logSock, logPref, logNoise, logAllow}
	shown, hidden, others := aggregateDenials(lines, "codex")
	if len(hidden) != 1 {
		t.Fatalf("hidden = %v, want one VoiceOver preference read", hidden)
	}
	if len(others) != 0 {
		t.Errorf("nothing here was refused to another process: %+v", others)
	}
	if len(shown) != 3 {
		t.Fatalf("got %d distinct refusals, want 3: %+v", len(shown), shown)
	}
	if shown[0].op != "file-ioctl" || shown[0].count != 3 {
		t.Errorf("first row = %s x%d, want the three ioctls first", shown[0].op, shown[0].count)
	}
	if shown[1].op != "file-write-create" || shown[2].op != "network-outbound" {
		t.Errorf("tie broken wrong: %s before %s", shown[1].op, shown[2].op)
	}
}

// compactLine writes one line as sandboxd does, so a test can name the process
// the kernel blamed.
func compactLine(proc string, pid int, op, target string) string {
	return `2026-11-22 09:21:43.2291+0000 0x1d383a   Default     0x0                  485    0    ` +
		`sandboxd: [com.apple.sandbox.reporting:violation] Sandbox: ` +
		fmt.Sprintf("%s(%d) deny(1) %s %s", proc, pid, op, target)
}

// A shell script is logged as bash and its helpers under their own names, so the
// refusals that stopped a program never carry the name the user typed. raptor on
// 2026-11-22: its clear died in dyld because the sandbox blocked the open of
// /opt/local/lib/libncurses.6.dylib, and --explain said nothing had been refused.
func TestPrintRunExplainShowsTheConfinedTree(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return []string{
			compactLine("clear", 29159, "file-read-data", "/opt/local/lib/libncurses.6.dylib"),
			compactLine("bash", 29062, "file-write-create", "/tmp/claude-501"),
			compactLine("node", 29180, "file-write-create", "/Users/daniel/.local/share/raptor/sessions.d"),
		}, nil
	}
	var b strings.Builder
	printRunExplain(&b, explainFor("raptor"), emit.Styles{})
	out := b.String()
	for _, want := range []string{
		"SANDBOX REFUSALS", "kernel log, all confined",
		"process", "clear", "/opt/local/lib/libncurses.6.dylib", "bash", "/tmp/claude-501", "node",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the tree report lacks %q:\n%s", want, out)
		}
	}
	// The innocent verdict is the sentence that must never appear here: the
	// sandbox is exactly what stopped this program.
	for _, bad := range []string{"So the failure is not the sandbox", "nothing was refused for raptor"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report clears the sandbox while a confined process was refused: %q\n%s", bad, out)
		}
	}
}

// When the named program was itself refused things, that is the report; the
// neighbours in the same window do not crowd out the answer.
func TestPrintRunExplainPrefersTheNamedProgram(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return []string{logIoctl, compactLine("someother", 42, "file-read-data", "/etc/hosts")}, nil
	}
	var b strings.Builder
	printRunExplain(&b, explainFor("codex"), emit.Styles{})
	out := b.String()
	if !strings.Contains(out, "file-ioctl") || !strings.Contains(out, "codex, kernel log") {
		t.Errorf("the program's own refusals should lead:\n%s", out)
	}
	if strings.Contains(out, "someother") {
		t.Errorf("another process crowded into the program's own table:\n%s", out)
	}
}

// Nothing at all was refused, by anyone: only then does the report vouch for the
// sandbox.
func TestPrintRunExplainClearsTheSandboxOnlyWhenEmpty(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return []string{logAllow, logNoise}, nil
	}
	var b strings.Builder
	printRunExplain(&b, explainFor("codex"), emit.Styles{})
	out := b.String()
	if !strings.Contains(out, "nothing was refused for codex") ||
		!strings.Contains(out, "No other confined process was refused either") {
		t.Errorf("a genuinely empty window should read as clean:\n%s", out)
	}
}

func TestFormatDenials(t *testing.T) {
	since := time.Date(2026, 11, 22, 20, 20, 0, 0, time.UTC)
	until := since.Add(90 * time.Second)
	ds := []denial{
		{op: "file-ioctl", target: "/dev/ttys003", count: 3},
		{op: "network-outbound", target: "/Users/daniel/.codex/app-server-control/app-server-control.sock", count: 1},
	}
	// The same reason twice: counted twice, named once.
	noise := []string{"the VoiceOver check most programs ignore", "the VoiceOver check most programs ignore"}
	out := formatDenials(ds, noise, "codex", since, until, emit.Styles{})
	for _, want := range []string{
		"SANDBOX REFUSALS",
		"kernel log", "codex,",
		"20:20:00 to 20:21:30",
		"count", "operation", "target", "notes",
		"file-ioctl", "/dev/ttys003",
		"terminal control; this run did not inherit that device",
		"unix socket, refused by design",
		"2 routine refusals hidden",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(out, "\n") {
		t.Errorf("the table needs a blank line above it, it follows another block:\n%s", out)
	}
	// A column is a column: the same offset in every row, whatever the width of
	// what sits above it. Measured in columns, so the ellipsis in the truncated
	// target cannot hide a two-column drift.
	rows := dataRows(t, out)
	if a, b := columnOffset(rows[0], "file-ioctl"), columnOffset(rows[1], "network-outbound"); a < 0 || a != b {
		t.Errorf("operation column drifts: %d vs %d\n%s", a, b, out)
	}
	if a, b := columnOffset(rows[0], "/dev/ttys003"), columnOffset(rows[1], "…"); a < 0 || a != b {
		t.Errorf("target column drifts: %d vs %d\n%s", a, b, out)
	}
	if strings.Contains(out, " \n") {
		t.Errorf("rows must not trail blanks:\n%s", out)
	}
}

func TestFormatDenialsRepeatsANoteOnce(t *testing.T) {
	// Eight timezone reads all want the same thing; saying it eight times is
	// noise that buries the one row nobody has seen before.
	ds := []denial{
		{op: "file-read-data", target: "/Users/daniel/.agents/skills", count: 3},
		{op: "file-read-data", target: "/Users/daniel/.agents/skills/find-skills", count: 3},
		{op: "file-read-data", target: "/private/var/db/timezone/tz/2026f.1.0/zoneinfo/GMT", count: 2},
	}
	out := formatDenials(ds, nil, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	if n := strings.Count(out, "outside the workdir; add --ro <dir>"); n != 1 {
		t.Errorf("the shared note should be stated once, found %d:\n%s", n, out)
	}
	if n := strings.Count(out, "file-read-data"); n != 3 {
		t.Errorf("every row should still name its operation, found %d:\n%s", n, out)
	}
}

func TestFormatDenialsKeepsDistinctNotes(t *testing.T) {
	// The suppression is per note per operation, not a blanket once-per-table.
	ds := []denial{
		{op: "file-write-data", target: "/Users/daniel/.npmrc", count: 2},
		{op: "file-read-data", target: "/Users/daniel/.aws/credentials", count: 1},
	}
	out := formatDenials(ds, nil, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	if !strings.Contains(out, "--rw") || !strings.Contains(out, "--ro") {
		t.Errorf("both notes should appear:\n%s", out)
	}
}

func TestFormatDenialsCapsTheTable(t *testing.T) {
	ds := make([]denial, 0, maxExplainRows+5)
	for i := 0; i < maxExplainRows+5; i++ {
		ds = append(ds, denial{op: "file-read-data", target: fmt.Sprintf("/Users/daniel/f%d", i), count: maxExplainRows + 5 - i})
	}
	out := formatDenials(ds, nil, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	if !strings.Contains(out, "and 5 more, least refused first") {
		t.Errorf("a truncated table should say so:\n%s", out)
	}
	if n := len(dataRows(t, out)); n != maxExplainRows {
		t.Errorf("printed %d rows, want the cap of %d", n, maxExplainRows)
	}
}

// dataRows returns the table's data rows, header and prose aside.
func dataRows(t *testing.T, out string) []string {
	t.Helper()
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.Contains(line, "──") &&
			!strings.Contains(line, "operation") && !strings.Contains(line, "routine refusal") &&
			!strings.Contains(line, "more, least refused") {
			rows = append(rows, line)
		}
	}
	if len(rows) == 0 {
		t.Fatalf("no data rows in:\n%s", out)
	}
	return rows
}

// columnOffset is where a string starts, counted in columns rather than bytes.
func columnOffset(row, s string) int {
	i := strings.Index(row, s)
	if i < 0 {
		return -1
	}
	return displayWidth(row[:i])
}

func TestFormatDenialsNothingRefused(t *testing.T) {
	out := formatDenials(nil, nil, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	if !strings.Contains(out, "nothing was refused for codex") ||
		!strings.Contains(out, "the failure is not the sandbox") {
		t.Errorf("an empty report should say so and point elsewhere:\n%s", out)
	}
}

func TestTruncTargetKeepsTheTail(t *testing.T) {
	long := "/Users/daniel/.cache/codex-runtimes/codex-primary-runtime/dependencies/docs/anything.txt"
	got := truncTarget(long)
	if !strings.HasPrefix(got, "…") || !strings.HasSuffix(got, "anything.txt") {
		t.Errorf("truncTarget(%q) = %q", long, got)
	}
	if n := displayWidth(got); n != 48 {
		t.Errorf("truncTarget width = %d columns, want 48: %q", n, got)
	}
	if truncTarget("/dev/tty") != "/dev/tty" {
		t.Error("short targets should pass through untouched")
	}
}

func TestAdviceFor(t *testing.T) {
	cases := []struct {
		op, target, want string
		level            noteLevel
	}{
		{"file-write-data", "/Users/daniel/.npmrc", "--rw", noteAction},
		{"file-read-data", "/Users/daniel/.aws/credentials", "--ro", noteAction},
		{"system-socket", "domain:32 type:2 protocol:2", "socket family", noteExpected},
		{"network-bind", "/tmp/worker.sock", "unix socket", noteExpected},
		{"network-bind", "local:*:0", "listener", noteExpected},
		{"file-ioctl", "/dev/ttys003", "terminal control", notePlain},
		{"process-fork", "", "", notePlain},
		{"file-write-data", "relative/path", "", notePlain},
	}
	for _, c := range cases {
		got, level := adviceFor(c.op, c.target)
		if c.want == "" && got != "" {
			t.Errorf("adviceFor(%s, %s) = %q, want no advice", c.op, c.target, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("adviceFor(%s, %s) = %q, want it to mention %q", c.op, c.target, got, c.want)
		}
		if level != c.level {
			t.Errorf("adviceFor(%s, %s) level = %v, want %v", c.op, c.target, level, c.level)
		}
	}
}

func TestSummariseReasonsWeightsByCount(t *testing.T) {
	got := summariseReasons([]string{"rare noise", "common noise", "common noise", "common noise"})
	if want := "3 common noise; 1 rare noise"; got != want {
		t.Errorf("summariseReasons = %q, want %q", got, want)
	}
	if got := summariseReasons(nil); got != "" {
		t.Errorf("no reasons should give no text, got %q", got)
	}
}

func TestRoutineDenialsCoverOnlyWhatWasMeasured(t *testing.T) {
	// Each of these appeared in a codex run on 2026-11-22 that went on to
	// finish its session with them refused. Anything else stays in the table.
	quiet := []struct{ op, target string }{
		{"user-preference-read", "com.apple.universalaccess"},
		{"user-preference-read", "com.apple.universalaccess.whatever"},
		{"user-preference-read", "kcfpreferencesanyapplication"},
		{"user-preference-read", "com.apple.security"},
	}
	for _, c := range quiet {
		if routineWhy(c.op, c.target) == "" {
			t.Errorf("%s %s should be folded away with a reason", c.op, c.target)
		}
	}
	loud := []struct{ op, target string }{
		{"user-preference-read", "com.apple.finder"},
		{"file-read-data", "/Users/daniel/.agents/skills"},
		{"file-write-data", "/Users/daniel/.npmrc"},
	}
	for _, c := range loud {
		if why := routineWhy(c.op, c.target); why != "" {
			t.Errorf("%s %s is not routine noise, it was excused as %q", c.op, c.target, why)
		}
	}
}

func TestPrintRunExplainRendersTheQuery(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return []string{logIoctl, logIoctl, logSocket, logPref, logPref}, nil
	}
	var b strings.Builder
	printRunExplain(&b, explainFor("codex"), emit.Styles{})
	out := b.String()
	for _, want := range []string{"file-ioctl", "/dev/ttys003", "app-server-control.sock", "routine refusals hidden"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestPrintRunExplainWithoutAKernelLog(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return nil, errExplainUnsupported
	}
	var b strings.Builder
	printRunExplain(&b, explainFor("codex"), emit.Styles{})
	out := b.String()
	if !strings.Contains(out, "macOS kernel log") || !strings.Contains(out, "EPERM") {
		t.Errorf("Linux should say it cannot do this rather than print an empty table:\n%s", out)
	}
	if strings.Contains(out, "nothing was refused") {
		t.Error("an unsupported platform must not report a clean run")
	}
}

func TestPrintRunExplainColourClosesEveryLine(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return []string{
			compactLine("codex", 21003, "file-read-data", filepath.Join(root, "lib", "libncurses.6.dylib")),
			compactLine("codex", 21003, "file-write-create", filepath.Join(root, "home", ".local", "share", "raptor")),
			compactLine("codex", 21003, "file-ioctl", "/dev/ttys003"),
		}, nil
	}
	newReq := func() explainRequest {
		req := explainFor("codex")
		req.agent = "codex-1"
		req.workdir = workOf(root)
		req.argv = []string{"codex", "--ask", "one two"}
		req.baseFlags = []string{"--deny-all"}
		req.eventsPath = writeEventsFixture(t, req.agent,
			events.Event{Time: time.Now(), Kind: events.KindConnect, Decision: events.Deny, Host: "api.example.com", Reason: "not in allow-list"})
		return req
	}
	on := emit.Palette(true)
	var plain, coloured strings.Builder
	printRunExplain(&plain, newReq(), emit.Styles{})
	printRunExplain(&coloured, newReq(), on)
	if got := ansiSequences.ReplaceAllString(coloured.String(), ""); got != plain.String() {
		t.Errorf("colour changed the report.\nplain:\n%s\ncoloured, stripped:\n%s", plain.String(), got)
	}
	if !strings.Contains(plain.String(), "NEXT RUN") {
		t.Fatalf("the fixture should reach the end of the report:\n%s", plain.String())
	}
	for _, line := range strings.Split(coloured.String(), "\n") {
		// A row the palette says nothing about carries no escape at all; a row
		// that carries one has to close it, or the shell inherits the colour.
		if strings.Contains(line, "\x1b") && !strings.Contains(line, on.Reset) {
			t.Errorf("an unclosed escape leaks colour into the shell: %q", line)
		}
	}
}

func TestPrintRunExplainQueryFailure(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return nil, errors.New("the log query timed out; try a shorter run")
	}
	var b strings.Builder
	printRunExplain(&b, explainFor("codex"), emit.Styles{})
	if out := b.String(); !strings.Contains(out, "could not read the kernel log") {
		t.Errorf("a failed query should be reported, not swallowed:\n%s", out)
	}
}

// ansiSequences matches what colour adds, so a coloured render can be compared
// with a plain one.
var ansiSequences = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestFormatDenialsColourKeepsTheColumns(t *testing.T) {
	since := time.Date(2026, 11, 22, 20, 20, 0, 0, time.UTC)
	until := since.Add(90 * time.Second)
	ds := []denial{
		{op: "file-read-data", target: "/Users/daniel/.agents/skills", count: 3},
		{op: "network-bind", target: "local:*:0", count: 1},
		{op: "file-ioctl", target: "/dev/ttys003", count: 1},
	}
	plain := formatDenials(ds, nil, "codex", since, until, emit.Styles{})
	on := emit.Palette(true)
	coloured := formatDenials(ds, nil, "codex", since, until, on)
	if got := ansiSequences.ReplaceAllString(coloured, ""); got != plain {
		t.Errorf("colour must not change the layout.\nplain:\n%s\ncoloured, stripped:\n%s", plain, got)
	}
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("with colour off there must be no escapes at all:\n%q", plain)
	}
	if !strings.Contains(coloured, on.Yellow+"outside the workdir; add --ro <dir>"+on.Reset) {
		t.Errorf("a grant you can add should stand out:\n%q", coloured)
	}
	for _, line := range strings.Split(coloured, "\n") {
		if strings.Contains(line, "network-bind") && !strings.HasPrefix(line, "  "+on.Dim) {
			t.Errorf("a refusal made on purpose should recede: %q", line)
		}
	}
	if empty := formatDenials(nil, nil, "codex", since, until, on); !strings.Contains(empty, on.Green+"  nothing was refused") {
		t.Errorf("a clean run should read as good news:\n%q", empty)
	}
}

func TestPrintRunExplainRejectsAwkwardCommand(t *testing.T) {
	var b strings.Builder
	printRunExplain(&b, explainFor(`co"dex`), emit.Styles{})
	if !strings.Contains(b.String(), "cannot search the kernel log") {
		t.Error("an unsafe command name should be refused before the query")
	}
}

// The report's job is to end with the command to run next, so the plan behind it
// is where the tool's opinion lives: which paths a refusal turns into a grant,
// and which it refuses to turn into one.

// outsideTemp points the private-scratch rule at a directory no fixture is in.
// The sandbox keeps /tmp to itself, and a test fixture built with t.TempDir
// would otherwise be counted as scratch rather than as a path to grant.
func outsideTemp(t *testing.T) {
	t.Helper()
	old := privateTempDirs
	privateTempDirs = []string{filepath.Join(string(filepath.Separator), "sandboxcheckr-test-tmp")}
	t.Cleanup(func() { privateTempDirs = old })
}

// fixtureTree makes the shapes a refusal can name: a directory, a file inside it,
// a directory the program was trying to create, and a workdir of its own.
func fixtureTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"lib", "work", "home", "home/.local"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"lib/libncurses.6.dylib", "home/.CFUserTextEncoding", "work/main.go"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// workOf is the fixture's project directory: a refusal inside it is the profile
// protecting its own files, which is a different answer from a missing grant.
func workOf(root string) string { return filepath.Join(root, "work") }

func read(target string) denial {
	return denial{proc: "prog", op: "file-read-data", target: target, count: 1}
}

func write(target string) denial {
	return denial{proc: "prog", op: "file-write-create", target: target, count: 1}
}

// writeEventsFixture writes the lines the proxy would have appended for this
// run. An event with no agent is stamped with the run's label, because it is the
// run's own lines the plan is allowed to read: two agents' runs share one log.
func writeEventsFixture(t *testing.T, agent string, evs ...events.Event) string {
	t.Helper()
	var b strings.Builder
	for _, e := range evs {
		if e.Agent == "" {
			e.Agent = agent
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanGrantsNarrowsAFileToItsDirectory(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	p := planGrants([]denial{read(filepath.Join(root, "lib", "libncurses.6.dylib"))}, workOf(root))
	if len(p.ro) != 1 || p.ro[0] != filepath.Join(root, "lib") {
		t.Fatalf("ro = %v, want the containing directory %s", p.ro, filepath.Join(root, "lib"))
	}
	if len(p.rw) != 0 || p.notGrantable != 0 {
		t.Errorf("a read refusal must not produce a write grant or a count: %v %d", p.rw, p.notGrantable)
	}
}

func TestPlanGrantsFallsBackToTheFileWhenTheDirectoryIsTooBroad(t *testing.T) {
	outsideTemp(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to be too broad")
	}
	// The home directory is never a grant, so a dotfile refused there can only
	// be granted as itself: the alternative is handing the program the home.
	p := planGrants([]denial{read(filepath.Join(home, ".CFUserTextEncoding"))}, "")
	if len(p.ro) != 1 || p.ro[0] != filepath.Join(home, ".CFUserTextEncoding") {
		t.Fatalf("ro = %v, want the file itself", p.ro)
	}
}

func TestPlanGrantsNamesTheDirectoryToCreate(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	missing := filepath.Join(root, "home", ".local", "share", "raptor", "sessions.d")
	p := planGrants([]denial{write(missing)}, "")
	want := filepath.Join(root, "home", ".local")
	if len(p.rw) != 1 || p.rw[0] != want {
		t.Fatalf("rw = %v, want the nearest directory that exists, %s", p.rw, want)
	}
	// The grant has to be a path run will accept, so the mkdir names what the
	// program was trying to make and --rw alone could not reach.
	if want := []string{filepath.Dir(missing)}; !slices.Equal(p.mkdir, want) {
		t.Errorf("mkdir = %v, want %v so --rw will accept it", p.mkdir, want)
	}
}

func TestPlanGrantsCountsWhatNoFlagCanOpen(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	p := planGrants([]denial{
		{proc: "prog", op: "file-ioctl", target: "/dev/ttys003", count: 1},
		{proc: "prog", op: "network-outbound", target: "/private/var/run/mDNSResponder", count: 1},
		{proc: "prog", op: "network-bind", target: "local:*:0", count: 1},
		{proc: "prog", op: "mach-lookup", target: "com.apple.coreservices.launchservicesd", count: 1},
		read(filepath.Join(root, "work", "main.go")),
		write(filepath.Join(root, "work", "out", "x")),
		read(filepath.Join(root, "lib", "a b.dylib")),
	}, workOf(root))
	if p.notGrantable != 5 {
		t.Errorf("notGrantable = %d, want 5: ioctl, socket, listener, mach, and a path with a space", p.notGrantable)
	}
	if p.insideWorkdir != 2 {
		t.Errorf("insideWorkdir = %d, want 2: the workdir protects its own files, it is not a missing grant", p.insideWorkdir)
	}
	if len(p.ro)+len(p.rw) != 0 {
		t.Errorf("nothing here is a grant, got ro=%v rw=%v", p.ro, p.rw)
	}
}

func TestPlanGrantsKeepsScratchOutOfThePlan(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	privateTempDirs = []string{filepath.Join(root, "scratch")}
	if err := os.MkdirAll(filepath.Join(root, "scratch"), 0o1777); err != nil {
		t.Fatal(err)
	}
	p := planGrants([]denial{write(filepath.Join(root, "scratch", "claude-501"))}, "")
	if p.inTemp != 1 {
		t.Errorf("inTemp = %d, want 1: the shared temp dir is a decision of its own", p.inTemp)
	}
	if len(p.rw) != 0 {
		t.Errorf("rw = %v, want the scratch directory left out of the paste line", p.rw)
	}
}

func TestPlanGrantsCapsTheLine(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	var ds []denial
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		dir := filepath.Join(root, "lib", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		ds = append(ds, read(filepath.Join(dir, "libthing.dylib")))
	}
	p := planGrants(ds, workOf(root))
	if len(p.ro) != maxPlanGrants {
		t.Errorf("ro = %d entries, want the cap of %d", len(p.ro), maxPlanGrants)
	}
	if p.overCap != 1 {
		t.Errorf("overCap = %d, want 1 said out loud rather than dropped", p.overCap)
	}
	if !slices.IsSorted(p.ro) {
		t.Errorf("ro = %v, want a stable order whatever the kernel logged", p.ro)
	}
}

func TestPlanAllowsReadsTheRunsOwnDestinations(t *testing.T) {
	now := time.Now()
	req := explainFor("prog")
	req.agent = "prog-1"
	req.eventsPath = writeEventsFixture(t, req.agent,
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Deny, Host: "api.example.com", Port: "443", Reason: "not in allow-list"},
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Allow, Host: "cdn.example.com", Port: "8443"},
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Deny, Host: "inference.internal", Port: "443",
			Reason: "resolved to non-public address 10.0.0.5; refusing (use --allow-private-host inference.internal to permit this host only)"},
		// None of these belong in a recommendation.
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Deny, Host: "canary.example", Reason: "canary credential"},
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Deny, Host: "is.gd", Relay: "shortener"},
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Deny, Host: "127.0.0.1", Port: "8080"},
		// A name looked up and never dialled is not something to open...
		events.Event{Time: now, Kind: events.KindDns, Decision: events.Deny, Host: "looked-up-only.example", Port: "53"},
		// ...and another agent's run in the same log is not this run's business.
		events.Event{Time: now, Kind: events.KindConnect, Decision: events.Deny, Host: "another-agent.example", Agent: "someone-else"},
	)
	p := planAllows(req)
	if strings.Join(p.allows, " ") != "api.example.com cdn.example.com inference.internal" {
		t.Errorf("allows = %v", p.allows)
	}
	if strings.Join(p.ports, " ") != "8443" {
		t.Errorf("ports = %v, want only the non-default one", p.ports)
	}
	if strings.Join(p.privHosts, " ") != "inference.internal" {
		t.Errorf("privHosts = %v, want the host the proxy refused for being private", p.privHosts)
	}
	if p.refused != 3 {
		t.Errorf("refused = %d, want the canary, the shortener and loopback counted separately", p.refused)
	}
}

func TestFormatNextRunIsPasteable(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	req := explainFor("raptor")
	req.argv = []string{"./bin/raptor", "--prompt", "say hi"}
	req.baseFlags = []string{"--deny-all", "--ro", filepath.Join(root, "lib")}
	g := planGrants([]denial{
		read(filepath.Join(root, "lib", "libncurses.6.dylib")), // already granted: must not be repeated
		read(filepath.Join(root, "home", ".CFUserTextEncoding")),
		write(filepath.Join(root, "home", ".local", "share", "raptor", "sessions.d")),
	}, workOf(root))
	h := hostPlan{allows: []string{"api.example.com"}, ports: []string{"8443"}}
	out := formatNextRun(g, h, req, emit.Styles{})
	for _, want := range []string{
		"sandboxcheckr run --explain --deny-all",
		"--allow api.example.com",
		"--allow-port 8443",
		"--ro " + filepath.Join(root, "home"),
		"--rw " + filepath.Join(root, "home", ".local"),
		"'say hi'",
		"./bin/raptor",
		"mkdir -p " + filepath.Join(root, "home", ".local", "share", "raptor"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the next-run line is missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "--ro "+filepath.Join(root, "lib")); n != 1 {
		t.Errorf("a grant the run already had should appear once, from the flags it ran with, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "2 grants, 2 hosts") {
		t.Errorf("the header should count what it is offering:\n%s", out)
	}
}

func TestFormatNextRunSaysWhenNothingIsMissing(t *testing.T) {
	out := formatNextRun(grantPlan{notGrantable: 3}, hostPlan{}, explainFor("prog"), emit.Styles{})
	if !strings.Contains(out, "nothing to add") {
		t.Errorf("a run whose refusals are all by design should not offer flags:\n%s", out)
	}
	if strings.Contains(out, "sandboxcheckr run") {
		t.Errorf("no command line should be offered when nothing would change:\n%s", out)
	}
	if !strings.Contains(out, "3 refusals are refused by design") {
		t.Errorf("the report should still account for every refusal:\n%s", out)
	}
}

func TestPrintRunExplainStillNamesTheHostsItReachedFor(t *testing.T) {
	// The destinations came from the proxy, not the kernel, so a platform whose
	// sandbox logs nothing still gets the half of the answer it can be given.
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) { return nil, errExplainUnsupported }
	req := explainFor("prog")
	req.agent = "prog-1"
	req.argv = []string{"./prog", "--verbose"}
	req.eventsPath = writeEventsFixture(t, req.agent,
		events.Event{Time: time.Now(), Kind: events.KindConnect, Decision: events.Deny, Host: "api.example.com", Reason: "not in allow-list"},
		events.Event{Time: time.Now(), Kind: events.KindConnect, Decision: events.Deny, Host: "inference.internal", Port: "8080",
			Reason: "resolved to non-public address 10.0.0.5; refusing (use --allow-private-host inference.internal to permit this host only)"})
	var b strings.Builder
	printRunExplain(&b, req, emit.Styles{})
	out := b.String()
	if !strings.Contains(out, "Linux sandbox has none") {
		t.Errorf("the missing kernel log should still be said out loud:\n%s", out)
	}
	for _, want := range []string{"sandboxcheckr run --explain", "--allow api.example.com",
		"--allow inference.internal", "--allow-port 8080", "--allow-private-host inference.internal", "./prog --verbose"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
}

func TestPrintRunExplainEndsWithTheNextCommand(t *testing.T) {
	outsideTemp(t)
	root := fixtureTree(t)
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(time.Time, time.Time) ([]string, error) {
		return []string{
			compactLine("raptor", 29159, "file-read-data", filepath.Join(root, "lib", "libncurses.6.dylib")),
			compactLine("raptor", 29159, "file-ioctl", "/dev/ttys003"),
		}, nil
	}
	req := explainFor("raptor")
	req.agent = "raptor-1"
	req.workdir = workOf(root)
	req.argv = []string{"./bin/raptor"}
	req.eventsPath = writeEventsFixture(t, req.agent,
		events.Event{Time: time.Now(), Kind: events.KindConnect, Decision: events.Deny, Host: "api.example.com", Reason: "not in allow-list"})
	var b strings.Builder
	printRunExplain(&b, req, emit.Styles{})
	out := b.String()
	for _, want := range []string{
		"NEXT RUN", "sandboxcheckr run --explain",
		"--ro " + filepath.Join(root, "lib"),
		"--allow api.example.com",
		"./bin/raptor",
		"1 refusal is refused by design",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report must end with what to run next, missing %q:\n%s", want, out)
		}
	}
}
