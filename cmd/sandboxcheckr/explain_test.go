package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
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
		name, line, wantOp, wantTarget string
		ok                             bool
	}{
		{"preference", logPref, "user-preference-read", "com.apple.universalaccess", true},
		{"ioctl", logIoctl, "file-ioctl", "/dev/ttys003", true},
		{"resolver socket", logSock, "network-outbound", "/private/var/run/mDNSResponder", true},
		{"write", logWrite, "file-write-create", "/Users/daniel/.cache/codex-runtimes/codex-primary-runtime/dependencies/docs/anything.txt", true},
		{"agent socket", logSocket, "network-outbound", "/Users/daniel/.codex/app-server-control/app-server-control.sock", true},
		{"not a refusal", logAllow, "", "", false},
		{"other process", logOther, "", "", false},
		{"longer name is another process", logLonger, "", "", false},
		{"no denial here", logNoise, "", "", false},
		{"empty", "", "", "", false},
	}
	for _, c := range cases {
		op, target, ok := parseDenialLine(c.line, "codex")
		if ok != c.ok || op != c.wantOp || target != c.wantTarget {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)", c.name, op, target, ok, c.wantOp, c.wantTarget, c.ok)
		}
	}
}

func TestParseDenialLineRejectsUnsafeNames(t *testing.T) {
	// The name goes into a quoted log predicate.
	for _, name := range []string{`co"dex`, "codex (1)", "", "codex) deny(1", strings.Repeat("x", 65)} {
		if _, _, ok := parseDenialLine(logIoctl, name); ok {
			t.Errorf("parseDenialLine accepted the process name %q", name)
		}
	}
}

func TestAggregateDenialsCountsAndOrders(t *testing.T) {
	lines := []string{logWrite, logIoctl, logIoctl, logIoctl, logSock, logPref, logNoise, logAllow}
	shown, hidden := aggregateDenials(lines, "codex")
	if len(hidden) != 1 {
		t.Fatalf("hidden = %v, want one VoiceOver preference read", hidden)
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
		"refused by the sandbox (kernel log, codex,",
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
	queryKernelLog = func(string, time.Time, time.Time) ([]string, error) {
		return []string{logIoctl, logIoctl, logSocket, logPref, logPref}, nil
	}
	var b strings.Builder
	printRunExplain(&b, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
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
	queryKernelLog = func(string, time.Time, time.Time) ([]string, error) {
		return nil, errExplainUnsupported
	}
	var b strings.Builder
	printRunExplain(&b, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	out := b.String()
	if !strings.Contains(out, "macOS kernel log") || !strings.Contains(out, "EPERM") {
		t.Errorf("Linux should say it cannot do this rather than print an empty table:\n%s", out)
	}
	if strings.Contains(out, "nothing was refused") {
		t.Error("an unsupported platform must not report a clean run")
	}
}

func TestPrintRunExplainColourClosesEveryLine(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(string, time.Time, time.Time) ([]string, error) {
		return nil, errExplainUnsupported
	}
	on := emit.Palette(true)
	var plain, coloured strings.Builder
	printRunExplain(&plain, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	printRunExplain(&coloured, "codex", time.Now().Add(-time.Minute), time.Now(), on)
	if got := ansiSequences.ReplaceAllString(coloured.String(), ""); got != plain.String() {
		t.Errorf("colour changed the note.\nplain:\n%s\ncoloured, stripped:\n%s", plain.String(), got)
	}
	for _, line := range strings.Split(coloured.String(), "\n") {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, on.Reset) {
			t.Errorf("an unclosed escape leaks colour into the shell: %q", line)
		}
	}
}

func TestPrintRunExplainQueryFailure(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(string, time.Time, time.Time) ([]string, error) {
		return nil, errors.New("the log query timed out; try a shorter run")
	}
	var b strings.Builder
	printRunExplain(&b, "codex", time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
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
	printRunExplain(&b, `co"dex`, time.Now().Add(-time.Minute), time.Now(), emit.Styles{})
	if !strings.Contains(b.String(), "cannot search the kernel log") {
		t.Error("an unsafe command name should be refused before the query")
	}
}
