package main

import (
	"errors"
	"strings"
	"testing"
	"time"
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
	if hidden != 1 {
		t.Fatalf("hidden = %d, want 1 (the VoiceOver preference read)", hidden)
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
	out := formatDenials(ds, 2, "codex", since, until)
	for _, want := range []string{
		"refused by the sandbox (kernel log, codex,",
		"20:20:00 to 20:21:30",
		"file-ioctl", "/dev/ttys003",
		"terminal control; this run did not inherit that device",
		"unix socket, refused by design",
		"2 routine refusals hidden",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "app-server-control.sock") {
		t.Errorf("the socket target should survive with its tail:\n%s", out)
	}
	// The count column is a column: same rune offset on both rows, whatever the
	// width of the operation or the target above and below it.
	rows := dataRows(t, out)
	if a, b := countColumn(rows[0], "3"), countColumn(rows[1], "1"); a < 0 || b < 0 || a != b {
		t.Errorf("counts not aligned: %d vs %d\n%s", a, b, out)
	}
}

// dataRows returns the table's data rows, header and prose aside.
func dataRows(t *testing.T, out string) []string {
	t.Helper()
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.Contains(line, "──") &&
			!strings.Contains(line, "operation") && !strings.Contains(line, "routine refusal") {
			rows = append(rows, line)
		}
	}
	if len(rows) == 0 {
		t.Fatalf("no data rows in:\n%s", out)
	}
	return rows
}

// countColumn is the rune offset of a count, measured in columns rather than
// bytes so a multi-byte ellipsis cannot hide a misalignment.
func countColumn(row, count string) int {
	i := strings.LastIndex(row, "  "+count)
	if i < 0 {
		return -1
	}
	return displayWidth(row[:i])
}

func TestFormatDenialsNothingRefused(t *testing.T) {
	out := formatDenials(nil, 0, "codex", time.Now().Add(-time.Minute), time.Now())
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
	}{
		{"file-write-data", "/Users/daniel/.npmrc", "--rw"},
		{"file-read-data", "/Users/daniel/.aws/credentials", "--ro"},
		{"system-socket", "domain:32 type:2 protocol:2", "socket family"},
		{"network-bind", "/tmp/worker.sock", "unix socket"},
		{"process-fork", "", ""},
		{"file-write-data", "relative/path", ""},
	}
	for _, c := range cases {
		got := adviceFor(c.op, c.target)
		if c.want == "" && got != "" {
			t.Errorf("adviceFor(%s, %s) = %q, want no advice", c.op, c.target, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("adviceFor(%s, %s) = %q, want it to mention %q", c.op, c.target, got, c.want)
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
	printRunExplain(&b, "codex", time.Now().Add(-time.Minute), time.Now())
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
	printRunExplain(&b, "codex", time.Now().Add(-time.Minute), time.Now())
	out := b.String()
	if !strings.Contains(out, "macOS kernel log") || !strings.Contains(out, "EPERM") {
		t.Errorf("Linux should say it cannot do this rather than print an empty table:\n%s", out)
	}
	if strings.Contains(out, "nothing was refused") {
		t.Error("an unsupported platform must not report a clean run")
	}
}

func TestPrintRunExplainQueryFailure(t *testing.T) {
	old := queryKernelLog
	defer func() { queryKernelLog = old }()
	queryKernelLog = func(string, time.Time, time.Time) ([]string, error) {
		return nil, errors.New("the log query timed out; try a shorter run")
	}
	var b strings.Builder
	printRunExplain(&b, "codex", time.Now().Add(-time.Minute), time.Now())
	if out := b.String(); !strings.Contains(out, "could not read the kernel log") {
		t.Errorf("a failed query should be reported, not swallowed:\n%s", out)
	}
}

func TestPrintRunExplainRejectsAwkwardCommand(t *testing.T) {
	var b strings.Builder
	printRunExplain(&b, `co"dex`, time.Now().Add(-time.Minute), time.Now())
	if !strings.Contains(b.String(), "cannot search the kernel log") {
		t.Error("an unsafe command name should be refused before the query")
	}
}
