package denials

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func row(command, run, op, target string, count int, t time.Time) Row {
	return Row{Time: t, Command: command, Agent: command + "-1", RunID: run, Proc: "bash", Op: op, Target: target, Count: count}
}

func TestWriteReadRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in := []Row{
		row("raptor", "raptor-1@1", "file-read-data", "/opt/local/lib/libncurses.6.dylib", 3, now),
		row("raptor", "raptor-2@2", "file-write-create", "/Users/daniel/.local/share/raptor/sessions.d", 1, now),
	}
	var buf bytes.Buffer
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Fatalf("want one line per row, got %d:\n%s", n, buf.String())
	}
	out, skipped := Read(&buf)
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if len(out) != 2 || out[0].Target != in[0].Target || out[0].Count != 3 || !out[0].Time.Equal(now) {
		t.Fatalf("round trip lost something: %+v", out)
	}
}

func TestWriteSkipsWhatItCannotPlanFrom(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, []Row{
		{Command: "raptor", Op: "file-read-data"}, // no target
		{Command: "raptor", Target: "/etc/hosts"}, // no operation
		row("raptor", "raptor-1@1", "file-read-data", "/x", 1, time.Time{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Errorf("rows without an operation or a target are not evidence: %q", buf.String())
	}
	out, _ := Read(strings.NewReader(buf.String()))
	if len(out) != 1 || out[0].Time.IsZero() {
		t.Errorf("a row written without a time should have been stamped: %+v", out)
	}
}

func TestReadCountsWhatItCannotUse(t *testing.T) {
	text := `{"command":"raptor","op":"file-read-data","target":"/a"}
not json at all

{"command":"raptor","target":"/b"}
{"command":"raptor","op":"file-read-data","target":"/c"}`
	out, skipped := Read(strings.NewReader(text))
	if len(out) != 2 {
		t.Fatalf("rows = %v, want the two usable ones", out)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want the junk line and the row with no operation said out loud", skipped)
	}
}

func TestSelectKeepsOneProgramAndItsWindow(t *testing.T) {
	now := time.Now().UTC()
	rows := []Row{
		row("raptor", "raptor-1@1", "file-read-data", "/keep", 1, now.Add(-time.Hour)),
		row("raptor", "raptor-2@2", "file-read-data", "/stale", 1, now.Add(-72*time.Hour)),
		row("codex", "codex-1@1", "file-read-data", "/another-program", 1, now),
	}
	got := Select(rows, "raptor", now.Add(-24*time.Hour))
	if len(got) != 1 || got[0].Target != "/keep" {
		t.Errorf("Select = %v, want this program's row inside the window only", got)
	}
	if n := Runs(rows); n != 3 {
		t.Errorf("Runs = %d, want three separate runs counted", n)
	}
	if n := Runs([]Row{rows[0], rows[0]}); n != 1 {
		t.Errorf("Runs = %d, want one run counted once however often it refused", n)
	}
}
