package events

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Hostnames and paths come from the sandboxed program. A newline must not
// split one event into two forged ones, and escape sequences must not reach
// the terminal.
func TestHostileFieldsStayContained(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "a")
	w.Write(Event{Kind: KindConnect, Host: "evil\n{\"kind\":\"connect\",\"agent\":\"forged\"}", Path: "\x1b]52;c;cGF5bG9hZA==\x07"})
	evs, skipped := Read(&buf)
	if len(evs) != 1 || skipped != 0 {
		t.Fatalf("got %d events, %d skipped; want exactly 1", len(evs), skipped)
	}
	if evs[0].Agent != "a" {
		t.Errorf("agent %q, want a", evs[0].Agent)
	}
	if c := Clean(evs[0].Path, 0); strings.ContainsAny(c, "\x1b\x07") {
		t.Errorf("Clean left control characters: %q", c)
	}
	if c := Clean("a\u202eb", 0); strings.Contains(c, "\u202e") {
		t.Error("Clean must remove bidi overrides")
	}
}

func TestAgentLabel(t *testing.T) {
	cases := map[string]string{
		"claude-123":             "claude-123",
		"a b/c;$(rm)":            "a-b-c---rm-",
		"\x1b[31mred":            "--31mred",
		"":                       "",
		strings.Repeat("x", 100): strings.Repeat("x", 64),
	}
	for in, want := range cases {
		if got := AgentLabel(in); got != want {
			t.Errorf("AgentLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadSkipsJunk(t *testing.T) {
	in := "not json\n{\"kind\":\"connect\",\"host\":\"a\"}\n{}\n\n"
	evs, skipped := Read(strings.NewReader(in))
	if len(evs) != 1 || skipped != 2 {
		t.Errorf("got %d events, %d skipped; want 1 and 2", len(evs), skipped)
	}
}

func TestNilWriterIsSafe(t *testing.T) {
	var w *Writer
	w.Write(Event{Kind: KindConnect})
}

// A Writer that fails every write, standing in for the disk that fills up
// mid-run.
type failWriter struct{ err error }

func (f failWriter) Write(p []byte) (int, error) { return 0, f.err }

// The event log is what questions get asked of afterwards. Losing it to
// ENOSPC in silence is the failure this guards.
func TestWriteFailuresAreCounted(t *testing.T) {
	var log bytes.Buffer
	w := NewWriter(failWriter{errors.New("no space left on device")}, "a")
	w.Log = &log
	for range 3 {
		w.Write(Event{Kind: KindConnect, Host: "x.test"})
	}
	if got := w.Dropped(); got != 3 {
		t.Errorf("Dropped = %d, want 3", got)
	}
	if n := strings.Count(log.String(), "\n"); n != 1 {
		t.Errorf("first failure should log one line, got %d: %q", n, log.String())
	}
	if !strings.Contains(log.String(), "no space left on device") {
		t.Errorf("the log line should name the error: %q", log.String())
	}

	var good bytes.Buffer
	w2 := NewWriter(&good, "a")
	w2.Log = &log
	w2.Write(Event{Kind: KindConnect, Host: "x.test"})
	if w2.Dropped() != 0 {
		t.Errorf("a successful write counted as dropped: %d", w2.Dropped())
	}
	if n := strings.Count(log.String(), "\n"); n != 1 {
		t.Errorf("a working writer should log nothing, log is %q", log.String())
	}
	var nilW *Writer
	if nilW.Dropped() != 0 {
		t.Error("a nil writer has dropped nothing")
	}
}

// One line past the cap must cost that line and nothing else: a Scanner stops
// at ErrTooLong, and every event after it went missing without the skipped
// count the console prints ever moving.
func TestReadSurvivesOversizedLine(t *testing.T) {
	long := strings.Repeat("x", MaxLine+1)
	in := `{"kind":"connect","host":"a"}` + "\n" + long + "\n" + `{"kind":"connect","host":"b"}` + "\n"
	evs, skipped := Read(strings.NewReader(in))
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2: the events after a too-long line must still be read", len(evs))
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 for the discarded line", skipped)
	}
}

func TestParseLine(t *testing.T) {
	e, ok := ParseLine([]byte("  {\"kind\":\"connect\",\"host\":\"a\"}\n"))
	if !ok || e.Host != "a" {
		t.Errorf("ParseLine on an event line: %+v, %v", e, ok)
	}
	if _, ok := ParseLine([]byte("not json")); ok {
		t.Error("ParseLine accepted junk")
	}
	if _, ok := ParseLine([]byte(`{"host":"a"}`)); ok {
		t.Error("a line with no kind is not an event")
	}
}
