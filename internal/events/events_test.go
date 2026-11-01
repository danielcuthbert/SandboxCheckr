package events

import (
	"bytes"
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
