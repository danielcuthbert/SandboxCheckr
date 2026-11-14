package projconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), Name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMissingFileReturnsNil(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), Name))
	if err != nil || cfg != nil {
		t.Fatalf("Load missing: cfg=%v err=%v", cfg, err)
	}
}

func TestLoadFullFile(t *testing.T) {
	cfg, err := Load(write(t, `
# project policy
allow = ["localhost", "127.0.0.1"]   # local inference server
rule = ["github.com:GET,HEAD:/danielcuthbert/"]
allow-port = [8000, 11434]
allow-private-host = ["localhost"]
pass-env = ["ANTHROPIC_API_KEY"]
ro = ["~/tools/raptor"]
rw = ["~/out"]
observe = false
no-canary = true
canary-kill = false
no-agent-auth = true
events = "~/logs/events.jsonl"
agent = "raptor"
deny-file = "~/deny.txt"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"localhost", "127.0.0.1"}
	for i, h := range want {
		if cfg.Allows[i] != h {
			t.Fatalf("allow %d: got %q want %q", i, cfg.Allows[i], h)
		}
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0] != "github.com:GET,HEAD:/danielcuthbert/" {
		t.Fatalf("rules: %q", cfg.Rules)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != "8000" {
		t.Fatalf("ports: %q", cfg.Ports)
	}
	home, _ := os.UserHomeDir()
	if cfg.RO[0] != filepath.Join(home, "tools", "raptor") {
		t.Fatalf("ro: %q", cfg.RO[0])
	}
	if cfg.RW[0] != filepath.Join(home, "out") {
		t.Fatalf("rw: %q", cfg.RW[0])
	}
	if !cfg.NoCanary || cfg.Observe || cfg.CanaryKill || !cfg.NoAgentAuth {
		t.Fatalf("bools: %+v", cfg)
	}
	if cfg.Events != filepath.Join(home, "logs", "events.jsonl") {
		t.Fatalf("events: %q", cfg.Events)
	}
	if cfg.Agent != "raptor" || cfg.DenyFile != filepath.Join(home, "deny.txt") {
		t.Fatalf("agent/deny: %q %q", cfg.Agent, cfg.DenyFile)
	}
}

func TestLoadEmptyArrayAndBareTilde(t *testing.T) {
	cfg, err := Load(write(t, "allow = []\nrw = [\"~\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Allows) != 0 {
		t.Fatalf("allows: %q", cfg.Allows)
	}
	home, _ := os.UserHomeDir()
	if len(cfg.RW) != 1 || cfg.RW[0] != home {
		t.Fatalf("rw: %q", cfg.RW)
	}
}

func TestLoadHashInsideStringSurvives(t *testing.T) {
	cfg, err := Load(write(t, "agent = \"agent #1\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent != "agent #1" {
		t.Fatalf("agent: %q", cfg.Agent)
	}
}

func TestLoadEscapes(t *testing.T) {
	cfg, err := Load(write(t, `agent = "a\"b\\c\nd\t"`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent != "a\"b\\c\nd\t" {
		t.Fatalf("agent: %q", cfg.Agent)
	}
}

func TestLoadLiteralStringNoEscapes(t *testing.T) {
	cfg, err := Load(write(t, `agent = 'C:\path\no\escape'`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent != `C:\path\no\escape` {
		t.Fatalf("agent: %q", cfg.Agent)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name, body, want string
		wantLine         int
	}{
		{"unknown key", "foo = true\n", `unknown key "foo"`, 1},
		{"duplicate key", "observe = true\nobserve = false\n", `duplicate key "observe"`, 2},
		{"type mismatch", "allow = \"host\"\n", "allow: expects an array of strings", 1},
		{"bool mismatch", "observe = \"yes\"\n", "observe: expects true or false", 1},
		{"no equals", "observe true\n", "expected key = value", 1},
		{"bare value", "agent = raptor\n", "cannot parse value", 1},
		{"unterminated string", "agent = \"raptor\n", "unterminated string", 1},
		{"unterminated array", "allow = [\"a\"\n", "unterminated array", 1},
		{"unquoted element", "allow = [a]\n", "array elements must be quoted strings or integers", 1},
		{"trailing junk", "agent = \"a\" extra\n", "unexpected text after string", 1},
		{"bad escape", `agent = "a\qb"`, "unsupported escape", 1},
		{"empty key", "= true\n", "empty key", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, tc.body))
			if err == nil {
				t.Fatalf("expected error for %q", tc.body)
			}
			var e *Error
			if !errorsAs(err, &e) {
				t.Fatalf("error is not *Error: %v", err)
			}
			if e.Line != tc.wantLine {
				t.Fatalf("line: got %d want %d", e.Line, tc.wantLine)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// errorsAs avoids importing errors just for As in every subtest.
func errorsAs(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestLoadLineNumbers(t *testing.T) {
	_, err := Load(write(t, "# header\n\nobserve = true\n\nfoo = 1\n"))
	var e *Error
	if !errorsAs(err, &e) || e.Line != 5 {
		t.Fatalf("want line 5, got %v", err)
	}
}
