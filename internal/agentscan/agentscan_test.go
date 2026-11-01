package agentscan

import "testing"

func TestToolFromPath(t *testing.T) {
	cases := map[string]string{
		"/Users/x/.config/acme/claude-sandbox.sb": "acme",
		"/Users/x/.codex/sandbox.sb":              "codex",
		"/Users/x/.gemini/agent.sb":               "gemini",
		"/Users/x/.config/opencode/sandbox.sb":    "opencode",
	}
	for path, want := range cases {
		if got := toolFromPath(path); got != want {
			t.Errorf("toolFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// assess must carry the linter's verdict into the report model, most-severe
// finding first.
func TestAssessMapsLintResult(t *testing.T) {
	permissive := "(allow default)\n(deny file-write*)\n(allow file-write* (subpath \"/tmp/x\"))"
	a := assess("/Users/x/.config/acme/claude-sandbox.sb", permissive)

	if a.Tool != "acme" {
		t.Errorf("tool = %q, want acme", a.Tool)
	}
	if a.Egress != "open" {
		t.Errorf("egress = %q, want open", a.Egress)
	}
	if !a.ReadsOpen {
		t.Error("reads should be open for the permissive shape")
	}
	if len(a.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if a.Findings[0].Severity != "high" {
		t.Errorf("findings should be sorted high-first, got %q", a.Findings[0].Severity)
	}
}
