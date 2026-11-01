// Package agentscan discovers sandbox profiles that other agent tools have
// already placed on this host, and lints each one.
//
// It exists because "am I protected?" should first reflect what is actually
// wrapping your agents today, not a hypothetical sandbox. If an agent tool has
// installed a profile, this finds it, reads it, and reports its posture using
// the same static linter a user could run by hand.
//
// It is read-only: it stats and reads files, nothing more.
package agentscan

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/sblint"
)

// knownGlobs are locations where agent tools keep Seatbelt profiles, relative to
// $HOME. Globs are matched case-sensitively. The list is intentionally small and
// specific; a too-broad scan would surface every stray .sb on the machine.
var knownGlobs = []string{
	".gemini/*.sb",
	".codex/*.sb",
	".config/*/sandbox.sb",
	".config/*/*-sandbox.sb",
}

// Run finds and lints agent sandbox profiles under the user's home directory.
func Run() []model.AgentSandbox {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []model.AgentSandbox

	for _, g := range knownGlobs {
		matches, _ := filepath.Glob(filepath.Join(home, g))
		for _, path := range matches {
			// Resolve so the same file reached by two globs is reported once.
			real := path
			if r, err := filepath.EvalSymlinks(path); err == nil {
				real = r
			}
			if seen[real] {
				continue
			}
			seen[real] = true

			fi, err := os.Stat(real)
			if err != nil || fi.IsDir() {
				continue
			}
			body, err := os.ReadFile(real)
			if err != nil {
				continue
			}
			out = append(out, assess(path, string(body)))
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// assess lints one profile and maps the result onto the report model.
func assess(path, body string) model.AgentSandbox {
	res := sblint.Lint(body)

	a := model.AgentSandbox{
		Tool:      toolFromPath(path),
		Path:      path,
		Egress:    string(res.Egress),
		ReadsOpen: res.ReadsOpen,
	}
	// Most severe first, so the report leads with what matters.
	findings := append([]sblint.Finding(nil), res.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) < sevRank(findings[j].Severity)
	})
	for _, f := range findings {
		a.Findings = append(a.Findings, model.Gap{
			Severity: f.Severity,
			Title:    f.Title,
			Detail:   f.Detail,
		})
	}
	return a
}

// toolFromPath infers the owning tool from the profile's directory. For a path
// like ~/.config/<tool>/claude-sandbox.sb this is "<tool>"; for ~/.codex/… it is
// "codex".
func toolFromPath(path string) string {
	dir := filepath.Dir(path)
	name := filepath.Base(dir)
	if name == ".config" || name == "" {
		name = filepath.Base(path)
	}
	return strings.TrimPrefix(name, ".")
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}
