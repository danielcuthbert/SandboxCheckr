package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
)

// foundCommand returns a command every platform can find in PATH — this test
// binary itself — so validation tests reach the flag checks instead of failing
// the command lookup first (e.g. /usr/bin/true does not exist on Windows).
func foundCommand(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestRunRejectsAllowFlagInjection(t *testing.T) {
	project := t.TempDir()
	if got := runSandbox([]string{"--workdir", project, "--allow", "api.example.com --observe", foundCommand(t)}); got != 2 {
		t.Fatalf("exit status = %d, want 2", got)
	}
}

func TestRunEventLogStaysOutsideProject(t *testing.T) {
	project := t.TempDir()
	for _, path := range []string{filepath.Join(project, "events.jsonl"), filepath.Join(project, "new", "events.jsonl")} {
		if _, err := eventLogForRun(path, project); err == nil {
			t.Fatalf("agent-writable event log %q must be refused", path)
		}
	}
}

func TestRunArtifactUsesPrivateDirectory(t *testing.T) {
	dir := t.TempDir()
	art := mechanism.Artifact{FileName: "runner.sh", FileBody: "#!/bin/sh\nexit 0\n",
		ExtraFiles: map[string]string{"profile.sb": "(version 1)\n"}}
	if err := writeRunArtifact(dir, art); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runner.sh", "profile.sb"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeRunArtifact(dir, mechanism.Artifact{FileName: "../escape.sh"}); err == nil {
		t.Fatal("artifact path traversal must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "escape.sh")); !os.IsNotExist(err) {
		t.Fatal("artifact escaped its private directory")
	}
}

func TestRunProxyWordsCannotSplitIntoFlags(t *testing.T) {
	for _, s := range []string{"api.example.com:GET:/safe path", "api.example.com:GET:/safe*", "api.example.com:GET:/safe;--observe"} {
		if safeProxyWord(s) {
			t.Errorf("accepted %q", s)
		}
	}
	if !safeProxyWord("registry.example:GET,HEAD:/org/") {
		t.Fatal("ordinary rule rejected")
	}
	if !strings.Contains(runUsage, "sandboxcheckr run claude") {
		t.Fatal("run help lacks one-command example")
	}
}

// Generic commands previously fell through to the proxy's api.anthropic.com
// default; they must start with nothing reachable. Claude and Codex keep their
// provider endpoints.
func TestAllowFlagsForDenyByDefault(t *testing.T) {
	cases := []struct {
		name             string
		command          string
		allows, rules    []string
		ports, privHosts []string
		want             string
	}{
		{"generic denies all", "sh", nil, nil, nil, nil, "--deny-all"},
		{"claude keeps provider", "claude", nil, nil, nil, nil, "--allow api.anthropic.com"},
		{"codex keeps provider", "codex", nil, nil, nil, nil, "--allow api.openai.com"},
		{"generic with allow", "sh", []string{"registry.example"}, nil, nil, nil, "--allow registry.example"},
		{"generic with rule only", "sh", nil, []string{"registry.example:GET,HEAD"}, nil, nil, "--rule registry.example:GET,HEAD"},
		{"claude with extras", "claude", []string{".github.com"}, nil, nil, nil, "--allow api.anthropic.com --allow .github.com"},
		{"local inference endpoint", "sh", []string{"localhost"}, nil, []string{"11434"}, []string{"localhost"},
			"--allow localhost --allow-port 11434 --allow-private-host localhost"},
	}
	for _, c := range cases {
		if got := allowFlagsFor(c.command, c.allows, c.rules, c.ports, c.privHosts); got != c.want {
			t.Errorf("%s: allowFlagsFor = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRunRejectsInvalidAllowPort(t *testing.T) {
	project := t.TempDir()
	for _, port := range []string{"99999", "443;--observe", "http"} {
		if got := runSandbox([]string{"--workdir", project, "--allow-port", port, foundCommand(t)}); got != 2 {
			t.Fatalf("--allow-port %q: exit status = %d, want 2", port, got)
		}
	}
}

func TestRunRejectsInvalidPrivateHost(t *testing.T) {
	project := t.TempDir()
	if got := runSandbox([]string{"--workdir", project, "--allow-private-host", "not a host", foundCommand(t)}); got != 2 {
		t.Fatalf("exit status = %d, want 2", got)
	}
}

func TestRunRejectsObserveWithPortOrPrivateHost(t *testing.T) {
	project := t.TempDir()
	for _, flag := range []string{"--allow-port", "--allow-private-host"} {
		args := []string{"--workdir", project, "--observe", flag, "8080", foundCommand(t)}
		if got := runSandbox(args); got != 2 {
			t.Fatalf("%s with --observe: exit status = %d, want 2", flag, got)
		}
	}
}

// A proxy decision log inside the project is editable by the sandboxed
// program, so an inherited PROXY_LOG pointing there must be refused.
func TestRunRefusesProxyLogInsideProject(t *testing.T) {
	project := t.TempDir()
	t.Setenv("PROXY_LOG", filepath.Join(project, "proxy.log"))
	if got := runSandbox([]string{"--workdir", project, foundCommand(t)}); got != 2 {
		t.Fatalf("exit status = %d, want 2", got)
	}
}

// The command lookup must fail before the proxy starts, with exit status 127.
func TestRunCommandNotFoundFailsFast(t *testing.T) {
	project := t.TempDir()
	if got := runSandbox([]string{"--workdir", project, "definitely-not-installed-xyz"}); got != 127 {
		t.Fatalf("exit status = %d, want 127", got)
	}
}

func TestPathHelpExplainsFix(t *testing.T) {
	for _, want := range []string{"PATH", "absolute path", "version manager"} {
		if !strings.Contains(pathHelp, want) {
			t.Errorf("path help lacks %q", want)
		}
	}
}
