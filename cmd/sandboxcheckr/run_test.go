package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms"
	"github.com/danielcuthbert/sandboxcheckr/internal/projconfig"
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

func TestMergeProjectConfigUnionsListsAndFillsScalars(t *testing.T) {
	cfg := &projconfig.Config{
		Allows:   []string{"api.example.com"},
		Ports:    []string{"8000"},
		RO:       []string{"/tmp/tools"},
		Observe:  false,
		NoCanary: true,
		Agent:    "from-file",
		Events:   "/tmp/events.jsonl",
	}
	o := &runOptions{
		allows:  multiFlag{"localhost"},
		ports:   multiFlag{"11434"},
		observe: true,
	}
	mergeProjectConfig(cfg, map[string]bool{"observe": true}, o)
	if got := []string(o.allows); got[0] != "api.example.com" || got[1] != "localhost" {
		t.Fatalf("allows union order: %q", got)
	}
	if got := []string(o.ports); len(got) != 2 || got[0] != "8000" || got[1] != "11434" {
		t.Fatalf("ports union: %q", got)
	}
	if len(o.ro) != 1 || o.ro[0] != "/tmp/tools" {
		t.Fatalf("ro: %q", o.ro)
	}
	// observe was set on the command line, so it wins over the file's false.
	if !o.observe {
		t.Fatal("command line observe lost to config")
	}
	// no-canary was not set, so the file's value applies.
	if !o.noCanary {
		t.Fatal("config no-canary not applied")
	}
	if o.agent != "from-file" || o.events != "/tmp/events.jsonl" {
		t.Fatalf("scalars: agent=%q events=%q", o.agent, o.events)
	}
}

func TestMergeProjectConfigFileDoesNotOverrideSetFlags(t *testing.T) {
	cfg := &projconfig.Config{Agent: "from-file", Observe: true, NoCanary: true}
	o := &runOptions{agent: "from-flag"}
	// Only --agent was set on the command line: it wins; the file's other
	// scalars fill in.
	mergeProjectConfig(cfg, map[string]bool{"agent": true}, o)
	if o.agent != "from-flag" {
		t.Fatalf("agent: %q, want from-flag", o.agent)
	}
	if !o.observe || !o.noCanary {
		t.Fatalf("unset scalars must come from the file: observe=%v noCanary=%v", o.observe, o.noCanary)
	}
}

func TestMergeProjectConfigNil(t *testing.T) {
	o := &runOptions{allows: multiFlag{"localhost"}}
	mergeProjectConfig(nil, map[string]bool{}, o)
	if len(o.allows) != 1 {
		t.Fatalf("nil config must be a no-op, got %q", o.allows)
	}
}

func TestDetectVenvPrefersActivatedThenProject(t *testing.T) {
	project := t.TempDir()
	if _, _, ok := detectVenv(project); ok {
		t.Fatal("no venv should be detected in an empty project")
	}
	// In-project .venv.
	if err := os.MkdirAll(filepath.Join(project, ".venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, bin, ok := detectVenv(project)
	if !ok || root != filepath.Join(project, ".venv") || bin != filepath.Join(root, "bin") {
		t.Fatalf("in-project venv: root=%q bin=%q ok=%v", root, bin, ok)
	}
	// An activated VIRTUAL_ENV wins over the in-project one.
	activated := t.TempDir()
	if err := os.MkdirAll(filepath.Join(activated, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VIRTUAL_ENV", activated)
	root, _, ok = detectVenv(project)
	if !ok || root != activated {
		t.Fatalf("activated venv: root=%q ok=%v", root, ok)
	}
	// A VIRTUAL_ENV without bin/ is ignored.
	broken := t.TempDir()
	t.Setenv("VIRTUAL_ENV", broken)
	empty := t.TempDir()
	if _, _, ok := detectVenv(empty); ok {
		t.Fatal("venv without bin/ must not be detected")
	}
}

func TestProjectEventsPathIsStableAndDistinct(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	pa, pb := projectEventsPath(a), projectEventsPath(b)
	if pa != projectEventsPath(a) {
		t.Fatal("path must be deterministic")
	}
	if pa == pb {
		t.Fatal("different projects must not share a log")
	}
	if !strings.Contains(pa, filepath.Join("projects", "", "events.jsonl")) &&
		!strings.Contains(pa, string(filepath.Separator)+"projects"+string(filepath.Separator)) {
		t.Fatalf("path %q is not under projects/", pa)
	}
	dir := filepath.Base(filepath.Dir(pa))
	if len(dir) != 8 {
		t.Fatalf("hash directory %q is not 8 characters", dir)
	}
}

func TestRunRejectsBrokenProjectConfig(t *testing.T) {
	project := t.TempDir()
	bad := "allow = [\"ok\"]\nnot-a-key = true\n"
	if err := os.WriteFile(filepath.Join(project, "sandboxcheckr.toml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runSandbox([]string{"--workdir", project, foundCommand(t)}); got != 2 {
		t.Fatalf("exit status = %d, want 2", got)
	}
}

func TestRunConfigObserveCannotCombineWithAllow(t *testing.T) {
	project := t.TempDir()
	body := "observe = true\n"
	if err := os.WriteFile(filepath.Join(project, "sandboxcheckr.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runSandbox([]string{"--workdir", project, "--allow", "api.example.com", foundCommand(t)}); got != 2 {
		t.Fatalf("exit status = %d, want 2", got)
	}
}

func TestBindPortsForExcludesBridgePortAndDuplicates(t *testing.T) {
	ports := []string{"8000", strconv.Itoa(mechanisms.DefaultProxyPort), "8080", "8000"}
	got := bindPortsFor(ports)
	want := []string{"8000", "8080"}
	if len(got) != len(want) {
		t.Fatalf("bindPortsFor(%v) = %v, want %v", ports, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bindPortsFor(%v) = %v, want %v", ports, got, want)
		}
	}
	if got := bindPortsFor(nil); got != nil {
		t.Fatalf("bindPortsFor(nil) = %v, want nil", got)
	}
}

func TestParseBindPorts(t *testing.T) {
	got, err := parseBindPorts("8000, 8080")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:8000", "[::1]:8000", "127.0.0.1:8080", "[::1]:8080"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("parseBindPorts = %v, want %v", got, want)
	}
	if got, err := parseBindPorts(""); err != nil || got != nil {
		t.Fatalf("parseBindPorts(\"\") = %v, %v; want nil, nil", got, err)
	}
	for _, bad := range []string{"0", "70000", "http", "8000,x"} {
		if _, err := parseBindPorts(bad); err == nil {
			t.Fatalf("parseBindPorts(%q) accepted an invalid port", bad)
		}
	}
}
