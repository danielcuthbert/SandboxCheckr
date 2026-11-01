package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
)

func TestRunRejectsAllowFlagInjection(t *testing.T) {
	project := t.TempDir()
	if got := runSandbox([]string{"--workdir", project, "--allow", "api.example.com --observe", "/usr/bin/true"}); got != 2 {
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
