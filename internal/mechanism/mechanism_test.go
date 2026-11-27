package mechanism

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestProtectedInWorkdirFindsWhatExists(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config/.env")
	write("node_modules/dep/.env")
	write(".git/hooks/pre-commit")
	write("tools/.pre-commit-config.yaml")

	secrets, execConfig, err := ProtectedInWorkdir(dir)
	if err != nil {
		t.Fatalf("scanning a readable workdir: %v", err)
	}
	wantSecret := filepath.Join(dir, "config", ".env")
	if !slices.Contains(secrets, wantSecret) {
		t.Errorf("secrets = %v, want it to include %s", secrets, wantSecret)
	}
	if slices.Contains(secrets, filepath.Join(dir, "node_modules", "dep", ".env")) {
		t.Error("node_modules must not be descended into")
	}
	for _, want := range []string{
		filepath.Join(dir, ".git", "hooks"),
		filepath.Join(dir, "tools", ".pre-commit-config.yaml"),
	} {
		if !slices.Contains(execConfig, want) {
			t.Errorf("execConfig = %v, want it to include %s", execConfig, want)
		}
	}
}

// TestProtectedInWorkdirReportsAnUnreadableWorkdir is the regression: every
// walk error used to be swallowed, so a workdir this process could not read
// came back with nothing to protect and the sandbox launched with .env
// readable and git hooks writable, with no warning anywhere.
func TestProtectedInWorkdirReportsAnUnreadableWorkdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows chmod does not enforce Unix permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory it has no permission for anyway")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, ".env"), []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	secrets, execConfig, err := ProtectedInWorkdir(locked)
	if err == nil {
		t.Fatalf("an unreadable workdir reported no error; found secrets=%v execConfig=%v", secrets, execConfig)
	}
	if len(secrets) != 0 || len(execConfig) != 0 {
		t.Errorf("an unreadable workdir reported protection it cannot have seen: %v %v", secrets, execConfig)
	}
}

// TestProtectedInWorkdirKeepsWhatItFoundBeforeAnError: a workdir where one
// subdirectory is unreadable still has its readable half protected, but the
// caller has to be told the picture is incomplete.
func TestProtectedInWorkdirKeepsWhatItFoundBeforeAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows chmod does not enforce Unix permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory it has no permission for anyway")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	secrets, _, err := ProtectedInWorkdir(dir)
	if err == nil {
		t.Fatal("an unreadable subdirectory reported no error")
	}
	if !slices.Contains(secrets, filepath.Join(dir, ".env")) {
		t.Errorf("the readable half of the workdir was dropped: %v", secrets)
	}
}
