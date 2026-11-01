// Package sysexec runs the external system tools SandboxCheckr depends on.
//
// It exists to enforce one rule: never resolve a tool through $PATH. A security
// tool that finds `csrutil` by searching $PATH can be handed a fake `csrutil`
// that prints "System Integrity Protection status: enabled." by anyone who can
// write to a directory earlier in the path — which is exactly the sort of
// attacker we are supposed to be reporting on. Instead we look only in a fixed
// set of system directories and require the result to be a regular file.
//
// This does not make the tool tamper-proof; an attacker who can write to
// /usr/bin has already won. It removes the cheap, unprivileged version of the
// attack, which is the one that matters.
package sysexec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// trustedDirs are the only directories we will resolve a system tool from,
// in priority order. All are root-owned on a healthy system.
var trustedDirs = func() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return []string{
			filepath.Join(root, "System32"),
			filepath.Join(root, "System32", "WindowsPowerShell", "v1.0"),
		}
	default:
		return []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"}
	}
}()

// ErrNotFound is returned when a tool is absent from every trusted directory.
// Callers should treat this as "the mechanism is not available here", never as
// a failure of the check itself.
var ErrNotFound = fmt.Errorf("tool not found in trusted directories")

// Lookup resolves a bare tool name to an absolute path inside a trusted
// directory. It deliberately ignores $PATH.
func Lookup(name string) (string, error) {
	// Reject anything that is already a path: callers pass bare names so that
	// resolution stays under our control.
	if filepath.Base(name) != name {
		return "", fmt.Errorf("%w: %q must be a bare tool name", ErrNotFound, name)
	}
	for _, dir := range trustedDirs {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		// Windows has no execute bit; the directory restriction is the control.
		if err != nil || fi.IsDir() || (runtime.GOOS != "windows" && fi.Mode()&0o111 == 0) {
			continue
		}
		return p, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, name)
}

// LookupAny returns the first of the named tools that resolves, along with its
// name. Useful where a capability may be provided by one of several binaries
// (docker or podman, say).
func LookupAny(names ...string) (name, path string, err error) {
	for _, n := range names {
		if p, e := Lookup(n); e == nil {
			return n, p, nil
		}
	}
	return "", "", fmt.Errorf("%w: none of %v", ErrNotFound, names)
}

// Run executes an absolute path and returns its combined output. Combined
// rather than separated because most of the tools we call (csrutil, spctl,
// sandbox-exec) report the interesting part on stderr, and the detectors match
// on message text.
//
// A non-zero exit is returned as an error, but the output is still returned:
// for several checks the failure message is the signal we want.
func Run(ctx context.Context, path string, args ...string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("refusing to run non-absolute path %q", path)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	// Run with an empty environment so tool behaviour cannot be steered by
	// inherited variables. Keep only a minimal, fixed set.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	if runtime.GOOS == "windows" {
		// Windows tools need SystemRoot to load at all.
		cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot"), "PATH=" + filepath.Dir(path)}
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// Exists reports whether a tool resolves in a trusted directory.
func Exists(name string) bool {
	_, err := Lookup(name)
	return err == nil
}

// LookupUnprivileged resolves a tool that is legitimately installed outside the
// system directories — container runtimes via Homebrew, nix, or a user profile,
// for example. It searches $PATH, so the result carries weaker trust than
// Lookup: a caller who can be tricked into running a fake `podman` learns
// nothing reliable.
//
// It is kept as a separate function, rather than a fallback inside Lookup, so
// that the weaker guarantee is visible at every call site. Trusted is false
// whenever the tool came from a directory we do not consider root-owned, and
// detectors surface that as a caveat in the report instead of quietly treating
// the two cases as equivalent.
func LookupUnprivileged(name string) (path string, trusted bool, err error) {
	if p, e := Lookup(name); e == nil {
		return p, true, nil
	}
	p, e := exec.LookPath(name)
	if e != nil {
		return "", false, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	abs, e := filepath.Abs(p)
	if e != nil {
		return "", false, fmt.Errorf("resolving %s: %w", name, e)
	}
	// Resolve symlinks so the report names the real backing binary; nix and
	// Homebrew both install via symlink farms.
	if resolved, e := filepath.EvalSymlinks(abs); e == nil {
		abs = resolved
	}
	return abs, false, nil
}
