// Package mechanism defines the abstraction every confinement technology
// implements, so that ranking and reporting stay free of OS-specific knowledge.
package mechanism

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Workdir is the scratch directory a sandbox is configured to permit writes to.
// It stands in for "the project directory you want the agent to work in".
type Workdir struct {
	// Path is the absolute directory the sandbox should allow.
	Path string
}

// Artifact is a generated wrapper: the thing a user can actually run.
type Artifact struct {
	// Command is the copy-pasteable invocation.
	Command string
	// FileName is the name of the supporting file, if the mechanism needs one
	// (a Seatbelt .sb profile, for instance). Empty when not applicable.
	FileName string
	// FileBody is the content of that supporting file.
	FileBody string
	// Notes explains what the user should know before running it.
	Notes []string
	// ExtraFiles are additional artifacts written alongside FileName, keyed by
	// filename. A proxied configuration needs both a runner script and the
	// profile it invokes, and emitting one without the other gives the user a
	// sandbox that cannot work.
	ExtraFiles map[string]string
}

// Mechanism is one way of confining a process.
//
// Confine and Wrapper are deliberately built from the same configuration: the
// probe harness calls Confine to test the sandbox, and the emitter calls
// Wrapper to hand the user a command. Sharing the underlying profile means we
// cannot recommend a configuration we never exercised — the single most useful
// property of the design, because "the profile I tested" and "the profile I
// printed" drifting apart is how these tools come to lie.
type Mechanism interface {
	// ID is the stable machine name, e.g. "seatbelt".
	ID() string
	// Name is the human label, e.g. "macOS Seatbelt (sandbox-exec)".
	Name() string
	// Summary is one plain sentence on what this mechanism stops.
	Summary() string
	// PermitsNetwork reports whether this configuration allows egress. A
	// strict variant scores higher but cannot run anything that needs the
	// network, so the two facts must always be reported together.
	PermitsNetwork() bool
	// Tradeoff states in one sentence what choosing this costs.
	Tradeoff() string
	// BestFor says in a few words what this configuration is the right choice
	// for, so a reader can pick a column without reading the probe rows.
	BestFor() string
	// Egress is "none", "proxy" or "open": the network this configuration
	// permits by design. The report puts it beside the measured score so a
	// reader can see at a glance whether a high score came from denying the
	// network an agent needs.
	Egress() string

	// Detect performs passive detection. It must not have side effects and
	// must not spawn confined children.
	Detect(ctx context.Context) model.Availability

	// Confine wraps argv into a command that runs inside this sandbox, scoped
	// so that w.Path is writable and little else is. Returning an error means
	// the sandbox could not be constructed, which the harness records as
	// INDETERMINATE rather than as a containment success.
	Confine(ctx context.Context, w Workdir, argv []string) (*exec.Cmd, error)

	// Wrapper renders the user-facing artifact for this mechanism.
	Wrapper(w Workdir) (Artifact, error)

	// KnownGaps lists exposures this mechanism cannot address even when
	// working perfectly. These are documented limits, not probe results, and
	// they are reported whether or not a probe happened to catch them.
	KnownGaps() []model.Gap
}

// Proxied is implemented by mechanisms whose egress goes through the
// allow-listing proxy. The harness starts a real proxy on the returned endpoint
// for the duration of a probe run, so a proxied configuration is measured with
// its egress component present — scoring it without the proxy would measure a
// different, broken configuration.
type Proxied interface {
	// UsesProxy reports whether this instance actually routes through the
	// proxy; a type may implement Proxied for only some of its variants.
	UsesProxy() bool
	// ProxyEndpoint returns where the proxy must listen for a sandbox scoped to
	// w: network is "tcp" or "unix", addr the address or socket path.
	ProxyEndpoint(w Workdir) (network, addr string)
	// ChildProxyAddr is the TCP address the confined program dials to reach
	// the proxy from inside the sandbox.
	ChildProxyAddr() string
}

// SandboxEnv is the environment every confined program starts with, both when
// SandboxCheckr probes a sandbox and when the emitted wrapper runs one.
//
// It exists as one definition because the two drifting apart is a lie the tool
// would tell: if the probes ran with a scrubbed environment while the wrapper
// passed the caller's through, exfil.env.secrets would credit the sandbox for
// keeping API keys out when the user's real run hands them straight in. The
// generated runner scripts reproduce exactly this set.
//
// extra carries variables a specific variant needs (proxy settings), already
// in NAME=VALUE form.
func SandboxEnv(home, tmpdir string, extra []string) []string {
	env := []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + home,
		"TMPDIR=" + tmpdir,
		"LANG=en_US.UTF-8",
		"TERM=xterm-256color",
		"SHELL=/bin/sh",
	}
	return append(env, extra...)
}

// ProxyEnv is the set of variables that points a program at an HTTP proxy.
// NODE_USE_ENV_PROXY teaches Node 22.21+ and 24.5+ to honour them (fetch only
// on 24.0–24.4). It is an environment variable rather than
// NODE_OPTIONS=--use-env-proxy because an older Node refuses to start when
// NODE_OPTIONS names a flag it does not know.
func ProxyEnv(url string) []string {
	return []string{
		"HTTP_PROXY=" + url, "HTTPS_PROXY=" + url,
		"http_proxy=" + url, "https_proxy=" + url,
		"NODE_USE_ENV_PROXY=1",
	}
}

// Project-directory protections.
//
// The workdir is writable on purpose — it is the positive control — but two
// kinds of file inside it are worth more to an attacker than the rest:
//
//   - secrets kept next to the code (.env and its variants), which is all the
//     backdoored model in ProjectDiscovery's 2026 demo needed to steal; and
//   - files that make OTHER programs execute code later, outside the sandbox:
//     git hooks and git config (core.hooksPath, core.fsmonitor), CI workflows,
//     editor task definitions, direnv's .envrc. A confined program that writes
//     one of these has not escaped yet; you let it out the next time you
//     commit, push or open the editor.
//
// Both mechanisms deny these by default, with an opt-in per class on the
// runner (ALLOW_DOTENV=1, ALLOW_EXEC_CONFIG=1). See SBX-011 in the threat model.

// IsWorkdirSecret reports whether a file name is a dotenv file: ".env" or
// ".env.<anything>" (.env.local, .env.production, and also .env.example, which
// is usually harmless but is often a copy of the real thing).
func IsWorkdirSecret(name string) bool {
	return name == ".env" || strings.HasPrefix(name, ".env.")
}

// ExecConfigPaths are workdir-relative paths whose contents another program
// executes later. Directories cover everything beneath them.
//
// This is a list of the common, high-value cases, not a closure. Anything a
// build tool runs — package.json scripts, a Makefile, setup.py — is also code
// you will execute later, and cannot be write-protected without breaking the
// agent's ability to edit the project. Review the diff before you run it.
var ExecConfigPaths = []string{
	".git/hooks",
	".git/config",
	".github/workflows",
	".vscode",
	".idea",
	".husky",
	".envrc",
	".pre-commit-config.yaml",
}

// SkipWhenScanning are directories not descended into when looking for
// protected files: they are large, generated, and not where these files live.
var SkipWhenScanning = []string{"node_modules", ".venv", "vendor", "target"}

// ProtectedInWorkdir finds the protected paths that currently exist under
// workdir: dotenv files at any depth, and ExecConfigPaths in the workdir and
// in any nested repository. It is what a mechanism that can only protect
// existing paths (bubblewrap, which binds over them) needs; Seatbelt matches
// by pattern and does not use it.
//
// The third result is the first entry the walk could not read, and the lists
// come back with whatever was found before that. Empty lists with no error
// mean there was nothing to protect; empty lists with an error mean the scan
// could not tell, which a caller must not present as a protected workdir.
func ProtectedInWorkdir(workdir string) (secrets, execConfig []string, err error) {
	skip := map[string]bool{}
	for _, d := range SkipWhenScanning {
		skip[d] = true
	}
	var walkErr error
	_ = filepath.WalkDir(workdir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// Keep the entries already found, but remember that the picture
			// is incomplete: a workdir this process cannot read is not a
			// workdir with nothing in it to protect.
			if walkErr == nil {
				walkErr = err
			}
			return nil
		}
		if d.IsDir() {
			if p != workdir && skip[d.Name()] {
				return filepath.SkipDir
			}
			if d.Name() == ".git" {
				// Only hooks and config matter inside a repository's git dir.
				for _, rel := range []string{"hooks", "config"} {
					if _, err := os.Lstat(filepath.Join(p, rel)); err == nil {
						execConfig = append(execConfig, filepath.Join(p, rel))
					}
				}
				return filepath.SkipDir
			}
			if isExecConfig(p) {
				execConfig = append(execConfig, p)
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case IsWorkdirSecret(d.Name()) && d.Type().IsRegular():
			secrets = append(secrets, p)
		case isExecConfig(p):
			execConfig = append(execConfig, p)
		}
		return nil
	})
	return secrets, execConfig, walkErr
}

// isExecConfig matches ExecConfigPaths other than those under .git, which the
// walk handles itself.
func isExecConfig(p string) bool {
	for _, rel := range ExecConfigPaths {
		if strings.HasPrefix(rel, ".git/") {
			continue
		}
		if strings.HasSuffix(p, string(filepath.Separator)+filepath.FromSlash(rel)) {
			return true
		}
	}
	return false
}

// TooBroadToGrant reports whether granting path to a sandbox would undo it:
// the filesystem root, the user's home directory, or any ancestor of home.
// Symlinks are resolved first, so a link to / is caught too.
func TooBroadToGrant(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return true
	}
	p := filepath.Clean(path)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if p == string(filepath.Separator) {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	home = filepath.Clean(home)
	if r, err := filepath.EvalSymlinks(home); err == nil {
		home = r
	}
	return p == home || strings.HasPrefix(home, p+string(filepath.Separator))
}
