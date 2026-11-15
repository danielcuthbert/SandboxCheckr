//go:build linux

// Package bwrap implements the bubblewrap mechanism for Linux.
//
// bubblewrap is the practical choice for unprivileged confinement on Linux: it
// needs no root, no daemon and no image, and it builds the sandbox out of the
// kernel's own namespace primitives. It is the same machinery Flatpak uses.
//
// Like the Seatbelt implementation, two variants are offered — strict (no
// network namespace access) and practical (network shared) — because a
// configuration that a coding agent cannot run in will simply be worked around.
package bwrap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

// Mechanism implements mechanism.Mechanism for bubblewrap.
type Mechanism struct {
	network bool
	// proxyPort, when non-zero, gives the sandbox an empty network namespace
	// and a single route out: a loopback port inside the sandbox bridged to
	// the allow-listing proxy's unix socket on the host.
	proxyPort int
	// autoPort is accepted for symmetry with Seatbelt. Inside an unshared
	// network namespace the loopback port is private to each sandbox, so two
	// sandboxes cannot collide on it; what must be unique is the host-side
	// socket, which the runner names per run.
	autoPort bool
}

// NewStrict denies network by giving the sandbox its own empty network namespace.
func NewStrict() *Mechanism { return &Mechanism{network: false} }

// NewPractical shares the host network namespace.
func NewPractical() *Mechanism { return &Mechanism{network: true} }

// NewProxied isolates the network namespace and permits egress only through
// the allow-listing proxy.
//
// A network namespace has its own loopback, so the host's 127.0.0.1 is not
// reachable from inside. The bridge is a unix socket in the workdir — which is
// bind-mounted, so the same path exists on both sides — plus a tiny forwarder
// (this binary's __bridge subcommand) running INSIDE the sandbox under the
// same restrictions, listening on the sandbox's loopback. Nothing else crosses
// the namespace boundary.
func NewProxied(port int, auto bool) *Mechanism {
	return &Mechanism{network: true, proxyPort: port, autoPort: auto}
}

func (m *Mechanism) ID() string {
	switch {
	case m.proxyPort != 0:
		return "bubblewrap-proxy"
	case m.network:
		return "bubblewrap-network"
	default:
		return "bubblewrap-strict"
	}
}

func (m *Mechanism) Name() string {
	switch {
	case m.proxyPort != 0:
		return "bubblewrap — proxied (allow-listed egress)"
	case m.network:
		return "bubblewrap — practical (network permitted)"
	default:
		return "bubblewrap — strict (no network)"
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

// ChildProxyAddr implements mechanism.Proxied.
func (m *Mechanism) ChildProxyAddr() string { return fmt.Sprintf("127.0.0.1:%d", m.proxyPort) }

// UsesProxy implements mechanism.Proxied.
func (m *Mechanism) UsesProxy() bool { return m.proxyPort != 0 }

// ProxyEndpoint implements mechanism.Proxied: the proxy listens on a unix
// socket inside the workdir, which the sandbox sees at the same path.
func (m *Mechanism) ProxyEndpoint(w mechanism.Workdir) (string, string) {
	return "unix", ProxySocket(w.Path)
}

// ProxySocket is where the host-side proxy listens for a sandbox scoped to
// workdir. Kept short: unix socket paths are limited to ~108 bytes.
func ProxySocket(workdir string) string { return filepath.Join(workdir, ".scr-proxy.sock") }

func (m *Mechanism) Tradeoff() string {
	if m.proxyPort != 0 {
		return "The sandbox has an empty network namespace whose only route out is the allow-listing " +
			"proxy, so direct sockets, DNS and the cloud metadata endpoint are unreachable and the proxy " +
			"alone decides which hosts are. The residual risk is the hosts you allow: one that stores or " +
			"forwards is still a route out."
	}
	if m.network {
		return "Filesystem and PID namespaces are isolated but the host network is shared, so egress " +
			"is unrestricted: a piped download works and readable data can leave. Pair with nftables " +
			"or an egress proxy for per-host control."
	}
	return "The sandbox is given an empty network namespace, so by construction the process has no " +
		"route off the machine; confirm with the net.egress probe. Any program needing the network " +
		"will not work."
}

func (m *Mechanism) Summary() string {
	base := "Builds an unprivileged sandbox from Linux namespaces: a private mount tree, " +
		"PID namespace, and no_new_privs. Needs no root and no daemon."
	switch {
	case m.proxyPort != 0:
		return base + " This variant permits egress only to allow-listed hosts via a local proxy."
	case m.network:
		return base + " This variant shares the host network."
	default:
		return base + " This variant has an isolated, empty network namespace."
	}
}

// Detect confirms bwrap exists and can actually construct a sandbox.
//
// Presence is not enough: bubblewrap depends on unprivileged user namespaces,
// which hardened and container-hosted kernels frequently disable. The only
// reliable check is to build a trivial sandbox and see whether it works.
func (m *Mechanism) Detect(ctx context.Context) model.Availability {
	path, trusted, err := sysexec.LookupUnprivileged("bwrap")
	if err != nil {
		return model.Availability{
			Status: model.StatusAbsent,
			Detail: "bubblewrap (bwrap) is not installed; installing it would provide unprivileged " +
				"namespace-based confinement",
		}
	}

	out, err := sysexec.Run(ctx, path, "--ro-bind", "/", "/", "--dev", "/dev", "/bin/true")
	if err != nil {
		msg := strings.TrimSpace(out)
		low := strings.ToLower(msg)
		if strings.Contains(low, "user namespace") || strings.Contains(low, "unshare") ||
			strings.Contains(low, "permission denied") || strings.Contains(low, "operation not permitted") {
			return model.Availability{
				Status: model.StatusDegraded,
				Path:   path,
				Detail: "bwrap is installed but cannot create a sandbox, which usually means " +
					"unprivileged user namespaces are disabled on this kernel: " + msg,
			}
		}
		return model.Availability{
			Status: model.StatusIndeterminate,
			Path:   path,
			Detail: "bwrap failed unexpectedly: " + msg,
		}
	}

	av := model.Availability{
		Status: model.StatusPass,
		Path:   path,
		Detail: "bwrap is present and can construct a sandbox",
	}
	if !trusted {
		av.Detail += " (resolved via PATH rather than a system directory, so the binary itself " +
			"carries weaker trust than a system tool)"
	}
	return av
}

// Opts parameterises the sandbox.
type Opts struct {
	// Workdir is the one writable location.
	Workdir string
	// Home is the user's home path. It is recreated inside the sandbox as an
	// EMPTY directory, so programs that expect $HOME to exist still start,
	// while nothing from the real home is present.
	Home string
	// Network shares the host network namespace when true and Proxied is false.
	Network bool
	// Proxied isolates the network and leaves only the proxy bridge.
	Proxied bool
	// ExtraRO are further directories bound read-only, e.g. the directory of
	// the program being run when it lives under /home.
	ExtraRO []string
	// Env is the complete environment inside the sandbox.
	Env []string
	// HideFiles are dotenv files inside the workdir, replaced with an empty
	// read-only file so their contents are absent from the sandbox.
	HideFiles []string
	// ReadOnly are paths inside the workdir (git hooks and config, CI
	// workflows, editor tasks) re-bound read-only over the writable workdir.
	ReadOnly []string
}

// Args builds the bubblewrap argument list, up to and including "--".
//
// Single source of truth shared by Confine and Wrapper, so the command we test
// is the command we recommend.
//
// Shape: bind the system read-only, give the workdir the only writable bind,
// and replace /home with an empty tmpfs so credentials in the real home are not
// merely unreadable but absent from the mount namespace entirely. That is a
// stronger guarantee than a deny rule, since there is nothing there to deny.
//
// Order matters: bubblewrap applies mounts in sequence and a later mount hides
// an earlier one. Every bind that must survive (the workdir, the program's own
// directory) therefore comes AFTER the tmpfs mounts over /home and /tmp. The
// first version of this function bound the program's directory first, so a
// binary under /home was hidden by the tmpfs and could not be executed.
func Args(o Opts) []string {
	args := []string{
		// Read-only view of the system.
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/lib32", "/lib32",
		"--ro-bind-try", "/etc", "/etc",
		"--ro-bind-try", "/nix/store", "/nix/store",
		"--ro-bind-try", "/opt", "/opt",
	}
	args = append(args,
		// Empty home: the credentials are not hidden, they are not present.
		"--tmpfs", "/home",
		"--tmpfs", "/root",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
	)
	if o.Network && !o.Proxied {
		// /etc/resolv.conf is commonly a symlink into /run (systemd-resolved,
		// NetworkManager). Without these the shared-network variant has a
		// network but no DNS, which looks like containment and is not. Bound
		// after the /run tmpfs so it does not hide them.
		args = append(args,
			"--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",
			"--ro-bind-try", "/run/NetworkManager", "/run/NetworkManager",
			"--ro-bind-try", "/run/resolvconf", "/run/resolvconf",
		)
	}
	if o.Home != "" {
		args = append(args, "--dir", o.Home)
	}
	args = append(args,
		// Minimal device and kernel interfaces.
		"--dev", "/dev",
		"--proc", "/proc",
	)
	for _, d := range o.ExtraRO {
		args = append(args, "--ro-bind-try", d, d)
	}
	args = append(args,
		// The one writable location, bound last so nothing above hides it.
		"--bind", o.Workdir, o.Workdir,
		"--chdir", o.Workdir,
	)
	// Workdir protections (SBX-011), mounted over the workdir bind so they
	// win. bubblewrap can only mount over paths that exist, so these cover
	// what is present at launch; see the gap list.
	for _, f := range o.HideFiles {
		args = append(args, "--ro-bind", "/dev/null", f)
	}
	for _, p := range o.ReadOnly {
		args = append(args, "--ro-bind", p, p)
	}
	args = append(args,

		// Isolate everything we can.
		//
		// --unshare-user-try is what actually neutralises setuid binaries: in a
		// private user namespace a setuid-root file is owned by an unmapped uid,
		// so its setuid bit grants nothing. This matters most when the invoker is
		// root or when bwrap is the setuid-root build — cases where the mount
		// namespace alone would not stop escalation via sudo/pkexec/newgrp.
		"--unshare-user-try",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--die-with-parent",

		// Drop all capabilities, so neither a setuid-root binary nor a root
		// invoker yields privileged operations inside the sandbox.
		"--cap-drop", "ALL",

		// A new session prevents TIOCSTI terminal-injection into the parent's
		// tty. (Setuid escalation is handled by the user namespace above.)
		"--new-session",

		// Start from an empty environment and set exactly what the probes ran
		// with, so API keys in the caller's shell are not silently inherited.
		"--clearenv",
	)
	for _, kv := range o.Env {
		k, v, _ := strings.Cut(kv, "=")
		args = append(args, "--setenv", k, v)
	}
	if !o.Network || o.Proxied {
		args = append(args, "--unshare-net")
	}
	return append(args, "--")
}

// bridgeArgv wraps argv so it runs behind the in-sandbox proxy bridge.
func bridgeArgv(self string, port int, sock string, argv []string) []string {
	out := []string{self, BridgeSubcommand,
		"--listen", fmt.Sprintf("127.0.0.1:%d", port), "--to", sock, "--"}
	return append(out, argv...)
}

// BridgeSubcommand is the hidden argv[1] that runs the in-sandbox forwarder.
const BridgeSubcommand = "__bridge"

func (m *Mechanism) env(home, scratch string) []string {
	var extra []string
	if m.proxyPort != 0 {
		extra = mechanism.ProxyEnv(fmt.Sprintf("http://127.0.0.1:%d", m.proxyPort))
	}
	// This mechanism replaces /tmp with a private per-sandbox tmpfs, so probes
	// running inside must not report a shared-scratch peer channel.
	extra = append(extra, "SANDBOXCHECKR_PRIVATE_TMP=1")
	return mechanism.SandboxEnv(home, scratch, extra)
}

func (m *Mechanism) Confine(ctx context.Context, w mechanism.Workdir, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command supplied")
	}
	path, _, err := sysexec.LookupUnprivileged("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bwrap unavailable: %w", err)
	}

	home := homeDir()
	// The probe binary may live under /home (a checkout run as ./bin/...),
	// which the tmpfs hides; bind its directory back in, after the tmpfs.
	binDir := filepath.Dir(argv[0])
	if mechanism.TooBroadToGrant(binDir) {
		return nil, fmt.Errorf("refusing to bind %s (the directory of %s): / and $HOME are too broad; move the binary into its own directory", binDir, argv[0])
	}
	o := Opts{
		Workdir: w.Path,
		Home:    home,
		Network: m.network,
		Proxied: m.proxyPort != 0,
		ExtraRO: []string{binDir},
		Env:     m.env(home, "/tmp"),
	}
	o.HideFiles, o.ReadOnly = mechanism.ProtectedInWorkdir(w.Path)
	if m.proxyPort != 0 {
		argv = bridgeArgv(argv[0], m.proxyPort, ProxySocket(w.Path), argv)
	}
	args := append(Args(o), argv...)

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd, nil
}

func (m *Mechanism) Wrapper(w mechanism.Workdir) (mechanism.Artifact, error) {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&b, "# Generated by SandboxCheckr (%s), scoped to %s\n", m.ID(), w.Path)
	b.WriteString("#\n# Usage: sh " + m.ID() + ".sh <command> [args...]\n")
	b.WriteString("#\n# Optional, set when invoking:\n")
	b.WriteString("#   PASS_ENV  names of variables to pass in (default: none)\n")
	b.WriteString("#   EXTRA_RO  extra directories to bind read-only\n")
	b.WriteString("#   EXTRA_RW  extra directories to bind read-write\n")
	b.WriteString("#   ALLOW_DOTENV=1       let the program read and write .env files in the workdir\n")
	b.WriteString("#   ALLOW_EXEC_CONFIG=1  let it write git hooks/config, CI workflows, editor tasks\n")
	if m.proxyPort != 0 {
		b.WriteString("#   ALLOW     proxy allow-list flags (default: --allow api.anthropic.com)\n")
		b.WriteString("#   BIND_PORTS  ports to bind on the sandbox loopback so direct connections\n")
		b.WriteString("#               reach the proxy too, e.g. 8000 (default: none)\n")
		b.WriteString("#   AGENT     label for this run in the event log (default: <command>-<pid>)\n")
		b.WriteString("#   EVENTS    event log for sandboxcheckr console (default: ~/.local/state/sandboxcheckr/events.jsonl)\n")
		b.WriteString("#   DENY_FILE hosts to cut off live, even if allowed (default: ~/.config/sandboxcheckr/deny.txt)\n")
		b.WriteString("#   CANARY=0  disable planted credentials; CANARY_KILL=1 stops on a high-confidence trip\n")
	}
	b.WriteString("set -eu\n\n")
	fmt.Fprintf(&b, "WORKDIR=%s\n", shQuote(w.Path))
	b.WriteString("PASS_ENV=\"${PASS_ENV:-}\"\nEXTRA_RO=\"${EXTRA_RO:-}\"\nEXTRA_RW=\"${EXTRA_RW:-}\"\n")
	if m.proxyPort != 0 {
		b.WriteString("ALLOW=\"${ALLOW:---allow api.anthropic.com}\"\n")
		b.WriteString("BIND_PORTS=\"${BIND_PORTS:-}\"\n")
		fmt.Fprintf(&b, "SANDBOXCHECKR_DEFAULT=%s\n", selfPath())
		// The binary is pinned, not env-overridable: an inherited
		// SANDBOXCHECKR would run attacker code outside the sandbox.
		b.WriteString("SANDBOXCHECKR=\"$SANDBOXCHECKR_DEFAULT\"\n")
		// Private per-run directory for the proxy socket and CA bundle. It is
		// outside the workdir, so a peer agent sharing the workdir can neither
		// see the socket path nor hijack it, and the sandboxed program cannot
		// tamper with the CA bundle (bound read-only). Removed at exit.
		b.WriteString("PRIVDIR=$(mktemp -d /tmp/sandboxcheckr-run.XXXXXX)\n")
		b.WriteString("SOCK=\"$PRIVDIR/proxy.sock\"\n")
		b.WriteString("PRIV_IN=\"/tmp/.sandboxcheckr-run\"\n")
		b.WriteString("HERE=$(cd \"$(dirname \"$0\")\" && pwd)\n")
		// The decision log lives outside the workdir, in a private per-run
		// directory the sandboxed program can neither see nor edit. It is
		// kept after the run, like the event log, so decisions stay
		// inspectable; PROXY_LOG= overrides for a trusted parent.
		b.WriteString("# The per-run decision log lives outside the workdir, in a private directory:\n" +
			"# the sandboxed program can neither see nor edit it. PROXY_LOG= overrides.\n" +
			"if [ -z \"${PROXY_LOG:-}\" ]; then\n" +
			"  LOGDIR=$(mktemp -d /tmp/sandboxcheckr-log.XXXXXX)\n" +
			"  PROXY_LOG=\"$LOGDIR/proxy.log\"\n" +
			"fi\n")
		// The event log lives outside the workdir, where the sandboxed program
		// cannot forge or erase it, and is shared by every runner so the
		// console can compare agents.
		b.WriteString("EVENTS=\"${EVENTS:-${XDG_STATE_HOME:-$HOME/.local/state}/sandboxcheckr/events.jsonl}\"\n")
		// Shared by every runner, outside the workdir: the agent must not be
		// able to edit its own kill switch.
		b.WriteString("DENY_FILE=\"${DENY_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/sandboxcheckr/deny.txt}\"\n")
		b.WriteString("CA_BUNDLE=\"$PRIVDIR/ca.pem\"\n")
		// Name resolution inside the sandbox goes to the proxy's gated DNS
		// relay on the loopback the bridge binds. The relay file is prepared
		// here; the bind that puts it where the resolver looks is emitted with
		// the other binds, once /etc/resolv.conf's true location is known.
		// The relay sits on port 53, which the bridge can bind because it runs
		// in its own network namespace (see the unshare below).
		b.WriteString("printf 'nameserver 127.0.0.1\\noptions timeout:2 attempts:2\\n' > \"$PRIVDIR/resolv.conf\"\n")
	}
	b.WriteString(`
[ $# -ge 1 ] || { echo "usage: sh $0 <command> [args...]" >&2; exit 2; }
CMD_PATH=$(command -v "$1" 2>/dev/null) || {
  echo "command not found: $1" >&2
  echo "  Looked up in this shell's PATH. Fixes:" >&2
  echo "    - install it, or run it by absolute path: sh $0 /absolute/path/to/$1 ..." >&2
  echo "    - if it comes from a version manager (nvm, pyenv, mise, ...), source that manager's init script in this shell first" >&2
  echo "    - check the search path with: echo \$PATH" >&2
  exit 127
}
CMD_REAL=$(realpath "$CMD_PATH")
BWRAP_PATH=$(command -v bwrap 2>/dev/null) || { echo "bwrap not found" >&2; exit 127; }
shift
`)
	if m.proxyPort != 0 {
		b.WriteString(`
# Start the allow-listing proxy on a unix socket in the workdir, which the
# sandbox sees at the same path, and wait until it is listening.
READY="$SOCK.ready"
rm -f "$SOCK" "$READY" "$CA_BUNDLE"
mkdir -p "$(dirname "$PROXY_LOG")" "$(dirname "$EVENTS")"
AGENT="${AGENT:-$(basename "$CMD_PATH")-$$}"
CANARY_DIR=""
CANARY_FLAGS=""
CANARY_MOUNT="/tmp/sandboxcheckr-canary"
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
  "$SANDBOXCHECKR" canary new --file "$CANARY_JSON" --dir "$CANARY_DATA" --mount "$CANARY_MOUNT" \
    --pass-env "$PASS_ENV" --extra "$EXTRA_RO $EXTRA_RW"
  if [ "${CANARY_KILL:-0}" = 1 ]; then CANARY_FLAGS="--canary-kill"; fi
fi
proxy_start() {
  if [ -n "$CANARY_DIR" ]; then
    exec "$SANDBOXCHECKR" proxy --unix "$SOCK" --dns-unix "$PRIVDIR/dns.sock" --ready-file "$READY" --log "$PROXY_LOG" \
      --events "$EVENTS" --agent "$AGENT" --deny-file "$DENY_FILE" --ca-bundle-out "$CA_BUNDLE" \
      --canaries "$CANARY_JSON" --canary-trip-file "$CANARY_TRIP_FILE" --canary-pid-file "$CANARY_PID_FILE" $CANARY_FLAGS $ALLOW >/dev/null
  fi
  exec "$SANDBOXCHECKR" proxy --unix "$SOCK" --dns-unix "$PRIVDIR/dns.sock" --ready-file "$READY" --log "$PROXY_LOG" \
    --events "$EVENTS" --agent "$AGENT" --deny-file "$DENY_FILE" --ca-bundle-out "$CA_BUNDLE" $ALLOW >/dev/null
}
proxy_start &
PROXY_PID=$!
# Recorded for sandboxcheckr run: if this runner is killed before its trap
# stops the proxy, run stops it so the exit summary is still printed.
echo "$PROXY_PID" > "$HERE/.proxy-pid" 2>/dev/null || true
trap 'kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; rm -rf "$PRIVDIR"; if [ -n "$CANARY_DIR" ]; then rm -rf "$CANARY_DIR"; fi' EXIT INT TERM
i=0
until [ -s "$READY" ]; do
  i=$((i + 1))
  if [ "$i" -gt 100 ] || ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "the egress proxy did not start; see $PROXY_LOG" >&2; exit 1
  fi
  sleep 0.1
done
echo "sandboxcheckr: running $CMD_REAL (selected from host PATH as $CMD_PATH)" >&2
echo "sandboxcheckr: egress proxy on $SOCK — decisions logged to $PROXY_LOG, events to $EVENTS as $AGENT" >&2
`)
	}

	o := Opts{
		Workdir: w.Path,
		Home:    "$HOME",
		Network: m.network,
		Proxied: m.proxyPort != 0,
		Env:     m.env("$HOME", "/tmp"),
	}
	args := Args(o)

	// Build argv back to front by prepending, so the user's own arguments stay
	// last and nothing they contain can be mistaken for a bwrap option: first
	// "-- [bridge] command", then the per-run binds and environment, and
	// finally the fixed arguments that were probed.
	b.WriteString("\n# The command (and, for the proxied variant, the in-sandbox bridge).\n")
	if m.proxyPort != 0 {
		fmt.Fprintf(&b, "set -- -- \"$SANDBOXCHECKR\" %s --listen 127.0.0.1:%d --to \"$PRIV_IN/proxy.sock\" --dns-sock \"$PRIV_IN/dns.sock\" ${BIND_PORTS:+--bind-ports \"$BIND_PORTS\"} -- \"$CMD_PATH\" \"$@\"\n",
			BridgeSubcommand, m.proxyPort)
		// The bridge gets its own network namespace so the DNS relay can bind
		// port 53 unprivileged; in a fresh namespace it brings the interface
		// up itself. Skipped where unshare is unavailable or disallowed, which
		// leaves name resolution unavailable but everything else working.
		b.WriteString("if command -v unshare >/dev/null 2>&1 && unshare --user --map-root-user --net true 2>/dev/null; then\n")
		b.WriteString("  set -- unshare --user --map-root-user --net \"$@\"\nfi\n")
	} else {
		b.WriteString("set -- -- \"$CMD_PATH\" \"$@\"\n")
	}
	b.WriteString(bindGuard)
	// argv is built by prepending, so what is prepended FIRST ends up LAST.
	// The protections go in before EXTRA_RW and the program binds, so in the
	// final argv they follow every writable bind and win over it.
	b.WriteString(runnerProtect)
	// The tool's own binary, when it lives inside the workdir (repo-as-workdir),
	// is pinned read-only: a sandboxed program must not be able to replace what
	// the user will execute next.
	fmt.Fprintf(&b, "case %s in \"$WORKDIR\"/*) set -- --ro-bind %s %s \"$@\" ;; esac\n",
		shQuote(selfPath()), shQuote(selfPath()), shQuote(selfPath()))
	if m.proxyPort != 0 {
		// The private per-run dir (proxy socket, CA bundle) is visible inside
		// only through this read-only bind at a fixed path; the host path never
		// appears in the child's view and a peer sharing the workdir cannot
		// find it to hijack. Emitted after the command lookup so it cannot
		// clobber the child argv, and only for proxied runs (PRIVDIR exists
		// there alone).
		b.WriteString("set -- --ro-bind \"$PRIVDIR\" \"$PRIV_IN\" \"$@\"\n")
		// Put the sandbox resolver's address where the resolver looks.
		// /etc/resolv.conf is commonly a symlink into /run (systemd-resolved),
		// and the tmpfs there hides the target, so the bind lands on the path
		// the symlink points at; a plain file is replaced directly.
		b.WriteString(`
RESOLV_TARGET=$(readlink -f /etc/resolv.conf 2>/dev/null || echo /etc/resolv.conf)
case "$RESOLV_TARGET" in
  /run/*)
    mkdir "$PRIVDIR/resolve"
    cp "$PRIVDIR/resolv.conf" "$PRIVDIR/resolve/$(basename "$RESOLV_TARGET")"
    set -- --ro-bind "$PRIVDIR/resolve" "$(dirname "$RESOLV_TARGET")" "$@" ;;
  *)
    set -- --ro-bind "$PRIVDIR/resolv.conf" /etc/resolv.conf "$@" ;;
esac
`)
	}
	b.WriteString("\n# Program directories, bound read-only AFTER the tmpfs over /home so they are not hidden.\n")
	b.WriteString("for d in \"$(dirname \"$CMD_PATH\")\" \"$(dirname \"$CMD_REAL\")\" \"$(dirname \"$(dirname \"$CMD_REAL\")\")\"; do\n")
	b.WriteString("  r=$(resolve \"$d\")\n")
	b.WriteString("  # The workdir is already bound with the user's policy: a program directory\n")
	b.WriteString("  # at or inside it needs no bind of its own, and one above it would shadow\n")
	b.WriteString("  # the writable grants inside the workdir (bwrap keeps the last bind of a\n")
	b.WriteString("  # path), so skip both and leave the workdir's own grants standing.\n")
	b.WriteString("  case \"$r\" in \"$WORKDIR\"|\"$WORKDIR\"/*) continue ;; esac\n")
	b.WriteString("  case \"$WORKDIR\" in \"$r\"|\"$r\"/*) continue ;; esac\n")
	b.WriteString("  if too_broad \"$r\"; then echo \"sandboxcheckr: not binding $d (too broad)\" >&2; continue; fi\n")
	b.WriteString("  set -- --ro-bind-try \"$d\" \"$d\" \"$@\"\ndone\n")
	if m.proxyPort != 0 {
		b.WriteString("set -- --ro-bind \"$SANDBOXCHECKR\" \"$SANDBOXCHECKR\" \"$@\"\n")
	}
	b.WriteString("for d in $EXTRA_RO; do r=$(resolve \"$d\"); too_broad \"$r\" && refuse EXTRA_RO \"$d\"; set -- --ro-bind \"$d\" \"$d\" \"$@\"; done\n")
	b.WriteString("for d in $EXTRA_RW; do r=$(resolve \"$d\"); too_broad \"$r\" && refuse EXTRA_RW \"$d\"; set -- --bind \"$d\" \"$d\" \"$@\"; done\n")
	b.WriteString("for name in $PASS_ENV; do eval \"val=\\${$name-}\"; set -- --setenv \"$name\" \"$val\" \"$@\"; done\n")
	if m.proxyPort != 0 {
		b.WriteString(`if [ -n "$CANARY_DIR" ]; then
  OLD_IFS=$IFS
  IFS='
'
  for kv in $("$SANDBOXCHECKR" canary env --file "$CANARY_JSON"); do
    name=${kv%%=*}
    value=${kv#*=}
    set -- --setenv "$name" "$value" "$@"
  done
  IFS=$OLD_IFS
  set -- --dir "$CANARY_MOUNT" --ro-bind "$CANARY_DATA" "$CANARY_MOUNT" "$@"
fi
`)
	}
	if m.proxyPort != 0 {
		b.WriteString("# --rule hosts are TLS-inspected; trust this run's constrained CA inside the sandbox only.\n")
		b.WriteString("if [ -s \"$CA_BUNDLE\" ]; then\n")
		b.WriteString("  for v in SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO PIP_CERT; do\n")
		b.WriteString("    set -- --setenv \"$v\" \"$PRIV_IN/ca.pem\" \"$@\"\n  done\nfi\n")
	}
	b.WriteString("\n")

	// The fixed arguments from Args, minus its trailing "--" (supplied above),
	// one option per line. They come before "$@", so the per-run --setenv
	// above lands after --clearenv and the per-run binds after the tmpfs.
	// Clear the launcher's environment before bwrap starts: --clearenv only
	// applies to the payload, after bwrap has created its namespaces.
	if m.proxyPort != 0 {
		// Not exec: the shell must survive to run the trap that stops the proxy.
		b.WriteString("run_confined() {\n/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \"$BWRAP_PATH\" \\\n")
	} else {
		b.WriteString("exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \"$BWRAP_PATH\" \\\n")
	}
	fixed := args[:len(args)-1]
	for i := 0; i < len(fixed); {
		line := []string{shWord(fixed[i])}
		i++
		for i < len(fixed) && !strings.HasPrefix(fixed[i], "--") {
			line = append(line, shWord(fixed[i]))
			i++
		}
		b.WriteString("  " + strings.Join(line, " ") + " \\\n")
	}
	b.WriteString("  \"$@\"\n")
	if m.proxyPort != 0 {
		b.WriteString(`}
status=0
if [ "${CANARY_KILL:-0}" = 1 ] && [ -n "$CANARY_DIR" ]; then
  exec 3<&0
  run_confined "$@" <&3 &
  CHILD_PID=$!
  exec 3<&-
  printf '%s\n' "$CHILD_PID" > "$CANARY_PID_FILE"
  wait "$CHILD_PID" || status=$?
else
  run_confined "$@" || status=$?
fi
# Separate the program's own output from what the egress proxy observed, so
# the summary that follows reads as the observed side of the run.
echo >&2 "── observed connection attempts (this run's egress proxy) ──"
kill "$PROXY_PID" 2>/dev/null || true
proxy_status=0
wait "$PROXY_PID" 2>/dev/null || proxy_status=$?
if [ "$proxy_status" -eq 3 ]; then exit 3; fi
if [ -n "$CANARY_DIR" ] && [ -s "$CANARY_TRIP_FILE" ]; then exit 3; fi
exit "$status"
`)
	}

	notes := []string{
		"Run: sh " + m.ID() + ".sh <command> [args...]",
		"/home is replaced with an empty tmpfs (with an empty $HOME recreated), so credentials are absent from the mount namespace rather than merely denied.",
		"The environment is cleared; name anything the program needs in PASS_ENV. Everything passed is readable by it.",
		"The command's own directory is bound read-only automatically. Add others with EXTRA_RO / EXTRA_RW. For Claude Code that is typically EXTRA_RW=\"$HOME/.claude\".",
		"Inside the workdir, .env files present at launch are replaced with an empty file, and existing git hooks/config, " +
			"CI workflows, editor tasks (.vscode, .idea), .husky, .envrc and .pre-commit-config.yaml are mounted read-only. " +
			"Opt out per class with ALLOW_DOTENV=1 or ALLOW_EXEC_CONFIG=1. bubblewrap can only protect paths that exist " +
			"when the run starts — run git init before starting the agent, not during.",
	}
	switch {
	case m.proxyPort != 0:
		notes = append(notes,
			"The sandbox has no network namespace route out except the proxy bridge. Discover the allow-list with: sandboxcheckr proxy --observe")
		notes = append(notes, proxy.KnownLimits()...)
	case m.network:
		notes = append(notes, "This variant shares the host network. Prefer bubblewrap-proxy for per-host control.")
	default:
		notes = append(notes, "This variant has no network at all. Anything needing egress will fail.")
	}

	return mechanism.Artifact{
		FileName: m.ID() + ".sh",
		FileBody: b.String(),
		Command:  "sh " + m.ID() + ".sh <your-command>",
		Notes:    notes,
	}, nil
}

// runnerProtect applies the workdir protections (SBX-011) at launch. The
// paths are found when the runner starts, not when it was emitted, because
// bubblewrap can only mount over paths that exist: a .env file or hook
// directory created DURING the run is not covered (see KnownGaps). The find
// expressions mirror mechanism.IsWorkdirSecret and mechanism.ExecConfigPaths.
const runnerProtect = `
# Workdir protections (SBX-011): .env files are replaced with an empty file,
# and files other programs execute later are mounted read-only. find output is
# split on newlines only, so paths containing spaces survive.
NL='
'
OLD_IFS=$IFS
if [ "${ALLOW_DOTENV:-0}" = 1 ]; then
  echo "sandboxcheckr: ALLOW_DOTENV=1 — .env files in the workdir are readable by the program" >&2
else
  IFS=$NL
  for f in $(find "$WORKDIR" \( -name node_modules -o -name .venv -o -name vendor -o -name target \) -prune \
      -o \( -name .env -o -name '.env.*' \) -print 2>/dev/null); do
    if [ -d "$f" ]; then
      # A directory named .env (or .env.*) must be hidden too, not just files.
      set -- --tmpfs "$f" "$@"
    elif [ -n "${CANARY_DIR:-}" ] && [ -f "$CANARY_DATA/dotenv" ]; then
      set -- --ro-bind "$CANARY_DATA/dotenv" "$f" "$@"
    else
      set -- --ro-bind /dev/null "$f" "$@"
    fi
  done
  IFS=$OLD_IFS
fi
if [ "${ALLOW_EXEC_CONFIG:-0}" = 1 ]; then
  echo "sandboxcheckr: ALLOW_EXEC_CONFIG=1 — git hooks, CI workflows and editor tasks are writable; review them before you commit or open the editor" >&2
else
  for d in .git/hooks .git/config .github/workflows; do
    if [ -e "$WORKDIR/$d" ]; then set -- --ro-bind "$WORKDIR/$d" "$WORKDIR/$d" "$@"; fi
  done
  IFS=$NL
  for f in $(find "$WORKDIR" \( -name node_modules -o -name .venv -o -name vendor -o -name target \) -prune \
      -o \( -name .vscode -o -name .idea -o -name .husky -o -name .envrc -o -name .pre-commit-config.yaml \) -print -prune 2>/dev/null); do
    set -- --ro-bind "$f" "$f" "$@"
  done
  IFS=$OLD_IFS
fi
`

// bindGuard defines the runner's checks against binding / or $HOME (or
// anything above $HOME) into the sandbox. Either would undo the empty /home
// tmpfs and expose every credential it hides. Paths are resolved first, so a
// symlink to / is caught too. Automatic program-directory binds that are too
// broad are skipped; an explicit EXTRA_RO / EXTRA_RW request is refused.
const bindGuard = `
resolve() { r=$(realpath -m -- "$1" 2>/dev/null || printf '%s\n' "$1"); while [ "$r" != "${r%/}" ] && [ "$r" != / ]; do r=${r%/}; done; printf '%s\n' "$r"; }
HOME_REAL=$(resolve "${HOME:-/var/empty}")
too_broad() {
  case "$1" in ""|/|*/..|*/../*|*/.|*/./*|[!/]*) return 0 ;; esac
  [ "$1" = "$HOME_REAL" ] && return 0
  case "$HOME_REAL/" in "$1"/*) return 0 ;; esac
  return 1
}
refuse() { echo "refusing $1 path $2: / and \$HOME are too broad to bind" >&2; exit 2; }
`

// shWord renders one bwrap argument as a shell word. Values containing $HOME
// are double-quoted so the shell expands them at run time; everything else is
// single-quoted.
func shWord(s string) string {
	if strings.Contains(s, "$HOME") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r == '-' || r == '/' || r == '.' || r == '_' || r == ':' || r == '=' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) < 0 {
		return s
	}
	return shQuote(s)
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func selfPath() string {
	if exe, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		return shQuote(exe)
	}
	return "sandboxcheckr"
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		if r, err := filepath.EvalSymlinks(h); err == nil {
			return r
		}
		return h
	}
	return "/home/sandbox"
}

func (m *Mechanism) KnownGaps() []model.Gap {
	gaps := []model.Gap{
		{
			Severity: "medium",
			Title:    "bubblewrap shares the host kernel",
			Detail: "Namespaces are a kernel-enforced boundary, not a hardware one. A kernel " +
				"vulnerability reachable from inside the sandbox escapes it. For untrusted code " +
				"where that matters, a VM boundary (Firecracker, Kata, a full VM) is stronger.",
		},
		{
			Severity: "medium",
			Title:    "No syscall filtering is applied by default",
			Detail: "This configuration uses namespaces but installs no seccomp filter, so the " +
				"confined process can still issue any syscall. Adding --seccomp with a compiled " +
				"BPF program narrows the kernel attack surface considerably.",
		},
		{
			Severity: "medium",
			Title:    "Workdir protections cover only paths that exist at launch",
			Detail: "bubblewrap protects .env files and git hooks/config, CI workflows and editor tasks by " +
				"mounting over them, and it can only mount over paths that exist when the run starts. A " +
				".env file, .git directory or .vscode folder created during the run is unprotected, and so " +
				"is a .env written under a new name. Seatbelt matches by pattern and does not have this " +
				"limit. Create the repository (git init) before starting the agent.",
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
			Severity: "low",
			Title:    "Depends on unprivileged user namespaces",
			Detail: "Hardened kernels and some container hosts disable unprivileged user " +
				"namespaces, which disables bubblewrap entirely. SandboxCheckr verifies a sandbox " +
				"can actually be constructed rather than assuming it.",
		},
	}
	if m.proxyPort != 0 {
		gaps = append(gaps, model.Gap{
			Severity: "high",
			Title:    "An allow-listed host is still an exfiltration route if it stores or forwards",
			Detail: "A package registry, object store or paste service on the allow-list can be written to " +
				"and can fetch onward — the route agents used in the 2026 OpenAI–Hugging Face incident. " +
				"Narrow such hosts to downloads with ALLOW=\"--allow registry.example --rule " +
				"registry.example:GET,HEAD\"; the proxy also flags any host receiving over 1 MiB. A code " +
				"host (raw.githubusercontent.com, gist) needs a path rule too, e.g. " +
				"--rule raw.githubusercontent.com:GET,HEAD:/your-org/, because download-only still lets in " +
				"a payload staged in someone else's repository.",
		})
	}
	if m.network && m.proxyPort == 0 {
		gaps = append(gaps, model.Gap{
			Severity: "high",
			Title:    "The host network is shared in this variant",
			Detail: "Egress is unrestricted, so a piped download still executes and any readable " +
				"data can still be exfiltrated. The cloud metadata endpoint is also reachable, " +
				"which on a CI runner or cloud VM can yield instance credentials.",
		})
	}
	return gaps
}
