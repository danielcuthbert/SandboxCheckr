//go:build linux

package bwrap

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
)

// Binds that must survive have to come after the tmpfs over /home, because
// bubblewrap applies mounts in order and a later mount hides an earlier one.
// Getting this backwards hid the probe binary whenever it lived under /home.
func TestBindsFollowHomeTmpfs(t *testing.T) {
	args := Args(Opts{Workdir: "/home/u/proj", Home: "/home/u", ExtraRO: []string{"/home/u/bin"}})
	tmpfs := indexPair(args, "--tmpfs", "/home")
	if tmpfs < 0 {
		t.Fatal("/home must be replaced with a tmpfs")
	}
	for _, pair := range [][2]string{{"--ro-bind", "/home/u/bin"}, {"--bind", "/home/u/proj"}, {"--dir", "/home/u"}} {
		if i := indexPair(args, pair[0], pair[1]); i < tmpfs {
			t.Errorf("%s %s at %d must come after --tmpfs /home at %d", pair[0], pair[1], i, tmpfs)
		}
	}
	// An explicit grant binds or the run fails: --ro-bind-try would let a
	// missing grant pass, and the program then dies on something the user
	// believes they granted.
	if indexPair(args, "--ro-bind-try", "/home/u/bin") >= 0 {
		t.Error("an explicit read-only grant must not use --ro-bind-try")
	}
	// Distro variance is the opposite: a distro without /lib32 is normal.
	if indexPair(args, "--ro-bind-try", "/lib32") < 0 {
		t.Error("the distro-variance binds must tolerate a missing directory")
	}
}

func TestArgsClearEnvironment(t *testing.T) {
	args := Args(Opts{Workdir: "/w", Env: []string{"HOME=/home/u"}})
	if !slices.Contains(args, "--clearenv") {
		t.Error("the sandbox must start from an empty environment")
	}
	if indexPair(args, "--setenv", "HOME") < 0 {
		t.Error("the environment must be set explicitly")
	}
}

func TestNetworkVariants(t *testing.T) {
	if !slices.Contains(Args(Opts{Workdir: "/w"}), "--unshare-net") {
		t.Error("strict must unshare the network")
	}
	if slices.Contains(Args(Opts{Workdir: "/w", Network: true}), "--unshare-net") {
		t.Error("practical must share the network")
	}
	if !slices.Contains(Args(Opts{Workdir: "/w", Network: true, Proxied: true}), "--unshare-net") {
		t.Error("proxied must unshare the network; the bridge is its only route out")
	}
}

// The emitted wrapper must be valid sh and must not contain a placeholder that
// the shell would parse as a redirection.
func TestWrapperIsValidShell(t *testing.T) {
	for _, m := range []*Mechanism{NewStrict(), NewPractical(), NewProxied(8899, true)} {
		art, err := m.Wrapper(mechanism.Workdir{Path: "/home/u/my proj"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(art.FileBody, "<your-command>") {
			t.Errorf("%s: wrapper contains a literal placeholder", m.ID())
		}
		cmd := exec.Command("/bin/sh", "-n")
		cmd.Stdin = strings.NewReader(art.FileBody)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: wrapper is not valid sh: %v\n%s", m.ID(), err, out)
		}
	}
}

// Permitted ports must reach the in-sandbox bridge through the BIND_PORTS
// variable: the runner sets it, the bridge binds each port on the sandbox's
// loopback and tunnels direct connections through the proxy. Without a bridge
// there is nothing to bind, so the other variants must not mention it.
func TestProxiedRunnerBindsPermittedPorts(t *testing.T) {
	art, err := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: "/tmp/proj"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`BIND_PORTS="${BIND_PORTS:-}"`,
		`${BIND_PORTS:+--bind-ports "$BIND_PORTS"}`,
		`--dns-unix "$PRIVDIR/dns.sock"`,
		`--dns-sock "$PRIV_IN/dns.sock"`,
		`printf 'nameserver 127.0.0.1\noptions timeout:2 attempts:2\n' > "$PRIVDIR/resolv.conf"`,
		`RESOLV_TARGET=$(readlink -f /etc/resolv.conf 2>/dev/null || echo /etc/resolv.conf)`,
		`--ro-bind "$PRIVDIR/resolve" "$(dirname "$RESOLV_TARGET")"`,
		`--ro-bind "$PRIVDIR/resolv.conf" /etc/resolv.conf`,
		`set -- unshare --user --map-root-user --net "$@"`,
	} {
		if !strings.Contains(art.FileBody, want) {
			t.Errorf("proxied runner lacks %q", want)
		}
	}
	for _, m := range []*Mechanism{NewStrict(), NewPractical()} {
		art, err := m.Wrapper(mechanism.Workdir{Path: "/tmp/proj"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(art.FileBody, "BIND_PORTS") {
			t.Errorf("%s runner mentions BIND_PORTS without a bridge", m.ID())
		}
	}
}

// A program directory that overlaps the workdir must not be re-bound: the
// workdir's own grants (a writable out/, state dirs) would be shadowed by a
// later read-only bind of the same tree, which is what made running a binary
// that lives in the project (./bin/raptor) crash with a read-only out/.
func TestProgramDirsNeverRebindTheWorkdir(t *testing.T) {
	art, err := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: "/tmp/proj"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`case "$r" in "$WORKDIR"|"$WORKDIR"/*) continue ;; esac`,
		`case "$WORKDIR" in "$r"|"$r"/*) continue ;; esac`,
	} {
		if !strings.Contains(art.FileBody, want) {
			t.Errorf("program-dir loop lacks the workdir guard %q", want)
		}
	}
}

func indexPair(args []string, flag, val string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return i
		}
	}
	return -1
}

// The decision log is evidence about what the program did, so it must default
// to a private per-run directory outside the workdir — the sandboxed program
// can neither see nor edit it there. The runner also records the proxy PID for
// `run` to stop an orphaned proxy, and separates the program's output from the
// proxy's observed-connections summary.
func TestProxiedRunnerKeepsDecisionLogOutsideWorkdir(t *testing.T) {
	art, err := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: "/tmp/proj"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(art.FileBody, "PROXY_LOG=\"${PROXY_LOG:-$WORKDIR") {
		t.Errorf("default decision log must not live in the workdir:\n%s", art.FileBody)
	}
	for _, want := range []string{
		`LOGDIR=$(mktemp -d /tmp/sandboxcheckr-log.XXXXXX)`,
		`echo "$PROXY_PID" > "$HERE/.proxy-pid"`,
		"Looked up in this shell's PATH",
	} {
		if !strings.Contains(art.FileBody, want) {
			t.Errorf("proxied runner lacks %q", want)
		}
	}
	// The proxy separates its own summary with section headers. A banner here
	// too would put two headings on the same block of output.
	if strings.Contains(art.FileBody, "observed connection attempts") {
		t.Errorf("proxied runner echoes a summary banner:\n%s", art.FileBody)
	}
}
