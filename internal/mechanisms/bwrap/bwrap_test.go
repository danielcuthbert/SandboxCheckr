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
	for _, pair := range [][2]string{{"--ro-bind-try", "/home/u/bin"}, {"--bind", "/home/u/proj"}, {"--dir", "/home/u"}} {
		if i := indexPair(args, pair[0], pair[1]); i < tmpfs {
			t.Errorf("%s %s at %d must come after --tmpfs /home at %d", pair[0], pair[1], i, tmpfs)
		}
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
		"observed connection attempts",
		"Looked up in this shell's PATH",
	} {
		if !strings.Contains(art.FileBody, want) {
			t.Errorf("proxied runner lacks %q", want)
		}
	}
}
