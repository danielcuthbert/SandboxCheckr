//go:build linux

package bridge

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// netnsTestEnv re-runs this test binary inside a private network namespace,
// which is the only place lo is reliably down.
const netnsTestEnv = "SANDBOXCHECKR_TEST_NETNS"

// TestEnsureLoopbackIsQuietWhenTheInterfaceIsUp covers the ordinary case: the
// bridge shares the host's namespace, lo is already up, so there is nothing to
// do and nothing to report.
func TestEnsureLoopbackIsQuietWhenTheInterfaceIsUp(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface here: %v", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Skip("lo is already down on this host, so this is the bring-up case")
	}
	if err := EnsureLoopback(); err != nil {
		t.Errorf("EnsureLoopback with lo up: %v", err)
	}
}

// TestLinkUpReportsWhyItFailed is the regression. The ioctl return used to be
// discarded, so a sandbox whose loopback never came up was reported as fine and
// every connection inside it failed with nothing to explain why.
func TestLinkUpReportsWhyItFailed(t *testing.T) {
	err := linkUp("sbxnosuchif")
	if err == nil {
		t.Fatal("bringing up an interface that does not exist reported success")
	}
	if !strings.Contains(err.Error(), "sbxnosuchif") {
		t.Errorf("the error does not name the interface: %v", err)
	}
}

// TestEnsureLoopbackBringsInterfaceUp runs the same check the bridge needs: in a
// fresh network namespace lo starts down, and after EnsureLoopback it must be
// raised and bindable, which is what lets the DNS relay bind port 53.
func TestEnsureLoopbackBringsInterfaceUp(t *testing.T) {
	if os.Getenv(netnsTestEnv) == "1" {
		// Child: inside the namespace, report through the exit status.
		if err := EnsureLoopback(); err != nil {
			fmt.Fprintf(os.Stderr, "EnsureLoopback: %v\n", err)
			os.Exit(1)
		}
		iface, err := net.InterfaceByName("lo")
		if err != nil {
			fmt.Fprintf(os.Stderr, "looking up lo: %v\n", err)
			os.Exit(1)
		}
		if iface.Flags&net.FlagUp == 0 {
			fmt.Fprintln(os.Stderr, "lo is still down after EnsureLoopback")
			os.Exit(1)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintf(os.Stderr, "binding the loopback after EnsureLoopback: %v\n", err)
			os.Exit(1)
		}
		_ = ln.Close()
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare(1) here, cannot make a private network namespace")
	}
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net",
		os.Args[0], "-test.run=TestEnsureLoopbackBringsInterfaceUp", "-test.count=1")
	cmd.Env = append(os.Environ(), netnsTestEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// A kernel that refuses unprivileged user or network namespaces is a
		// property of the host, not of the bridge.
		if strings.Contains(strings.ToLower(string(out)), "not permitted") {
			t.Skipf("unprivileged namespaces unavailable: %s", strings.TrimSpace(string(out)))
		}
		t.Fatalf("EnsureLoopback in a fresh network namespace: %v\n%s", err, out)
	}
}
