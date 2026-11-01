package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

// ProbeSubcommand is the hidden argv[1] that switches this binary into
// child-payload mode. Re-executing ourselves means there is no helper binary to
// ship or locate, and the probe code is compiled and tested with everything
// else rather than drifting as a shell script would.
const ProbeSubcommand = "__probe"

// runTimeout bounds a single confined child. A sandbox that hangs is a failed
// sandbox for our purposes, and we must not hang with it.
const runTimeout = 45 * time.Second

// Harness runs the battery inside candidate sandboxes.
type Harness struct {
	// SelfPath is the absolute path to this executable, re-executed as the
	// probe child.
	SelfPath string
	// TCC enables the opt-in macOS privacy-folder probes.
	TCC bool

	home   string
	homeID string
	online bool
	socks  []string
}

// NewHarness constructs a harness bound to the running executable.
func NewHarness() (*Harness, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locating own executable: %w", err)
	}
	// Resolve symlinks so that a sandbox profile granting exec on the real path
	// still matches when we are invoked through a symlink.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	h := &Harness{SelfPath: exe}

	// Facts about the host, gathered once from outside any sandbox and handed
	// to every child so it can judge what it sees against them.
	if home, err := os.UserHomeDir(); err == nil {
		if resolved, err := filepath.EvalSymlinks(home); err == nil {
			home = resolved
		}
		h.home = home
		if fi, err := os.Stat(home); err == nil {
			h.homeID = FileID(fi)
		}
	}
	h.socks = agentSockets(h.home)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if addrs, err := net.DefaultResolver.LookupHost(ctx, egressHost); err == nil && len(addrs) > 0 {
		h.online = true
	}
	return h, nil
}

// agentSockets lists credential agent sockets that exist on the host.
func agentSockets(home string) []string {
	var out []string
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		out = append(out, s)
	}
	if home != "" {
		for _, rel := range []string{
			"Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
			".1password/agent.sock",
			".gnupg/S.gpg-agent",
			".gnupg/S.gpg-agent.ssh",
		} {
			p := filepath.Join(home, rel)
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		for _, rel := range []string{"gnupg/S.gpg-agent", "gnupg/S.gpg-agent.ssh", "ssh-agent.socket", "gcr/ssh"} {
			p := filepath.Join(d, rel)
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// childArgs renders the parent's knowledge of the host as flags for the child.
func (h *Harness) childArgs(workdir string) []string {
	args := []string{h.SelfPath, ProbeSubcommand, "--workdir", workdir}
	if h.home != "" {
		args = append(args, "--home", h.home)
	}
	if h.homeID != "" {
		args = append(args, "--home-id", h.homeID)
	}
	if h.online {
		args = append(args, "--online")
	}
	if h.TCC {
		args = append(args, "--tcc")
	}
	for _, s := range h.socks {
		args = append(args, "--agent-socket", s)
	}
	return args
}

// Run executes the battery inside m's sandbox and returns the observed results.
//
// The scratch workdir is created here and removed afterwards, so probes never
// touch the user's real project directory.
func (h *Harness) Run(ctx context.Context, m mechanism.Mechanism) ([]model.ProbeResult, error) {
	dir, cleanup, err := scratchDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	w := mechanism.Workdir{Path: dir}
	// A proxied configuration is only the configuration it claims to be while
	// its proxy is running. Start a real, enforcing proxy with an allow-list
	// the probes never contact, so egress through it is measured as denied by
	// the same code path a user's run would take.
	var probeSrv *proxy.Server
	var canaryHost string
	if p, ok := m.(mechanism.Proxied); ok && p.UsesProxy() {
		var stop func()
		probeSrv, canaryHost, stop, err = startProbeProxy(ctx, p, w)
		if err != nil {
			return nil, fmt.Errorf("starting egress proxy: %w", err)
		}
		defer stop()
	}

	argv := h.childArgs(dir)
	if p, ok := m.(mechanism.Proxied); ok && p.UsesProxy() {
		argv = append(argv, "--expect-proxy", p.ChildProxyAddr(), "--canary-host", canaryHost)
	}
	cmd, err := m.Confine(ctx, w, argv)
	if err != nil {
		return nil, fmt.Errorf("constructing sandbox: %w", err)
	}
	results, err := runChild(cmd)
	if err != nil {
		return nil, err
	}
	for i := range results {
		if results[i].ID == model.ProbeCanaryDetection {
			if len(probeSrv.Trips()) > 0 {
				results[i].Verdict = model.VerdictAllowed
				results[i].Err = ""
				results[i].Detail = "the confined child reached a canary hostname and the proxy recorded and denied the trip"
			} else {
				results[i].Verdict = model.VerdictErrored
				results[i].Detail = "canary detection is unverified on this host: the proxy recorded no trip"
			}
		}
	}
	return results, nil
}

// probeProxyAllow is the allow-list used while probing a proxied mechanism. No
// probe contacts it, so every destination a probe tries is one the proxy must
// refuse; anything that gets through is a real leak.
const probeProxyAllow = "sandboxcheckr-probe.invalid"

func startProbeProxy(ctx context.Context, p mechanism.Proxied, w mechanism.Workdir) (*proxy.Server, string, func(), error) {
	list, err := proxy.NewAllowList([]string{probeProxyAllow})
	if err != nil {
		return nil, "", nil, err
	}
	srv := proxy.NewServer(list, false, nil)
	set, err := canary.New("", "", w.Path)
	if err != nil {
		return nil, "", nil, err
	}
	srv.Canaries = set
	canaryHost := set.Credentials[0].Host
	network, addr := p.ProxyEndpoint(w)
	if network == "unix" {
		_ = os.Remove(addr)
	}
	if _, err := srv.ListenOn(network, addr); err != nil {
		return nil, "", nil, err
	}
	pctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = srv.Serve(pctx); close(done) }()
	return srv, canaryHost, func() {
		cancel()
		<-done
		if network == "unix" {
			_ = os.Remove(addr)
		}
	}, nil
}

// RunBaseline executes the battery with no sandbox at all, inheriting this
// process's full environment.
//
// That is deliberately the realistic case: it is what an agent gets when it is
// started straight from this terminal, including every environment variable
// and every privacy grant the terminal app holds. It is also the control for
// the sandboxed runs — a probe that cannot succeed even here says nothing about
// what a sandbox blocked.
func (h *Harness) RunBaseline(ctx context.Context) ([]model.ProbeResult, error) {
	dir, cleanup, err := scratchDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	argv := h.childArgs(dir)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	return runChild(cmd)
}

func scratchDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "sandboxcheckr-probe-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating scratch workdir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	// EvalSymlinks matters on macOS, where TMPDIR is under /var -> /private/var.
	// A profile written against the unresolved path would not match the path
	// the kernel sees, and the positive control would fail for a reason that
	// has nothing to do with the sandbox.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	// Seed the workdir probes' decoys before any sandbox is built, so
	// mechanisms that protect only paths present at launch are measured as
	// a user would run them.
	if err := SeedWorkdir(dir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("seeding scratch workdir: %w", err)
	}
	return dir, cleanup, nil
}

func runChild(cmd *exec.Cmd) ([]model.ProbeResult, error) {
	// Separate stdout from stderr: the child writes JSON to stdout, while the
	// sandbox tooling itself writes warnings to stderr (sandbox-exec emits a
	// deprecation notice on every run). Combining them would corrupt the JSON.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	var results []model.ProbeResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		// No parseable output means the child never got far enough to report.
		// This is INDETERMINATE, not containment: a sandbox that prevents the
		// probe from running tells us nothing about what it would have blocked.
		return nil, fmt.Errorf("probe produced no usable result (%v): %s",
			runErr, truncate(stderr.String(), 400))
	}
	return results, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
