package probe

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

func TestClassifyPermissionErrorsAreBlocked(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EROFS} {
		v, _ := classify(errno)
		if v != model.VerdictBlocked {
			t.Errorf("errno %v classified %s, want BLOCKED", errno, v)
		}
	}
}

// An unrelated failure must not be mistaken for the sandbox doing its job.
func TestClassifyUnrelatedErrorIsInconclusive(t *testing.T) {
	if v, _ := classify(errors.New("disk on fire")); v != model.VerdictErrored {
		t.Errorf("unrelated error classified %s, want ERRORED", v)
	}
}

func TestClassifyNilIsAllowed(t *testing.T) {
	if v, _ := classify(nil); v != model.VerdictAllowed {
		t.Errorf("nil error classified %s, want ALLOWED", v)
	}
}

// The central honesty property for network probes: a timeout is ambiguous
// between a sandbox blackholing traffic and a network being unreachable, so it
// must not be counted as containment. Otherwise SandboxCheckr would report a
// laptop with its Wi-Fi off as protected against exfiltration.
func TestTimeoutIsNotCountedAsContained(t *testing.T) {
	timeout := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &timeoutError{},
	}
	v, errno, detail := classifyNet(timeout)
	if v == model.VerdictBlocked {
		t.Error("a network timeout must not be classified BLOCKED")
	}
	if v != model.VerdictErrored {
		t.Errorf("timeout classified %s, want ERRORED", v)
	}
	if errno != "timeout" {
		t.Errorf("errno %q, want \"timeout\"", errno)
	}
	if detail == "" {
		t.Error("timeout should explain why it is inconclusive")
	}
}

// An actively refused connection IS positive evidence of denial.
func TestRefusedConnectionIsBlocked(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.ECONNREFUSED, syscall.EPERM, syscall.EACCES, syscall.ENETUNREACH, syscall.EHOSTUNREACH,
	} {
		v, _, _ := classifyNet(&net.OpError{Op: "dial", Net: "tcp", Err: errno})
		if v != model.VerdictBlocked {
			t.Errorf("errno %v classified %s, want BLOCKED", errno, v)
		}
	}
}

// The positive control must pass in a directory we can write to, and fail
// loudly in one we cannot.
func TestPositiveControlReflectsWritability(t *testing.T) {
	dir := t.TempDir()
	if got := probeWriteAllowed(dir); got.Verdict != model.VerdictAllowed || !got.OK() {
		t.Errorf("writable dir gave %s, want ALLOWED", got.Verdict)
	}

	missing := filepath.Join(dir, "does-not-exist")
	got := probeWriteAllowed(missing)
	if got.OK() {
		t.Error("positive control should fail for an unwritable workdir")
	}
}

// The positive control must leave nothing behind, since it runs against a real
// directory the user cares about.
func TestPositiveControlCleansUp(t *testing.T) {
	dir := t.TempDir()
	probeWriteAllowed(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("probe left %d file(s) behind: %v", len(entries), entries)
	}
}

// An empty workdir is a missing precondition, not a containment result.
func TestPositiveControlSkipsWithoutWorkdir(t *testing.T) {
	if got := probeWriteAllowed(""); got.Verdict != model.VerdictSkipped {
		t.Errorf("empty workdir gave %s, want SKIPPED", got.Verdict)
	}
}

// Every probe must declare what a healthy sandbox looks like, and the positive
// control must be the one that inverts the expectation.
func TestBatteryWantValues(t *testing.T) {
	results := RunBattery(Options{Workdir: t.TempDir()})
	if len(results) == 0 {
		t.Fatal("battery returned no results")
	}
	for _, r := range results {
		switch r.ID {
		case model.ProbeFSWriteAllowed:
			if r.Want != model.VerdictAllowed {
				t.Errorf("%s wants %s, should want ALLOWED", r.ID, r.Want)
			}
		default:
			if r.Want != model.VerdictBlocked {
				t.Errorf("%s wants %s, should want BLOCKED", r.ID, r.Want)
			}
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// A sandbox that shows an empty private directory at the home path (bwrap's
// tmpfs over /home) has isolated the home, and writes into it reach nothing.
// Reporting those writes as ALLOWED would penalise the stronger design.
func TestIsolatedHomeIsBlockedNotAllowed(t *testing.T) {
	real := t.TempDir()
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	hostID := FileID(fi)
	if hostID == "" {
		t.Skip("file identity unavailable on this platform")
	}
	// The child sees a different directory at the same path.
	h := homeView(t.TempDir(), hostID)
	if !h.isolated {
		t.Fatal("a different directory at the home path must be recognised as isolation")
	}
	for _, r := range []model.ProbeResult{probeWriteOutside(h), probePersistence(h), probeReadSecrets(h)} {
		if r.Verdict != model.VerdictBlocked {
			t.Errorf("%s gave %s for an isolated home, want BLOCKED", r.ID, r.Verdict)
		}
	}

	// The same directory is the real home and must be probed normally.
	if homeView(real, hostID).isolated {
		t.Error("the real home must not be treated as isolated")
	}
}

// A missing parent directory is not a sandbox refusal; the persistence probe
// must not claim containment when every attempt failed for unrelated reasons.
func TestPersistenceInconclusiveIsNotBlocked(t *testing.T) {
	h := home{path: filepath.Join(t.TempDir(), "does-not-exist")}
	if r := probePersistence(h); r.Verdict == model.VerdictBlocked {
		t.Errorf("persistence gave BLOCKED with no permission refusal: %s", r.Detail)
	}
}

// The write-outside probe must never overwrite an existing file.
func TestWriteOutsideNeverClobbers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".sandboxcheckr-probe")
	if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	probeWriteOutside(home{path: dir})
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "keep" {
		t.Errorf("existing file was modified or removed: %q, %v", b, err)
	}
}

// A file that is not ours is not evidence either way, and must not be reported
// as a successful write.
func TestWriteOutsideForeignFileIsNotReportedAllowed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".sandboxcheckr-probe")
	if err := os.WriteFile(p, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := probeWriteOutside(home{path: dir}); r.Verdict == model.VerdictAllowed {
		t.Errorf("a foreign file of the same name was read as a successful write: %s", r.Detail)
	}
}

// A run killed before its cleanup leaves the marker behind. Every later run
// meets EEXIST and would otherwise call that "writes outside the workdir are
// refused", so a home directory the sandbox never protected could never be
// detected again. Our own marker in the file is the proof.
func TestWriteOutsideLeftoverMarkerIsAllowed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".sandboxcheckr-probe")
	if err := os.WriteFile(p, []byte(probeMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	r := probeWriteOutside(home{path: dir})
	if r.Verdict != model.VerdictAllowed {
		t.Errorf("a leftover marker gave %s, want ALLOWED: %s", r.Verdict, r.Detail)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("the probe left its own marker behind")
	}
}

// openTree restores permissions on the way out, so that t.TempDir can still
// remove a tree the test made unwritable.
func openTree(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
	})
}

// One permission refusal among a set of attempts that failed for other reasons
// (a missing parent directory) is not the sandbox refusing persistence, and
// BLOCKED is worth too much to be won by a single coincidence.
func TestPersistencePartialRefusalIsNotBlocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not refused by file permissions")
	}
	h := t.TempDir()
	openTree(t, h)
	// Exactly one target sits in a directory that refuses the create, and every
	// other target fails for a reason that is not a permission denial: a
	// dangling symlink cannot be opened for append (ENOENT).
	one := ""
	for _, rel := range persistencePaths[runtime.GOOS] {
		p := filepath.Join(h, rel)
		if one == "" {
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(p), 0o500); err != nil {
				t.Fatal(err)
			}
			one = rel
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(h, "no-such-file"), p); err != nil {
			t.Fatal(err)
		}
	}
	r := probePersistence(home{path: h})
	if r.Verdict == model.VerdictBlocked {
		t.Errorf("persistence gave BLOCKED on %s refused of %d attempts: %s",
			one, len(persistencePaths[runtime.GOOS]), r.Detail)
	}
}

// When every attempt is refused, that IS the finding, and the probe must say
// so rather than hedge.
func TestPersistenceUnanimousRefusalIsBlocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not refused by file permissions")
	}
	h := t.TempDir()
	openTree(t, h)
	// Every target must fail with a refusal rather than a missing parent
	// directory, so the directories the probe wants to create files in are made
	// first and then closed.
	for _, rel := range persistencePaths[runtime.GOOS] {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(h, rel)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range persistencePaths[runtime.GOOS] {
		if err := os.Chmod(filepath.Dir(filepath.Join(h, rel)), 0o500); err != nil {
			t.Fatal(err)
		}
	}

	r := probePersistence(home{path: h})
	if r.Verdict != model.VerdictBlocked {
		t.Errorf("every attempt refused gave %s, want BLOCKED: %s", r.Verdict, r.Detail)
	}
}

// A crashed run's own files would otherwise answer the probe as "already
// present and modifiable", reporting a persistence write the sandbox never
// permitted. Its own marker is what makes them recognisable as the probe's.
func TestPersistenceClearsOnlyItsOwnLeftovers(t *testing.T) {
	h := t.TempDir()
	own, foreign := ".config/systemd/user/sandboxcheckr-probe.service", ".config/autostart/sandboxcheckr-probe.desktop"
	if runtime.GOOS == "darwin" {
		own, foreign = "Library/LaunchAgents/sandboxcheckr-probe.plist", ".zshrc"
	}
	ownPath := filepath.Join(h, own)
	if err := os.MkdirAll(filepath.Dir(ownPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownPath, []byte(probeMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	foreignPath := filepath.Join(h, foreign)
	if err := os.MkdirAll(filepath.Dir(foreignPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignPath, []byte("a unit someone else installed"), 0o600); err != nil {
		t.Fatal(err)
	}

	probePersistence(home{path: h})

	if _, err := os.Lstat(ownPath); err == nil {
		t.Error("the probe left its own leftover behind to be mistaken for a persistence write")
	}
	if b, err := os.ReadFile(foreignPath); err != nil || string(b) != "a unit someone else installed" {
		t.Errorf("the probe touched a file that is not its own: %q, %v", b, err)
	}
}

// A browser profile we could not open for a reason other than a permission
// refusal (a symlink loop, a dangling link, an I/O error) is not the sandbox
// closing the channel.
func TestBrowserProfileUnrelatedErrorIsNotBlocked(t *testing.T) {
	rels := browserProfiles[runtime.GOOS]
	if len(rels) == 0 {
		t.Skip("no browser profile paths defined for this OS")
	}
	h := t.TempDir()
	p := filepath.Join(h, rels[0])
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p, p); err != nil {
		t.Fatal(err) // a symlink that points at itself: open gives ELOOP
	}
	r := probeBrowserProfiles(home{path: h})
	if r.Verdict == model.VerdictBlocked {
		t.Errorf("an unopenable profile gave BLOCKED, want ERRORED: %s", r.Detail)
	}
}

// A container socket that failed to dial for a reason other than a refusal says
// nothing about what the sandbox would have allowed.
func TestContainerSocketUnrelatedFailureIsNotBlocked(t *testing.T) {
	dir := t.TempDir()
	// A dangling symlink where a socket should be: connect fails with ENOENT,
	// which is not evidence of containment.
	p := filepath.Join(dir, "docker.sock")
	if err := os.Symlink(filepath.Join(dir, "gone"), p); err != nil {
		t.Fatal(err)
	}
	restore := containerSockets
	containerSockets = []string{p}
	defer func() { containerSockets = restore }()

	r := probeContainerSocket(context.Background())
	if r.Verdict == model.VerdictBlocked {
		t.Errorf("an un-diallable socket path gave BLOCKED, want ERRORED: %s", r.Detail)
	}
}

// A socket file that refuses the connection is the sandbox or the daemon
// closing the door, which is the finding.
func TestContainerSocketRefusalIsBlocked(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Skip("cannot bind a unix socket:", err)
	}
	// Leave the file behind so the probe sees a socket present with nothing
	// willing to accept it.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()

	restore := containerSockets
	containerSockets = []string{p}
	defer func() { containerSockets = restore }()

	r := probeContainerSocket(context.Background())
	if r.Verdict != model.VerdictBlocked {
		t.Errorf("a refused container socket gave %s, want BLOCKED: %s", r.Verdict, r.Detail)
	}
}

// The whole point of the shared network budget: when it runs out the probes
// report ERRORED and the child still prints its results, rather than dialling
// until the harness kills it and the mechanism scores INDETERMINATE with zero.
func TestExpiredNetworkBudgetIsErroredNotHung(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	type networkProbe struct {
		name string
		run  func(context.Context) model.ProbeResult
	}
	probes := []networkProbe{
		{"net.egress.tcp", probeNetTCP},
		{"net.egress.dns", probeNetDNS},
		{"cloud.metadata", probeCloudMetadata},
		{"container.socket", probeContainerSocket},
		{"proxy.control", func(ctx context.Context) model.ProbeResult {
			return probeProxyControl(ctx, "127.0.0.1:1")
		}},
		{"fs.sockets", func(ctx context.Context) model.ProbeResult {
			return probeAgentSockets(ctx, []string{"/run/docker.sock"})
		}},
		{"canary.detection", func(ctx context.Context) model.ProbeResult {
			return probeCanaryDetection(ctx, "127.0.0.1:1", "canary.invalid")
		}},
	}
	for _, p := range probes {
		start := time.Now()
		r := p.run(ctx)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("%s took %v after the budget expired; it should not dial at all", p.name, elapsed)
		}
		if r.Verdict != model.VerdictErrored {
			t.Errorf("%s gave %s after the budget expired, want ERRORED: %s", p.name, r.Verdict, r.Detail)
		}
		if !strings.Contains(r.Detail, "budget") {
			t.Errorf("%s did not say the budget ran out: %s", p.name, r.Detail)
		}
	}
}

// A lookup that succeeds with no addresses is NODATA: a working resolver and no
// egress finding, not a successful lookup scored as an open channel. The system
// resolver cannot be made to answer that way on demand, so the probe takes its
// lookup from a seam.
func TestDNSNoDataIsNotAnOpenChannel(t *testing.T) {
	withLookup(t, func(context.Context, string) ([]string, error) {
		return nil, nil
	})

	r := probeNetDNS(context.Background())
	if r.Verdict == model.VerdictAllowed {
		t.Errorf("a NODATA answer was scored as egress: %s", r.Detail)
	}
	if r.Verdict != model.VerdictErrored {
		t.Errorf("NODATA gave %s, want ERRORED: %s", r.Verdict, r.Detail)
	}
	if !strings.Contains(r.Detail, "no addresses") {
		t.Errorf("NODATA should be named in the detail: %s", r.Detail)
	}
}

// The other side of the same branch: addresses came back, so name resolution
// works from inside the sandbox, and that is the finding.
func TestDNSAnswerIsAnOpenChannel(t *testing.T) {
	withLookup(t, func(context.Context, string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	})

	r := probeNetDNS(context.Background())
	if r.Verdict != model.VerdictAllowed {
		t.Errorf("a resolved name gave %s, want ALLOWED: %s", r.Verdict, r.Detail)
	}
}

func withLookup(t *testing.T, lookup func(context.Context, string) ([]string, error)) {
	t.Helper()
	restore := dnsLookup
	dnsLookup = lookup
	t.Cleanup(func() { dnsLookup = restore })
}
