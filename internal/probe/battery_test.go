package probe

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

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
