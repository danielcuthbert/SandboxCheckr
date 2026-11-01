//go:build linux

package detect

import (
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// ABI → capability mapping, checked against the documented Landlock history:
// v1 filesystem (5.13), v4 TCP (6.7), v6 unix/signal scoping (6.12),
// v10 UDP (current frontier). Getting this wrong would tell someone their
// kernel can restrict network when it cannot.
func TestAbiCapabilities(t *testing.T) {
	cases := []struct {
		abi         int
		mustContain string
		mustNotHave string
	}{
		{1, "filesystem", "TCP"},
		{3, "filesystem", "TCP"},
		{4, "TCP", "UDP"},
		{6, "TCP", "UDP"},
		{10, "UDP", ""},
		{12, "UDP", ""},
	}
	for _, tc := range cases {
		got := abiCapabilities(tc.abi)
		if !strings.Contains(got, tc.mustContain) {
			t.Errorf("ABI %d: %q missing %q", tc.abi, got, tc.mustContain)
		}
		// Descriptions note what a level lacks as "(no UDP)"; that is a
		// negation, not a claim. Only an un-negated mention grants it.
		if tc.mustNotHave != "" && claimsCapability(got, tc.mustNotHave) {
			t.Errorf("ABI %d: %q should not claim %q", tc.abi, got, tc.mustNotHave)
		}
	}
	if abiCapabilities(0) != "" {
		t.Error("ABI 0 means unsupported and must describe nothing")
	}
}

// claimsCapability reports whether desc grants cap: the capability is named
// without an explicit "no <cap>" negation beside it.
func claimsCapability(desc, cap string) bool {
	return strings.Contains(desc, cap) && !strings.Contains(desc, "no "+cap)
}

func TestParseLSM(t *testing.T) {
	got := parseLSM("lockdown,capability,landlock,yama,apparmor\n")
	if len(got) != 5 || got[4] != "apparmor" {
		t.Errorf("parsed %v", got)
	}
	if parseLSM("  \n") != nil {
		t.Error("blank input should parse to nil")
	}
}

func TestLSMFinding(t *testing.T) {
	withMAC := lsmFinding("capability,landlock,yama,apparmor")
	if withMAC.Status != model.StatusPass {
		t.Errorf("apparmor present → %s, want PASS", withMAC.Status)
	}
	withoutMAC := lsmFinding("capability,landlock,yama")
	if withoutMAC.Status != model.StatusDegraded {
		t.Errorf("no MAC module → %s, want DEGRADED", withoutMAC.Status)
	}
	if lsmFinding("").Status != model.StatusIndeterminate {
		t.Error("unreadable LSM list should be INDETERMINATE, not a pass")
	}
}

// Disabled user namespaces remove most unprivileged sandboxing on Linux, so
// this must be reported as a failure rather than a footnote.
func TestUsernsFinding(t *testing.T) {
	if got := usernsFinding("0", "15000"); got.Status != model.StatusFail {
		t.Errorf("unprivileged_userns_clone=0 → %s, want FAIL", got.Status)
	}
	if got := usernsFinding("", "0"); got.Status != model.StatusFail {
		t.Errorf("max_user_namespaces=0 → %s, want FAIL", got.Status)
	}
	if got := usernsFinding("1", "15000"); got.Status != model.StatusPass {
		t.Errorf("enabled → %s, want PASS", got.Status)
	}
	// Non-Debian kernels omit the clone toggle entirely.
	if got := usernsFinding("", "15000"); got.Status != model.StatusPass {
		t.Errorf("absent clone toggle with a positive max → %s, want PASS", got.Status)
	}
}

// Captured from /proc/self/status on a 6.x kernel.
const statusFixture = `Name:	cat
Umask:	0022
State:	R (running)
Tgid:	1234
NoNewPrivs:	0
Seccomp:	2
Seccomp_filters:	1
Speculation_Store_Bypass:	thread vulnerable`

func TestParseSeccompMode(t *testing.T) {
	if got := parseSeccompMode(statusFixture); got != "2" {
		t.Errorf("seccomp mode = %q, want 2", got)
	}
	if got := parseSeccompMode("Name:\tcat\n"); got != "" {
		t.Errorf("absent field = %q, want empty", got)
	}
}

func TestSeccompFinding(t *testing.T) {
	if got := seccompFinding(statusFixture); got.Status != model.StatusPass {
		t.Errorf("seccomp present → %s, want PASS", got.Status)
	}
	if got := seccompFinding("Name:\tcat\n"); got.Status != model.StatusIndeterminate {
		t.Error("missing seccomp field should be INDETERMINATE, not a pass")
	}
}
