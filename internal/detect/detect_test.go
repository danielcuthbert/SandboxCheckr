package detect

import (
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

func TestParseCsrutil(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want model.Status
	}{
		{"enabled", "System Integrity Protection status: enabled.\n", model.StatusPass},
		{"disabled", "System Integrity Protection status: disabled.\n", model.StatusFail},
		{
			"partial",
			"System Integrity Protection status: unknown (Custom Configuration).\n\n" +
				"Configuration:\n\tApple Internal: disabled\n\tKext Signing: enabled\n",
			model.StatusIndeterminate,
		},
		{"empty", "", model.StatusIndeterminate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseCsrutil(tc.in); got.Status != tc.want {
				t.Errorf("status = %s, want %s", got.Status, tc.want)
			}
		})
	}
}

// A disabled SIP must say plainly that it undermines any user-space sandbox,
// since that is the actionable part.
func TestCsrutilDisabledExplainsConsequence(t *testing.T) {
	got := parseCsrutil("System Integrity Protection status: disabled.")
	if got.Impact == "" {
		t.Fatal("disabled SIP must explain the consequence")
	}
}

func TestParseSpctl(t *testing.T) {
	if got := parseSpctl("assessments enabled\n"); got.Status != model.StatusPass {
		t.Errorf("enabled → %s, want PASS", got.Status)
	}
	if got := parseSpctl("assessments disabled\n"); got.Status != model.StatusFail {
		t.Errorf("disabled → %s, want FAIL", got.Status)
	}
}

// Captured from macOS 26.6.2. Real output, not invented, so the parser is
// tested against the shape it will actually meet.
const mountFixture = `/dev/disk3s3s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk3s6 on /System/Volumes/VM (apfs, local, noexec, journaled, noatime, nobrowse)
/dev/disk3s1 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect, root data)
/dev/disk3s7 on /nix (apfs, local, nosuid, journaled, noatime, nobrowse, protect)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)`

func TestParseMounts(t *testing.T) {
	mounts := parseMounts(mountFixture)
	if len(mounts) != 6 {
		t.Fatalf("parsed %d mounts, want 6", len(mounts))
	}

	root, ok := findMount(mounts, "/")
	if !ok {
		t.Fatal("did not find the root mount")
	}
	if root.Device != "/dev/disk3s3s1" {
		t.Errorf("root device = %q", root.Device)
	}
	if !root.has("sealed") || !root.has("read-only") {
		t.Errorf("root options = %v, want sealed and read-only", root.Options)
	}

	// A mount point containing spaces or an unusual name must not break parsing
	// of the others.
	nix, ok := findMount(mounts, "/nix")
	if !ok || !nix.has("nosuid") {
		t.Errorf("/nix should be nosuid, got %v", nix.Options)
	}
}

func TestRootVolumeFinding(t *testing.T) {
	sealed := rootVolumeFinding(parseMounts(mountFixture))
	if sealed.Status != model.StatusPass {
		t.Errorf("sealed read-only root → %s, want PASS", sealed.Status)
	}

	writable := rootVolumeFinding(parseMounts("/dev/disk1 on / (apfs, local, journaled)"))
	if writable.Status != model.StatusFail {
		t.Errorf("writable root → %s, want FAIL", writable.Status)
	}

	missing := rootVolumeFinding(nil)
	if missing.Status != model.StatusIndeterminate {
		t.Errorf("absent root mount → %s, want INDETERMINATE", missing.Status)
	}
}

// Malformed input must be skipped rather than panicking or producing junk
// entries: this parses output from a tool we do not control.
func TestParseMountsIgnoresMalformedLines(t *testing.T) {
	in := "garbage without the expected shape\n" +
		"/dev/disk1 on / (apfs, read-only, sealed)\n" +
		"\n" +
		"another bad line on\n"
	mounts := parseMounts(in)
	if len(mounts) != 1 {
		t.Fatalf("parsed %d mounts, want 1: %+v", len(mounts), mounts)
	}
	if mounts[0].Point != "/" {
		t.Errorf("point = %q, want /", mounts[0].Point)
	}
}

// Every finding must carry an Impact. A status with no explanation of what it
// means for running untrusted code is not useful to the person reading it.
func TestFindingsExplainTheirImpact(t *testing.T) {
	findings := []model.PostureFinding{
		parseCsrutil("System Integrity Protection status: enabled."),
		parseSpctl("assessments enabled"),
		rootVolumeFinding(parseMounts(mountFixture)),
	}
	for _, f := range findings {
		if f.Impact == "" {
			t.Errorf("%s has no Impact text", f.ID)
		}
		if f.Name == "" {
			t.Errorf("%s has no Name", f.ID)
		}
	}
}
