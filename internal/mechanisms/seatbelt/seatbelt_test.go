//go:build darwin

package seatbelt

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

func TestProxiedWrapperShellSyntax(t *testing.T) {
	art, err := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: "/tmp/canary project"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-n")
	cmd.Stdin = strings.NewReader(art.FileBody)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated runner is not valid sh: %v\n%s", err, out)
	}
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
		`mktemp -d "${TMPDIR:-/tmp}/sandboxcheckr-log.XXXXXX"`,
		`echo "$PROXY_PID" > "$HERE/.proxy-pid"`,
		"observed connection attempts",
		"Looked up in this shell's PATH",
	} {
		if !strings.Contains(art.FileBody, want) {
			t.Errorf("proxied runner lacks %q", want)
		}
	}
}

// Apple Events (cross-app automation) must be explicitly denied in every
// variant, not just left to deny-default, so the intent is auditable and
// survives a future broad allow.
func TestProfileDeniesAppleEvents(t *testing.T) {
	for _, o := range []ProfileOpts{
		{Workdir: "/tmp/x"},
		{Workdir: "/tmp/x", PermitNetwork: true},
		{Workdir: "/tmp/x", ProxyPort: 8899},
	} {
		if !strings.Contains(Profile(o), "(deny appleevent-send)") {
			t.Errorf("profile must explicitly deny appleevent-send (opts %+v)", o)
		}
	}
}

// The profile must import Apple's loader rules. Without them a deny-default
// profile aborts inside dyld/libignition before main() runs, which surfaces as
// a crash report rather than a sandbox denial — the failure that motivated
// this test.
func TestProfileImportsDyldSupport(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x"})
	if !strings.Contains(p, `(import "dyld-support.sb")`) {
		t.Error("profile must import dyld-support.sb or processes will not boot")
	}
}

// Mapping a file as executable is a distinct operation from reading it.
// Granting only file-read* is why the first version of this profile could not
// launch anything.
func TestProfileGrantsMapExecutable(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x"})
	if !strings.Contains(p, "file-map-executable") {
		t.Fatal("profile must grant file-map-executable")
	}
	if !strings.Contains(p, `(allow file-map-executable
  (subpath "/usr/lib")`) {
		t.Error("profile must allow mapping system dylibs from /usr/lib")
	}
}

// The program being confined usually lives outside the workdir, so its own
// directory must be granted read and map-executable.
func TestProfileGrantsExecPath(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x", ExecPaths: []string{"/Users/someone/tools"}})
	want := `(allow file-read* file-test-existence file-map-executable (subpath "/Users/someone/tools"))`
	if !strings.Contains(p, want) {
		t.Errorf("profile missing exec path grant:\n%s", p)
	}
}

// Deny must come before the allows, since later rules win in Seatbelt.
func TestDenyDefaultPrecedesAllows(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x"})
	deny := strings.Index(p, "(deny default)")
	allow := strings.Index(p, "(allow")
	if deny < 0 {
		t.Fatal("profile must deny by default")
	}
	if allow < deny {
		t.Error("(deny default) must precede allow rules or it would override them")
	}
}

// The workdir must be writable and must be quoted, so paths containing spaces
// cannot break the profile or smuggle in extra rules.
func TestWorkdirIsQuoted(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: `/tmp/a dir"with quote`})
	if !strings.Contains(p, `(allow file-read* file-write* (subpath "/tmp/a dir\"with quote"))`) {
		t.Errorf("workdir must be safely quoted, got:\n%s", p)
	}
}

// Network denial is the control that stops a piped download from executing.
func TestProfileDeniesNetwork(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x"})
	if !strings.Contains(p, "(deny network*)") {
		t.Error("profile must deny network by default")
	}
}

// The home directory must never be granted: reading it is how credentials leak.
func TestProfileDoesNotGrantHome(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x"})
	for _, bad := range []string{`(subpath "/Users")`, `(subpath "/home")`} {
		if strings.Contains(p, bad) {
			t.Errorf("profile must not grant %s", bad)
		}
	}
}

// Confine must include the target binary's directory automatically, since
// forgetting it produces a loader abort rather than a useful error.
func TestConfineGrantsBinaryDirectory(t *testing.T) {
	m := NewStrict()
	cmd, err := m.Confine(t.Context(), mechanism.Workdir{Path: "/tmp/wd"},
		[]string{"/opt/custom/bin/tool", "__probe"})
	if err != nil {
		t.Skipf("sandbox-exec unavailable: %v", err)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, `(subpath "/opt/custom/bin")`) {
		t.Error("Confine must grant the directory containing the target binary")
	}
}

// The strict variant must deny network and the practical variant must allow it.
// If these ever swapped, the tool would hand someone a profile that does the
// opposite of what its name and score claim.
func TestVariantsDifferOnNetwork(t *testing.T) {
	strict := Profile(ProfileOpts{Workdir: "/tmp/x", PermitNetwork: false})
	practical := Profile(ProfileOpts{Workdir: "/tmp/x", PermitNetwork: true})

	if !strings.Contains(strict, "(deny network*)") || strings.Contains(strict, "(allow network*)") {
		t.Error("strict variant must deny network and must not allow it")
	}
	if !strings.Contains(practical, "(allow network*)") {
		t.Error("practical variant must allow network")
	}
	if NewStrict().PermitsNetwork() {
		t.Error("NewStrict must report PermitsNetwork false")
	}
	if !NewPractical().PermitsNetwork() {
		t.Error("NewPractical must report PermitsNetwork true")
	}
}

// Both variants keep every filesystem restriction. Permitting network must not
// quietly loosen anything else.
func TestPracticalVariantKeepsFilesystemLockdown(t *testing.T) {
	practical := Profile(ProfileOpts{Workdir: "/tmp/x", PermitNetwork: true})
	if !strings.Contains(practical, "(deny default)") {
		t.Error("practical variant must still deny by default")
	}
	for _, bad := range []string{`(subpath "/Users")`, `(subpath "/home")`} {
		if strings.Contains(practical, bad) {
			t.Errorf("practical variant must not grant %s", bad)
		}
	}
}

// The two variants must emit differently-named artifacts, or generating both
// into one directory would silently overwrite.
func TestVariantsHaveDistinctIDs(t *testing.T) {
	if NewStrict().ID() == NewPractical().ID() {
		t.Error("variants must have distinct IDs")
	}
}

// Seatbelt resolves conflicts by taking the LAST matching rule, so a narrowing
// allow must appear after the blanket deny. Getting this backwards silently
// denied everything in the proxied variant, breaking the feature entirely while
// still looking correct on a casual read.
func TestNetworkAllowFollowsDeny(t *testing.T) {
	cases := map[string]string{
		"proxied":   Profile(ProfileOpts{Workdir: "/tmp/x", ProxyPort: 8899}),
		"practical": Profile(ProfileOpts{Workdir: "/tmp/x", PermitNetwork: true}),
	}
	for name, p := range cases {
		deny := strings.LastIndex(p, "(deny network*)")
		allow := strings.LastIndex(p, "(allow network")
		if deny < 0 {
			t.Fatalf("%s: profile must deny network somewhere", name)
		}
		if allow < 0 {
			t.Fatalf("%s: profile must contain a narrowing allow", name)
		}
		if allow < deny {
			t.Errorf("%s: allow at %d precedes deny at %d, so it is overridden", name, allow, deny)
		}
	}
}

// The proxied variant must permit exactly the proxy port and nothing wider.
func TestProxyProfilePermitsOnlyLoopbackPort(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x", ProxyPort: 8899})
	// Seatbelt rejects a numeric host here ("host must be * or localhost"),
	// so the rule must say localhost.
	if !strings.Contains(p, `(allow network-outbound (remote ip "localhost:8899"))`) {
		t.Error("proxied profile must permit the loopback proxy port via localhost")
	}
	if strings.Contains(p, `remote ip "127.0.0.1`) {
		t.Error("a numeric remote ip makes the profile fail to compile")
	}
	if strings.Contains(p, "(allow network*)") {
		t.Error("proxied profile must not permit unrestricted network")
	}
	// DNS denial is what closes the tunnelling channel; it follows from there
	// being no allow for it.
	if strings.Count(p, "(allow network") != 1 {
		t.Error("proxied profile should contain exactly one network allow")
	}
}

// The strict variant must contain no network allow at all.
func TestStrictProfileHasNoNetworkAllow(t *testing.T) {
	p := Profile(ProfileOpts{Workdir: "/tmp/x"})
	if strings.Contains(p, "(allow network") {
		t.Error("strict profile must not allow any network")
	}
}

// The probe child must run with exactly the environment the emitted runner
// gives a real program. If they diverge, exfil.env.secrets measures a
// different configuration from the one the user runs.
func TestConfineEnvMatchesSharedDefinition(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "should-not-leak")
	cmd, err := NewStrict().Confine(t.Context(), mechanism.Workdir{Path: t.TempDir()}, []string{"/usr/bin/true"})
	if err != nil {
		t.Skipf("sandbox-exec unavailable: %v", err)
	}
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") {
			t.Error("caller's secrets must not reach the confined child")
		}
	}
	want := mechanism.SandboxEnv(homeDir(), ScratchDir(cmd.Dir), nil)
	if strings.Join(cmd.Env, "\n") != strings.Join(want, "\n") {
		t.Errorf("Confine env diverges from mechanism.SandboxEnv:\n got %v\nwant %v", cmd.Env, want)
	}
}

// Every variant ships a runner script that clears the environment, and the
// runner must be valid POSIX sh.
func TestWrapperRunnerScripts(t *testing.T) {
	for _, m := range []*Mechanism{NewStrict(), NewPractical(), NewProxied(8899, true)} {
		art, err := m.Wrapper(mechanism.Workdir{Path: "/tmp/it's a dir"})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := art.ExtraFiles[m.ID()+".sb"]; !ok {
			t.Errorf("%s: runner must ship with its profile", m.ID())
		}
		if !strings.Contains(art.FileBody, "/usr/bin/env -i") {
			t.Errorf("%s: runner must clear the environment", m.ID())
		}
		cmd := exec.Command("/bin/sh", "-n")
		cmd.Stdin = strings.NewReader(art.FileBody)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: runner is not valid sh: %v\n%s", m.ID(), err, out)
		}
	}
	proxied, _ := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: "/tmp/x"})
	if strings.Contains(proxied.FileBody, "sleep 1\n") {
		t.Error("proxied runner must wait for the proxy to listen, not sleep and hope")
	}
}

// The pasteboard service must be denied by name.
func TestProfileDeniesPasteboard(t *testing.T) {
	if !strings.Contains(Profile(ProfileOpts{Workdir: "/tmp/x"}), `(deny mach-lookup (global-name "com.apple.pasteboard.1"))`) {
		t.Error("profile must deny the pasteboard service")
	}
}

// Every generated variant must compile and boot under sandbox-exec. The
// proxied variant once shipped with a numeric remote-ip host that Seatbelt
// rejects at parse time, and only a real run caught it.
func TestEveryVariantCompiles(t *testing.T) {
	for _, m := range []*Mechanism{NewStrict(), NewPractical(), NewProxied(8899, true)} {
		av := m.Detect(t.Context())
		if av.Status == model.StatusIndeterminate {
			t.Skipf("cannot apply sandboxes here (already confined?): %s", av.Detail)
		}
		if av.Status != model.StatusPass {
			t.Errorf("%s: %s — %s", m.ID(), av.Status, av.Detail)
		}
	}
}

// The strict variant refuses the keychain service; the networked variants
// keep it, because agents store their login there.
func TestStrictDeniesKeychainService(t *testing.T) {
	deny := `(deny mach-lookup (global-name "com.apple.SecurityServer"))`
	if !strings.Contains(Profile(ProfileOpts{Workdir: "/tmp/x"}), deny) {
		t.Error("strict profile must deny securityd")
	}
	if strings.Contains(Profile(ProfileOpts{Workdir: "/tmp/x", ProxyPort: 8899}), deny) {
		t.Error("proxied profile must keep securityd so agents can log in")
	}
}

// SBX-010: two runners started together must each get their own proxy. This
// runs the real emitted script with sandbox-exec replaced by a stub that
// reports the proxy port it was handed.
func TestConcurrentRunnersGetSeparateProxies(t *testing.T) {
	bin := os.Getenv("SANDBOXCHECKR_BIN")
	if bin == "" {
		t.Skip("set SANDBOXCHECKR_BIN to a built sandboxcheckr to run the runner end to end")
	}
	dir := t.TempDir()
	work := filepath.Join(dir, "proj")
	_ = os.MkdirAll(work, 0o700)
	art, err := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: work})
	if err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "fake-sbx")
	_ = os.WriteFile(stub, []byte("#!/bin/sh\necho \"$HTTPS_PROXY\"\nsleep 1\n"), 0o755)
	script := strings.ReplaceAll(art.FileBody, "/usr/bin/sandbox-exec", stub)
	// The runner pins its own binary at emit time, so point the pinned default
	// at the built binary this test supplies; the poisoned SANDBOXCHECKR below
	// is what the pin has to ignore.
	script = pinRunnerBinary(t, script, bin)
	_ = os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "seatbelt-proxy.sb"), []byte(art.ExtraFiles["seatbelt-proxy.sb"]), 0o600)

	run := func() *exec.Cmd {
		c := exec.Command("/bin/sh", filepath.Join(dir, "run.sh"), "/bin/echo")
		c.Env = append(os.Environ(), "SANDBOXCHECKR=/nonexistent/sandboxcheckr")
		return c
	}
	a, b := run(), run()
	var oa, ob strings.Builder
	a.Stdout, b.Stdout = &oa, &ob
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	_ = a.Wait()
	_ = b.Wait()
	pa, pb := strings.TrimSpace(oa.String()), strings.TrimSpace(ob.String())
	if pa == "" || pb == "" || pa == pb {
		t.Errorf("each runner must get its own proxy: %q vs %q", pa, pb)
	}
}

// The runner must refuse EXTRA_RO / EXTRA_RW of / or $HOME (or a symlink to
// either), and must still accept an ordinary directory.
func TestRunnerRefusesRootAndHomeGrants(t *testing.T) {
	art, err := NewStrict().Wrapper(mechanism.Workdir{Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, NewStrict().ID()+".sb"), []byte("(version 1)"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte(art.FileBody), 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	rootLink := filepath.Join(dir, "rootlink")
	_ = os.Symlink("/", rootLink)
	run := func(env ...string) (string, error) {
		// A refused grant exits 2 before sandbox-exec is reached.
		cmd := exec.Command("/bin/sh", script, "/usr/bin/true")
		cmd.Env = append([]string{"HOME=" + home, "PATH=/usr/bin:/bin"}, env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, env := range []string{"EXTRA_RO=/", "EXTRA_RW=" + home, "EXTRA_RO=" + home + "/", "EXTRA_RO=" + filepath.Dir(home),
		"EXTRA_RO=" + rootLink, "EXTRA_RW=//", "EXTRA_RO=" + home + "/../" + filepath.Base(home)} {
		out, err := run(env)
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(out, "refusing") {
			t.Errorf("%s: want refusal with exit 2, got %v:\n%s", env, err, out)
		}
	}
	ok := t.TempDir()
	if out, _ := run("EXTRA_RO=" + ok); strings.Contains(out, "refusing") {
		t.Errorf("ordinary EXTRA_RO path refused:\n%s", out)
	}
}

// pinRunnerBinary rewrites the binary the emitted runner pins, the way
// re-emitting from a different build would.
func pinRunnerBinary(t *testing.T, script, bin string) string {
	t.Helper()
	const marker = "SANDBOXCHECKR_DEFAULT="
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatal("the runner does not record a default binary to pin")
	}
	rest := script[i+len(marker):]
	end := strings.Index(rest, "\n")
	if end < 0 {
		t.Fatal("the pinned binary is not a line of its own")
	}
	return script[:i+len(marker)] + shQuote(bin) + rest[end:]
}

// The runner starts the egress proxy and the canary generator OUTSIDE the
// sandbox, so the binary it runs has to be the one emitted with the profile. An
// inherited SANDBOXCHECKR would otherwise run attacker-chosen code unconfined,
// which is why the bubblewrap runner pins it too.
func TestRunnerPinsItsOwnBinary(t *testing.T) {
	art, err := NewProxied(8899, true).Wrapper(mechanism.Workdir{Path: "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(art.FileBody, "${SANDBOXCHECKR:-") {
		t.Errorf("the environment must not be able to choose the runner's binary:\n%s", art.FileBody)
	}
	if !strings.Contains(art.FileBody, `SANDBOXCHECKR="$SANDBOXCHECKR_DEFAULT"`) {
		t.Errorf("the runner must pin SANDBOXCHECKR to the emitted default:\n%s", art.FileBody)
	}
}

// SBX-011: the dotenv and exec-config deny blocks sit in the .sb between
// ;; BEGIN / ;; END markers; the runner cuts them out of the main text and
// re-applies them after the EXTRA_* grants. A profile whose blocks are missing
// (hand-edited, damaged) would leave PROTECT empty, so the blocks would be gone
// from both places and .env would be readable with nothing printed. Failing
// closed is the only safe answer, and an explicit opt-out still runs.
func TestRunnerFailsClosedWhenProtectionBlocksAreMissing(t *testing.T) {
	dir := t.TempDir()
	work := t.TempDir()
	art, err := NewStrict().Wrapper(mechanism.Workdir{Path: work})
	if err != nil {
		t.Fatal(err)
	}
	sbName := NewStrict().ID() + ".sb"
	profile := art.ExtraFiles[sbName]
	for _, marker := range []string{beginDotenv, beginExecConfig} {
		if !strings.Contains(profile, marker) {
			t.Fatalf("the emitted profile must carry %q:\n%s", marker, profile)
		}
	}
	// sandbox-exec is replaced by a stub that records the profile it was
	// handed, so the ordering of the re-applied blocks is checkable and the
	// test does not need a working Seatbelt.
	stub := filepath.Join(dir, "fake-sandbox-exec")
	handed := filepath.Join(dir, "handed-over.sb")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' \"$2\" > "+shQuote(handed)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.sh")
	body := strings.ReplaceAll(art.FileBody, "/usr/bin/sandbox-exec", stub)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}

	run := func(profileText string, env ...string) (string, int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, sbName), []byte(profileText), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(handed)
		cmd := exec.Command("/bin/sh", script, "/usr/bin/true")
		cmd.Env = append([]string{"HOME=" + dir, "PATH=/usr/bin:/bin"}, env...)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("running the runner: %v\n%s", err, out)
		}
		return string(out), 0
	}

	out, code := run(profile, "EXTRA_RW="+work)
	if code != 0 {
		t.Fatalf("the intact profile would not run: exit %d\n%s", code, out)
	}
	handedText, err := os.ReadFile(handed)
	if err != nil {
		t.Fatal(err)
	}
	applied := string(handedText)
	deny := "(deny file-read-data file-write* file-link"
	if !strings.Contains(applied, deny) {
		t.Errorf("the .env deny is missing from the profile handed to sandbox-exec:\n%s", applied)
	}
	// Seatbelt takes the last matching rule, so the protection has to land
	// after a grant that names the project itself.
	realWork := work
	if r, err := filepath.EvalSymlinks(work); err == nil {
		realWork = r
	}
	grant := `(allow file-read* file-write* (subpath "` + realWork + `"))`
	gi, di := strings.Index(applied, grant), strings.Index(applied, deny)
	if gi < 0 {
		t.Errorf("the EXTRA_RW grant is missing from the profile handed over:\n%s", applied)
	} else if di >= 0 && di < gi {
		t.Error("the workdir protection must be re-applied after EXTRA_* grants")
	}

	for _, tc := range []struct {
		name   string
		drop   []string
		wants  string
		env    []string
		expect bool
	}{
		{"both blocks gone", []string{"protect-dotenv", "protect-exec-config"}, "protect-dotenv", nil, false},
		{"exec config block gone", []string{"protect-exec-config"}, "protect-exec-config", nil, false},
		{"opted out", nil, "", []string{"ALLOW_DOTENV=1", "ALLOW_EXEC_CONFIG=1"}, true},
	} {
		broken := profile
		for _, name := range tc.drop {
			broken = dropBlock(broken, name)
		}
		out, code := run(broken, tc.env...)
		if tc.expect {
			if code != 0 {
				t.Errorf("%s: opted out but the runner refused to start: exit %d\n%s", tc.name, code, out)
			}
			continue
		}
		if code != 2 || !strings.Contains(out, tc.wants) {
			t.Errorf("%s: want exit 2 naming %q, got exit %d:\n%s", tc.name, tc.wants, code, out)
		}
	}
}

// dropBlock removes a protection block from a profile, markers and rules both,
// the way a hand-edited profile or a bad merge would.
func dropBlock(profile, name string) string {
	var kept []string
	skip := false
	for _, line := range strings.Split(profile, "\n") {
		switch {
		case strings.HasPrefix(line, ";; BEGIN "+name):
			skip = true
		case strings.HasPrefix(line, ";; END "+name):
			skip = false
		case !skip:
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func TestConfineRefusesBinaryInHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	if _, err := NewStrict().Confine(t.Context(), mechanism.Workdir{Path: t.TempDir()}, []string{filepath.Join(home, "probe")}); err == nil {
		t.Error("Confine granted $HOME as the binary's directory")
	}
	if _, err := NewStrict().Confine(t.Context(), mechanism.Workdir{Path: t.TempDir()}, []string{"/probe"}); err == nil {
		t.Error("Confine granted / as the binary's directory")
	}
}
