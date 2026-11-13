package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

// colorEnabled encodes the conventions people expect; the piped-off default is
// the one that keeps escape sequences out of redirected files and CI logs.
func TestColorEnabled(t *testing.T) {
	clear := func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		t.Setenv("FORCE_COLOR", "")
		t.Setenv("CLICOLOR_FORCE", "")
	}

	t.Run("flag forces off", func(t *testing.T) {
		clear(t)
		if colorEnabled(true, true, "xterm") {
			t.Error("--no-color must force colour off even on a terminal")
		}
	})
	t.Run("NO_COLOR forces off", func(t *testing.T) {
		clear(t)
		t.Setenv("NO_COLOR", "1")
		if colorEnabled(false, true, "xterm") {
			t.Error("NO_COLOR must force colour off")
		}
	})
	t.Run("FORCE_COLOR forces on when piped", func(t *testing.T) {
		clear(t)
		t.Setenv("FORCE_COLOR", "1")
		if !colorEnabled(false, false, "xterm") {
			t.Error("FORCE_COLOR must force colour on even when not a terminal")
		}
	})
	t.Run("piped is off by default", func(t *testing.T) {
		clear(t)
		if colorEnabled(false, false, "xterm") {
			t.Error("non-terminal output must default to no colour")
		}
	})
	t.Run("dumb terminal is off", func(t *testing.T) {
		clear(t)
		if colorEnabled(false, true, "dumb") {
			t.Error("TERM=dumb must disable colour")
		}
	})
	t.Run("interactive is on", func(t *testing.T) {
		clear(t)
		if !colorEnabled(false, true, "xterm-256color") {
			t.Error("an interactive terminal should get colour")
		}
	})
}

func TestUTF8Locale(t *testing.T) {
	t.Run("utf-8 lang", func(t *testing.T) {
		t.Setenv("LC_ALL", "")
		t.Setenv("LC_CTYPE", "")
		t.Setenv("LANG", "en_US.UTF-8")
		if !utf8Locale() {
			t.Error("a UTF-8 LANG should report UTF-8")
		}
	})
	t.Run("C locale", func(t *testing.T) {
		t.Setenv("LC_ALL", "")
		t.Setenv("LC_CTYPE", "")
		t.Setenv("LANG", "C")
		if utf8Locale() {
			t.Error("the C locale should not report UTF-8")
		}
	})
	t.Run("unset assumes utf-8", func(t *testing.T) {
		t.Setenv("LC_ALL", "")
		t.Setenv("LC_CTYPE", "")
		t.Setenv("LANG", "")
		if !utf8Locale() {
			t.Error("an unset locale should assume UTF-8 rather than punish a capable terminal")
		}
	})
}

// The help text must list every mechanism --emit accepts on this platform,
// because it is generated from the same registry. This guards the case that
// prompted it: --emit seatbelt-proxy worked but -h never mentioned it.
func TestHelpListsEveryMechanism(t *testing.T) {
	var b strings.Builder
	writeMechanismHelp(&b)
	for _, m := range mechanisms.All(0) {
		if !strings.Contains(b.String(), m.ID()) {
			t.Errorf("help does not mention mechanism %q", m.ID())
		}
	}
}

// docText returns the usage documentation: README and user guide together,
// since the usage content moved to docs/USER_GUIDE.md and either place may
// carry a flag.
func docText(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	for _, p := range []string{"../../README.md", "../../docs/USER_GUIDE.md"} {
		if b, err := os.ReadFile(p); err == nil {
			sb.Write(b)
			sb.WriteByte('\n')
		}
	}
	if sb.Len() == 0 {
		t.Skip("no README or user guide found")
	}
	return sb.String()
}

// Every top-level flag must be documented in the usage docs (README or the
// user guide), so the two cannot drift apart again.
func TestReadmeDocumentsEveryFlag(t *testing.T) {
	readme := docText(t)
	for _, name := range []string{"json", "gaps", "no-probes", "peers", "no-color", "no-banner", "ascii",
		"width", "verbose", "emit", "proxy-port", "workdir", "no-baseline", "tcc"} {
		if !strings.Contains(readme, "--"+name) {
			t.Errorf("command reference does not mention --%s", name)
		}
	}
	for _, m := range []string{"seatbelt-strict", "seatbelt-proxy", "seatbelt-network",
		"bubblewrap-strict", "bubblewrap-proxy", "bubblewrap-network"} {
		if !strings.Contains(readme, m) {
			t.Errorf("does not mention mechanism %s", m)
		}
	}
}

// Every proxy flag must appear in the usage docs, for the same reason as the
// top-level flags: so the docs cannot drift from the binary.
func TestReadmeDocumentsProxyFlags(t *testing.T) {
	readme := docText(t)
	for _, name := range []string{"allow", "allow-port", "allow-private-host", "rule", "observe",
		"ca-bundle-out", "log", "unix", "ready-file", "quiet", "allow-private", "port"} {
		if !strings.Contains(readme, "--"+name) {
			t.Errorf("does not mention proxy flag --%s", name)
		}
	}
	for _, env := range []string{"PASS_ENV", "EXTRA_RO", "EXTRA_RW", "ALLOW", "PORT", "PROXY_LOG"} {
		if !strings.Contains(readme, env) {
			t.Errorf("does not mention runner variable %s", env)
		}
	}
}

// The main -h must at least name every proxy control, so a reader finds them
// without knowing to ask for "help proxy".
func TestMainHelpSummarisesProxyControls(t *testing.T) {
	for _, name := range []string{"--allow", "--allow-port", "--allow-private-host", "--rule", "--observe",
		"TLS-inspected", "1 MiB", "help proxy"} {
		if !strings.Contains(proxyHelpSummary, name) {
			t.Errorf("main help's proxy summary does not mention %s", name)
		}
	}
}

// --deny-all must suppress the api.anthropic.com default, so `run` can start a
// generic command with no reachable host at all.
func TestDenyAllSuppressesDefaultAllow(t *testing.T) {
	if got := effectiveAllowPatterns(nil, false, false); !slices.Equal(got, defaultAllow) {
		t.Errorf("bare proxy default = %v, want %v", got, defaultAllow)
	}
	for _, c := range []struct{ observe, denyAll bool }{
		{observe: false, denyAll: true},
		{observe: true, denyAll: false},
	} {
		if got := effectiveAllowPatterns(nil, c.observe, c.denyAll); len(got) != 0 {
			t.Errorf("observe=%v denyAll=%v: patterns = %v, want none", c.observe, c.denyAll, got)
		}
	}
	if got := effectiveAllowPatterns([]string{"a.example"}, false, true); !slices.Equal(got, []string{"a.example"}) {
		t.Errorf("explicit list = %v, want it kept", got)
	}
}

// Hostnames in the observe summary come from the sandboxed program. Only
// well-formed ones may be printed, and the ALLOW line must be single-quoted
// so pasting it into a shell expands nothing.
func TestObserveSummaryOmitsMalformedHosts(t *testing.T) {
	var buf strings.Builder
	list, _ := proxy.NewAllowList(nil)
	printSummary(&buf, []proxy.Stat{
		{Host: "api.anthropic.com", Port: "443"},
		{Host: "$(touch /tmp/pwned).evil.com", Port: "443"},
		{Host: "evil.com", Port: "443;id"},
		{Host: "\x1b]0;title\x07x.com", Port: "443"},
	}, list, true)
	out := buf.String()
	for _, bad := range []string{"$(", "touch", ";id", "\x1b"} {
		if strings.Contains(out, bad) {
			t.Errorf("summary contains %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "ALLOW='--allow api.anthropic.com'") {
		t.Errorf("ALLOW line missing or not single-quoted:\n%s", out)
	}
	if !strings.Contains(out, "3 destinations with malformed") {
		t.Errorf("summary should say how many were omitted:\n%s", out)
	}
}
