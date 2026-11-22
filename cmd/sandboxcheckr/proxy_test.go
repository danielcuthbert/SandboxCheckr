package main

import (
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

// The proxy takes its whole policy from flags, so an entry that can never match
// is worse than a rejected one: the documented answer to unexplained DENYs is
// --observe or --allow-private, which means a typo buys a policy downgrade
// rather than a correction. Each case here used to be accepted.
func TestProxyRejectsMalformedPolicyFlags(t *testing.T) {
	cases := []struct {
		flag  string
		value string
	}{
		{"--allow", "https://example.com"},
		{"--allow", "exa mple.com"},
		{"--allow", "example.com/path"},
		{"--allow-port", "443x"},
		{"--allow-port", "0"},
		{"--allow-port", "65536"},
		{"--allow-private-host", "-evil.com"},
		{"--rule", "exa mple.com:GET"},
		{"--rule", "example.com"},
	}
	for _, c := range cases {
		code, out := withStderr(t, func() int {
			return runProxy([]string{c.flag, c.value})
		})
		if code != 2 {
			t.Errorf("%s %q: exit %d, want 2 (output: %s)", c.flag, c.value, code, out)
		}
		if !strings.Contains(out, c.flag) {
			t.Errorf("%s %q was refused for some other reason: %s", c.flag, c.value, out)
		}
	}
}

// The exit summary is the part of the output a reader aligns by eye, so colour
// must not move a column or leak past the end of a line. That holds only if the
// widths are measured on plain text and the escapes wrap whole fields, which is
// what this compares: the coloured render stripped of escapes has to be the
// plain render, byte for byte.
func TestSummaryColourKeepsTheColumns(t *testing.T) {
	list, _ := proxy.NewAllowList([]string{"api.anthropic.com"})
	stats := []proxy.Stat{
		{Host: "api.anthropic.com", Port: "443", Conns: 3, Sent: 1 << 20, Received: 4096},
		{Host: "is.gd", Port: "443", Conns: 1, Denied: 1, Relay: proxy.RelayKind("is.gd"), RelaysOnGet: true},
		{Host: proxy.AggregateHost, Port: "-", Conns: 40, Denied: 39, Sent: 12, Received: 0},
	}
	trips := []proxy.Trip{{Confidence: "high", Label: "aws-key", Method: "POST", Host: "is.gd", Port: "443"}}
	render := func(st emit.Styles) string {
		var b strings.Builder
		printCanarySummary(&b, st, "13610e6f165edfb7", trips, true)
		printSummary(&b, st, stats, list, true, 5)
		return b.String()
	}
	on := emit.Palette(true)
	plain, coloured := render(emit.Styles{}), render(on)
	if got := ansiSequences.ReplaceAllString(coloured, ""); got != plain {
		t.Errorf("colour moved a column.\nplain:\n%s\ncoloured, stripped:\n%s", plain, got)
	}
	for _, line := range strings.Split(coloured, "\n") {
		if strings.Contains(line, "\x1b") && !strings.Contains(line, on.Reset) {
			t.Errorf("an unclosed escape leaks colour into the shell: %q", line)
		}
	}
}
