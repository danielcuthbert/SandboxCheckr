package main

import (
	"strings"
	"testing"
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
