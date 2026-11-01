package sblint

import (
	"strings"
	"testing"
)

func hasFinding(r Result, titleSub string) bool {
	for _, f := range r.Findings {
		if strings.Contains(strings.ToLower(f.Title), strings.ToLower(titleSub)) {
			return true
		}
	}
	return false
}

// The permissive shape: allow-default, writes locked to an allow-list, reads and
// egress open. This is the case the whole investigation turned on, so the linter
// must nail it.
func TestPermissiveProfile(t *testing.T) {
	p := `(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath (param "TARGET_DIR")))`
	r := Lint(p)

	if r.Egress != EgressOpen {
		t.Errorf("egress = %s, want open", r.Egress)
	}
	if !r.ReadsOpen {
		t.Error("reads should be reported open under allow-default")
	}
	if !r.Cooperative {
		t.Error("open egress should be flagged cooperative (bypassable)")
	}
	if !hasFinding(r, "everything by default") {
		t.Error("must flag allow-default")
	}
	if !hasFinding(r, "restricts writes but not reads") {
		t.Error("must flag the writes-locked/reads-open shape")
	}
	if !hasFinding(r, "outbound network is open") {
		t.Error("must flag open egress")
	}
}

// The strict shape: deny-default, but a broad read allow of "/" and a bare
// (allow network-outbound) — restrictive on paper yet reads and egress open.
func TestStrictButLeakyProfile(t *testing.T) {
	p := `(version 1)
(deny default)
(allow file-read* (literal "/") (subpath "/usr"))
(allow process-exec)
(allow network-outbound)`
	r := Lint(p)

	if r.Egress != EgressOpen {
		t.Errorf("egress = %s, want open (bare allow network-outbound)", r.Egress)
	}
	if !r.ReadsOpen {
		t.Error(`reads should be open when "/" is granted`)
	}
	if !hasFinding(r, "reads are broadly allowed") {
		t.Error(`must flag the "/" read grant`)
	}
	if hasFinding(r, "everything by default") {
		t.Error("deny-default profile must not be flagged as allow-default")
	}
}

// The network-deny shape: deny outbound, allow only the loopback proxy. This is
// the enforced-egress pattern and must be recognised as healthy.
func TestProxiedProfileIsHealthy(t *testing.T) {
	p := `(version 1)
(deny default)
(allow file-read* (subpath (param "TARGET_DIR")))
(deny network-outbound)
(allow network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket))`
	r := Lint(p)

	if r.Egress != EgressProxied {
		t.Errorf("egress = %s, want proxied", r.Egress)
	}
	if r.Cooperative {
		t.Error("enforced proxy egress must not be flagged cooperative")
	}
	if hasFinding(r, "outbound network is open") {
		t.Error("must not flag open egress when it is denied-except-proxy")
	}
}

// A tight deny-default profile with no network allow-back = strongest egress.
func TestDeniedEgress(t *testing.T) {
	p := `(version 1)
(deny default)
(allow file-read* (subpath (param "TARGET_DIR")))
(deny network*)`
	r := Lint(p)
	if r.Egress != EgressDenied {
		t.Errorf("egress = %s, want denied", r.Egress)
	}
	if r.ReadsOpen {
		t.Error("reads should not be open under deny-default without a broad read grant")
	}
}

// Blanket mach-lookup is flagged; an allow-listed one is not.
func TestMachLookup(t *testing.T) {
	blanket := Lint("(deny default)\n(allow mach-lookup)\n(deny network*)")
	if !hasFinding(blanket, "unrestricted mach-lookup") {
		t.Error("blanket mach-lookup must be flagged")
	}
	scoped := Lint(`(deny default)
(allow mach-lookup (global-name "com.apple.sysmond"))
(deny network*)`)
	if hasFinding(scoped, "unrestricted mach-lookup") {
		t.Error("an allow-listed mach-lookup must not be flagged")
	}
}

// Comments must not create false positives: a rule mentioned only in a comment
// is not a rule.
func TestCommentsAreIgnored(t *testing.T) {
	p := `(version 1)
;; we deliberately do NOT use (allow default) here
(deny default)
(deny network*)`
	r := Lint(p)
	if hasFinding(r, "everything by default") {
		t.Error("(allow default) mentioned only in a comment must not be flagged")
	}
}

// Every finding must carry a severity and a title, so the report can render it.
func TestFindingsWellFormed(t *testing.T) {
	r := Lint("(allow default)\n(deny file-write*)\n(allow file-write* (subpath \"/tmp/x\"))")
	if len(r.Findings) == 0 {
		t.Fatal("expected findings for a permissive profile")
	}
	for _, f := range r.Findings {
		if f.Severity == "" || f.Title == "" || f.Detail == "" {
			t.Errorf("malformed finding: %+v", f)
		}
	}
}

// A network deny with "harmless" holes: the shape of agent-seatbelt-sandbox's
// published profile. Egress is proxied for TCP, but DNS, every unix socket and
// every loopback port are open, and each needs naming.
func TestNetworkDenyWithHoles(t *testing.T) {
	p := `(version 1)
(allow default)
(deny network*)
;; DNS resolution via macOS system resolver (mDNSResponder)
(allow network-outbound (literal "/private/var/run/mDNSResponder"))
(allow network-outbound (remote unix-socket))
(allow network-outbound (remote ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))`
	r := Lint(p)
	if r.Egress != EgressProxied {
		t.Errorf("egress = %s, want proxied", r.Egress)
	}
	if !r.ReadsOpen {
		t.Error("allow-default with no blanket read deny must report reads open")
	}
	for _, want := range []string{"dns resolver reachable", "any unix socket", "every loopback port"} {
		if !hasFinding(r, want) {
			t.Errorf("must flag %q", want)
		}
	}
	for _, f := range r.Findings {
		if strings.Contains(strings.ToLower(f.Title), "dns") && f.Line != 5 {
			t.Errorf("DNS finding on line %d, want 5 (the rule, not the comment)", f.Line)
		}
	}
}

// The narrow forms of the same rules are fine.
func TestNarrowNetworkHolesAreNotFlagged(t *testing.T) {
	p := `(version 1)
(deny default)
(deny network*)
(allow network-outbound (remote ip "localhost:8899"))
(allow network-outbound (remote unix-socket (path-literal "/tmp/proxy.sock")))
(deny network-outbound (literal "/private/var/run/mDNSResponder"))`
	r := Lint(p)
	for _, bad := range []string{"dns resolver", "any unix socket", "every loopback port"} {
		if hasFinding(r, bad) {
			t.Errorf("narrow rule wrongly flagged as %q", bad)
		}
	}
}

// Denying one directory under allow-default does not close reads.
func TestNarrowReadDenyLeavesReadsOpen(t *testing.T) {
	r := Lint(`(version 1)
(allow default)
(deny file-read* (subpath (param "SECRETS_DIR")))
(deny file-write* (subpath (param "SECRETS_DIR")))
(deny network*)`)
	if !r.ReadsOpen {
		t.Error("a single-directory read deny must not count as restricting reads")
	}
	if !hasFinding(r, "filesystem reads are open") {
		t.Error("must flag open reads under allow-default")
	}
}
