package probe

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// The single most important property of the env probe: it must report which
// credentials are exposed without ever emitting their values. This tool's
// output lands in terminals, CI logs and JSON artifacts, so a probe that
// printed secrets would become the exfiltration channel it is warning about.
func TestEnvProbeNeverLeaksValues(t *testing.T) {
	const canary = "sk-canary-VALUE-must-never-appear-0123456789"
	t.Setenv("SANDBOXCHECKR_TEST_API_KEY", canary)

	r := probeEnvSecrets()

	if strings.Contains(r.Detail, canary) {
		t.Fatal("probe leaked a secret VALUE into its output")
	}
	if strings.Contains(r.Err, canary) || strings.Contains(r.Errno, canary) {
		t.Fatal("probe leaked a secret value into an error field")
	}
	if !strings.Contains(r.Detail, "SANDBOXCHECKR_TEST_API_KEY") {
		t.Errorf("probe should report the variable NAME, got: %s", r.Detail)
	}
	if r.Verdict != model.VerdictAllowed {
		t.Errorf("an exposed credential should be ALLOWED (i.e. a finding), got %s", r.Verdict)
	}
}

// Names that merely describe credential configuration are not credentials.
// Without this the probe fires on ordinary developer machines and gets ignored.
func TestEnvProbeIgnoresConfigShapedNames(t *testing.T) {
	t.Setenv("SANDBOXCHECKR_TEST_CREDENTIAL_PROVIDERS", "one,two")
	r := probeEnvSecrets()
	if strings.Contains(r.Detail, "SANDBOXCHECKR_TEST_CREDENTIAL_PROVIDERS") {
		t.Error("a _PROVIDERS name lists providers, not secrets, and should not be reported")
	}
}

func TestEnvProbeMatchesCommonCredentialNames(t *testing.T) {
	for _, name := range []string{
		"SCRTEST_AWS_SECRET_ACCESS_KEY",
		"SCRTEST_GITHUB_TOKEN",
		"SCRTEST_DB_PASSWORD",
		"SCRTEST_ANTHROPIC_API_KEY",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "value")
			if r := probeEnvSecrets(); !strings.Contains(r.Detail, name) {
				t.Errorf("%s should be reported as credential-shaped", name)
			}
		})
	}
}

// The DNS tunnel probe must use a fixed benign label. Encoding anything real
// would make the tool itself exfiltrate data every time it ran.
func TestDNSTunnelLabelCarriesNoData(t *testing.T) {
	if !strings.HasSuffix(tunnelDomain, ".invalid") {
		t.Error("the tunnel probe must target a reserved non-existent TLD")
	}
	if strings.ContainsAny(tunnelLabel, "${}") {
		t.Error("the tunnel label must be a constant, not interpolated")
	}
	// A fixed label means two runs are indistinguishable on the wire.
	if tunnelLabel != "sandboxcheckr-probe-0000000000000000000000000000" {
		t.Error("the tunnel label should be a stable constant")
	}
}

func TestProxyHostPort(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:2677":          "127.0.0.1:2677",
		"http://proxy.example.com":       "proxy.example.com:80",
		"https://user:pw@proxy.corp:911": "proxy.corp:911",
		"proxy.local:3128":               "proxy.local:3128",
		"http://proxy.example.com/path":  "proxy.example.com:80",
		"":                               "",
	}
	for in, want := range cases {
		if got := proxyHostPort(in); got != want {
			t.Errorf("proxyHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// Credentials embedded in a proxy URL must not survive into the report.
func TestProxyHostPortStripsCredentials(t *testing.T) {
	got := proxyHostPort("http://admin:hunter2@proxy.corp:8080")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "admin") {
		t.Errorf("proxy credentials leaked into %q", got)
	}
}

// Filesystem probes must leave nothing behind, since they run against real
// directories the user cares about.
func TestSharedScratchProbeCleansUp(t *testing.T) {
	before, err := os.ReadDir("/tmp")
	if err != nil {
		t.Skip("cannot read /tmp")
	}
	probeSharedScratch()
	after, err := os.ReadDir("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range after {
		if strings.HasPrefix(e.Name(), ".sandboxcheckr-shared-") {
			t.Errorf("probe left %s behind", e.Name())
		}
	}
	if len(after) > len(before)+2 {
		t.Errorf("probe appears to have added %d entries", len(after)-len(before))
	}
}

// Every exfil probe must declare BLOCKED as the healthy outcome, or the score
// would reward an open channel.
func TestExfilProbesWantBlocked(t *testing.T) {
	for _, r := range RunExfilBattery(homeView(t.TempDir(), "")) {
		if r.Want != model.VerdictBlocked {
			t.Errorf("%s wants %s, should want BLOCKED", r.ID, r.Want)
		}
		if r.Detail == "" && r.Verdict != model.VerdictSkipped {
			t.Errorf("%s produced no detail", r.ID)
		}
	}
}

// An allow-listing proxy that refuses an unlisted destination is egress
// control working. It must not be reported as an open egress path, or the
// proxied sandbox would score below one with no proxy at all.
func TestProxyEnvEnforcingProxyIsBlocked(t *testing.T) {
	addr := fakeProxy(t, "HTTP/1.1 403 Forbidden\r\n\r\n")
	t.Setenv("HTTPS_PROXY", "http://"+addr)
	if r := probeProxyEnv(); r.Verdict != model.VerdictBlocked {
		t.Errorf("enforcing proxy gave %s, want BLOCKED: %s", r.Verdict, r.Detail)
	}
}

func TestProxyEnvRelayingProxyIsAllowed(t *testing.T) {
	addr := fakeProxy(t, "HTTP/1.1 200 Connection established\r\n\r\n")
	t.Setenv("HTTPS_PROXY", "http://"+addr)
	if r := probeProxyEnv(); r.Verdict != model.VerdictAllowed {
		t.Errorf("relaying proxy gave %s, want ALLOWED: %s", r.Verdict, r.Detail)
	}
}

func fakeProxy(t *testing.T, reply string) string {
	t.Helper()
	for _, v := range proxyEnvVars {
		t.Setenv(v, "")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback")
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 512)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte(reply))
			c.Close()
		}
	}()
	return ln.Addr().String()
}
