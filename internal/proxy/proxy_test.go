package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRuleExactByDefault(t *testing.T) {
	r, err := ParseRule("api.anthropic.com")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Matches("api.anthropic.com") {
		t.Error("should match itself")
	}
	// Exact-by-default is the whole point: allowing a domain must not silently
	// allow every host anyone parks beneath it.
	if r.Matches("evil.api.anthropic.com") {
		t.Error("an exact rule must not match subdomains")
	}
	if r.Matches("notapi.anthropic.com") {
		t.Error("an exact rule must not match a different host")
	}
}

func TestRuleWildcard(t *testing.T) {
	for _, pattern := range []string{".anthropic.com", "*.anthropic.com"} {
		r, err := ParseRule(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Matches("api.anthropic.com") {
			t.Errorf("%s should match a subdomain", pattern)
		}
		if !r.Matches("anthropic.com") {
			t.Errorf("%s should match the apex", pattern)
		}
		if r.Matches("notanthropic.com") {
			t.Errorf("%s must not match a lookalike domain", pattern)
		}
		if r.Matches("anthropic.com.evil.net") {
			t.Errorf("%s must not match a suffix-confusion host", pattern)
		}
	}
}

// A rule that permits everything defeats the proxy and must be refused rather
// than quietly accepted.
func TestRuleRejectsCatchAll(t *testing.T) {
	for _, bad := range []string{"*", ".", "", "   "} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("ParseRule(%q) should be rejected", bad)
		}
	}
}

func TestHostMatchingIsCaseInsensitive(t *testing.T) {
	a, err := NewAllowList([]string{"API.Anthropic.COM"})
	if err != nil {
		t.Fatal(err)
	}
	if !a.PermitsHost("api.anthropic.com") {
		t.Error("host matching must be case-insensitive")
	}
	if !a.PermitsHost("api.anthropic.com.") {
		t.Error("a trailing root dot must not defeat matching")
	}
}

// The address guard is what stops an allow-listed name whose DNS an attacker
// controls from turning the proxy into a confused deputy against the metadata
// endpoint or the internal network.
func TestAddressGuardBlocksNonPublic(t *testing.T) {
	a, _ := NewAllowList([]string{"example.com"})

	blocked := []string{
		"169.254.169.254", // cloud metadata
		"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
		"100.64.0.1", "0.0.0.0", "::1", "fd00::1",
	}
	for _, s := range blocked {
		if err := a.CheckAddr(net.ParseIP(s)); err == nil {
			t.Errorf("%s should be refused", s)
		}
	}

	for _, s := range []string{"1.1.1.1", "93.184.216.34", "2606:2800:220:1::1"} {
		if err := a.CheckAddr(net.ParseIP(s)); err != nil {
			t.Errorf("%s should be permitted: %v", s, err)
		}
	}
}

func TestAddressGuardHonoursOverride(t *testing.T) {
	a, _ := NewAllowList([]string{"example.com"})
	a.AllowPrivate = true
	if err := a.CheckAddr(net.ParseIP("169.254.169.254")); err != nil {
		t.Error("--allow-private should permit link-local")
	}
}

// Ranges the guard used to leave open. Each is unreachable in a default
// install, which is what makes them worth closing: the ones that matter are
// reachable exactly when something else on the host has already put a route
// there, and that is the case where an allow-listed name answering from one of
// them is indistinguishable from a redirect to a host service.
func TestAddressGuardCoversReservedRanges(t *testing.T) {
	a, _ := NewAllowList([]string{"example.com"})
	blocked := []string{
		"0.1.2.3",           // "this host on this network"
		"0.255.255.255",     //
		"192.0.0.1",         // IETF protocol assignments
		"198.18.0.1",        // benchmarking
		"198.19.255.1",      //
		"240.0.0.1",         // reserved
		"255.255.255.255",   // limited broadcast
		"2002:0a00:0001::",  // 6to4, embeds 10.0.0.1
		"2001:0000:0001::1", // Teredo
		"100::1",            // discard-only
	}
	for _, s := range blocked {
		if err := a.CheckAddr(net.ParseIP(s)); err == nil {
			t.Errorf("%s should be refused", s)
		}
	}
	// Ordinary global addresses must still get through, including ones that
	// share a prefix with a refused range at a distance.
	for _, s := range []string{"1.1.1.1", "192.0.2.1", "198.51.100.1", "203.0.113.9", "2001:db8::1", "1000::1"} {
		if err := a.CheckAddr(net.ParseIP(s)); err != nil {
			t.Errorf("%s should be permitted: %v", s, err)
		}
	}
}

// A path rule is the only thing between "trust this code host" and "fetch
// anybody's payload", so a prefix has to end at a path boundary. Prefix
// matching alone admitted /acmeevil beside /acme.
func TestHostRulePathAnchorsAtBoundary(t *testing.T) {
	request := func(t *testing.T, target string) *http.Request {
		t.Helper()
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{Method: "GET", URL: u}
	}
	hr, err := ParseHostRule("raw.githubusercontent.com:GET:/acme/")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/acme", "/acme/", "/acme/README.md", "/acme/a/b/c"} {
		if ok, why := hr.Permits(request(t, "http://raw.githubusercontent.com"+p)); !ok {
			t.Errorf("%s should be permitted: %s", p, why)
		}
	}
	for _, p := range []string{"/acmeevil/README.md", "/acme-secret/x", "/acme/../other/x", "/ACME/x", "/", "/x/acme/y"} {
		if ok, _ := hr.Permits(request(t, "http://raw.githubusercontent.com"+p)); ok {
			t.Errorf("%s should be refused by a /acme/ prefix", p)
		}
	}
	// Encoded separators and dots are the server's to decode, not ours: refuse
	// rather than guess whether %2e%2e walked out of the prefix.
	for _, p := range []string{"/acme/%2e%2e/other/x", "/acme/%2f..%2f", "/acme/%2E%2E/x"} {
		if ok, _ := hr.Permits(request(t, "http://raw.githubusercontent.com"+p)); ok {
			t.Errorf("%s should be refused as encoded traversal", p)
		}
	}
	// "/" is what a user writes for "any path"; it must not narrow anything.
	root, err := ParseHostRule("raw.githubusercontent.com:GET:/")
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := root.Permits(request(t, "http://raw.githubusercontent.com/anything/at/all")); !ok {
		t.Errorf("a / prefix should permit any path: %s", why)
	}
}

func TestSplitHostPortDefaults(t *testing.T) {
	h, p, err := SplitHostPort("example.com", "443")
	if err != nil || h != "example.com" || p != "443" {
		t.Errorf("got %q %q %v", h, p, err)
	}
	h, p, err = SplitHostPort("example.com:8443", "443")
	if err != nil || h != "example.com" || p != "8443" {
		t.Errorf("got %q %q %v", h, p, err)
	}
}

// startProxy runs a server on an ephemeral port for the duration of a test.
func startProxy(t *testing.T, allow []string, observe bool) (addr string, logBuf *syncBuffer) {
	t.Helper()
	list, err := NewAllowList(allow)
	if err != nil {
		t.Fatal(err)
	}
	// The test upstream lives on loopback, which the address guard refuses by
	// design; permit it so this exercises allow-list logic rather than the guard.
	list.AllowPrivate = true
	// The upstream binds a random port; this exercises host logic, and the
	// port restriction has its own tests.
	list.AnyPort = true

	logBuf = &syncBuffer{}
	srv := NewServer(list, observe, logBuf)
	addr, err = srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)
	return addr, logBuf
}

// startUpstream runs a plain HTTP origin server.
func startUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = bufio.NewReader(c).ReadString('\n')
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
			}(c)
		}
	}()
	return ln.Addr().String()
}

// proxyRequest issues an absolute-form request through the proxy.
func proxyRequest(t *testing.T, proxyAddr, targetURL string) *http.Response {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		targetURL, strings.TrimPrefix(targetURL, "http://"))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading proxy response: %v", err)
	}
	return resp
}

// The central enforcement property: a host that is not allow-listed is refused.
func TestProxyDeniesUnlistedHost(t *testing.T) {
	upstream := startUpstream(t)
	proxyAddr, logBuf := startProxy(t, []string{"allowed.test"}, false)

	resp := proxyRequest(t, proxyAddr, "http://"+upstream+"/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unlisted host got %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(logBuf.String(), "DENY") {
		t.Errorf("denial should be logged, got: %s", logBuf.String())
	}
}

// And the converse: an allow-listed host is reachable, so the proxy is not
// simply refusing everything.
func TestProxyAllowsListedHost(t *testing.T) {
	upstream := startUpstream(t)
	host, _, _ := net.SplitHostPort(upstream)
	proxyAddr, logBuf := startProxy(t, []string{host}, false)

	resp := proxyRequest(t, proxyAddr, "http://"+upstream+"/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed host got %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(logBuf.String(), "ALLOW") {
		t.Errorf("allowance should be logged, got: %s", logBuf.String())
	}
}

// Observe mode must permit and record, and must say plainly in the log that it
// is not enforcing — otherwise someone leaves it on believing they are protected.
func TestObserveModePermitsAndMarksWouldDeny(t *testing.T) {
	upstream := startUpstream(t)
	proxyAddr, logBuf := startProxy(t, nil, true)

	resp := proxyRequest(t, proxyAddr, "http://"+upstream+"/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("observe mode should permit, got %d", resp.StatusCode)
	}
	log := logBuf.String()
	if !strings.Contains(log, "OBSERVE") || !strings.Contains(log, "would be DENIED") {
		t.Errorf("observe log must flag that it is not enforcing, got: %s", log)
	}
}

// CONNECT to an unlisted host must be refused before any tunnel is established.
func TestProxyDeniesUnlistedConnect(t *testing.T) {
	proxyAddr, _ := startProxy(t, []string{"allowed.test"}, false)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprint(conn, "CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "403") {
		t.Errorf("CONNECT to unlisted host should be 403, got %q", line)
	}
}

// The limits must be stated, not left for the reader to discover. The relay
// caveat in particular is the one that mattered in the 2026 incident.
func TestKnownLimitsCoverRelay(t *testing.T) {
	joined := strings.ToLower(strings.Join(KnownLimits(), " "))
	for _, want := range []string{"forward", "relay", "loopback"} {
		if !strings.Contains(joined, want) {
			t.Errorf("KnownLimits should mention %q", want)
		}
	}
}
