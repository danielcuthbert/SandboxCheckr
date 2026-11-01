package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseHostRule(t *testing.T) {
	r, err := ParseHostRule("registry.internal:get,HEAD:/api/npm/,/api/pypi/")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, path string
		ok           bool
	}{
		{"GET", "/api/npm/left-pad", true},
		{"HEAD", "/api/pypi/simple/", true},
		{"PUT", "/api/npm/left-pad", false},
		{"MKCOL", "/api/npm/board/", false},
		{"GET", "/api/other/x", false},
		{"GET", "/api/npm/../admin", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "https://registry.internal"+c.path, nil)
		if ok, why := r.Permits(req); ok != c.ok {
			t.Errorf("%s %s: got %v (%s), want %v", c.method, c.path, ok, why, c.ok)
		}
	}
	for _, bad := range []string{"host", "host:CONNECT", "host:GET:relative", "*:GET"} {
		if _, err := ParseHostRule(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// Per-host private access opens exactly one host, and never the link-local
// range that holds the cloud metadata endpoint.
func TestPrivateHostIsScoped(t *testing.T) {
	a, _ := NewAllowList([]string{"registry.internal", "example.com"})
	if err := a.AddPrivateHost("registry.internal"); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckHostAddr("registry.internal", net.ParseIP("10.0.0.5")); err != nil {
		t.Errorf("named private host should be allowed: %v", err)
	}
	if err := a.CheckHostAddr("example.com", net.ParseIP("10.0.0.5")); err == nil {
		t.Error("other hosts must still be refused private addresses")
	}
	if err := a.CheckHostAddr("registry.internal", net.ParseIP("169.254.169.254")); err == nil {
		t.Error("link-local (cloud metadata) must stay refused even for a private host")
	}
}

func TestRelayKind(t *testing.T) {
	for _, h := range []string{"registry.npmjs.org", "acme.jfrog.io", "artifactory.corp", "pastebin.com", "github.com"} {
		if RelayKind(h) == "" {
			t.Errorf("%s should be recognised as store-or-forward", h)
		}
	}
	if k := RelayKind("api.anthropic.com"); k != "" {
		t.Errorf("api.anthropic.com flagged as %q", k)
	}
}

// The inspection CA must be constrained to the ruled hosts, so a leaked key
// cannot mint a certificate that constraint-honouring clients accept for any
// other name.
func TestCAIsNameConstrained(t *testing.T) {
	ca, err := NewCA([]string{"registry.internal", ".corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.PermittedDNSDomainsCritical {
		t.Error("name constraints must be critical")
	}
	got := strings.Join(ca.cert.PermittedDNSDomains, ",")
	if got != "registry.internal,corp.example" {
		t.Errorf("permitted domains = %q", got)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	for host, want := range map[string]bool{"registry.internal": true, "a.corp.example": true, "evil.com": false} {
		leaf, err := ca.leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(leaf.Certificate[0])
		_, verr := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
		if (verr == nil) != want {
			t.Errorf("%s: verify err=%v, want ok=%v", host, verr, want)
		}
	}
}

// End to end: a ruled host is inspected, GET passes, PUT and WebDAV MKCOL are
// refused before reaching the server. This is the registry-as-message-board
// case from the 2026 incident.
func TestInspectionEnforcesRule(t *testing.T) {
	var got []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	host := "127.0.0.1" // the httptest certificate covers 127.0.0.1, not localhost

	list, _ := NewAllowList([]string{host})
	list.AnyPort = true
	_ = list.AddPrivateHost(host)
	if err := list.AddHostRule(host + ":GET,HEAD"); err != nil {
		t.Fatal(err)
	}
	ca, err := NewCA([]string{host})
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	srv := NewServer(list, false, &logBuf)
	srv.CA = ca
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	srv.UpstreamRoots = roots
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca.cert)
	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: clientRoots},
	}}
	target := "https://" + net.JoinHostPort(host, port)
	for _, c := range []struct {
		method string
		want   int
	}{{"GET", 200}, {"PUT", 403}, {"MKCOL", 403}} {
		req, _ := http.NewRequest(c.method, target+"/pkg", strings.NewReader("x"))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.method, err, logBuf.String())
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", c.method, resp.StatusCode, c.want)
		}
	}
	if strings.Join(got, ",") != "GET /pkg" {
		t.Errorf("only the GET should have reached the server, got %v", got)
	}
}

// Bytes sent to a host are counted without decryption, and a host receiving
// more than UploadWarnBytes is flagged.
func TestUploadIsCountedAndFlagged(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer up.Close()
	upstream := strings.TrimPrefix(up.URL, "http://")
	addr, logBuf := startProxy(t, []string{"127.0.0.1"}, false)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("a"), UploadWarnBytes+1024)
	fmt.Fprintf(conn, "POST http://%s/up HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", upstream, upstream, len(body))
	conn.Write(body)
	bufio.NewReader(conn).ReadString('\n')
	conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logBuf.String(), "WARN") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(logBuf.String(), "WARN") {
		t.Errorf("a >1 MiB upload must be flagged; log:\n%s", logBuf.String())
	}
}
