package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

func TestCanaryHostDeniedInObserveBeforeDNS(t *testing.T) {
	s, err := canary.New("", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	list, _ := NewAllowList([]string{"example.com"})
	srv := NewServer(list, true, io.Discard)
	srv.Canaries = s
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", s.Credentials[0].Host, s.Credentials[0].Host)
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "403 Forbidden") {
		t.Fatalf("response: %s", b)
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "medium" {
		t.Fatalf("trips: %+v", trips)
	}
}

func TestExternalTokenDNSForwarded(t *testing.T) {
	// The token service's nameserver must see the lookup or its alert never
	// fires, so the relay forwards instead of refusing, and answers with
	// whatever the resolver said.
	fake := fakeDNSOverTCP(t, func(q []byte) []byte {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		return r
	})
	logBuf := &syncBuffer{}
	eventsBuf := &syncBuffer{}
	srv := newDNSServer(t, []string{"example.test"}, false, logBuf, fake)
	srv.Events = events.NewWriter(eventsBuf, "test")
	srv.Canaries = &canary.Set{RunID: "ext", Credentials: []canary.Credential{
		{Label: "external canarytoken", Host: "abc123.tokenexample.com", Value: "abc123.tokenexample.com", External: true},
	}}
	c := startDNSProxy(t, srv)

	query := dnsQuery("abc123.tokenexample.com", 1)
	resp := exchangeDNS(t, c, query)
	if got := resp[3] & 0x0F; got != 0 {
		t.Fatalf("external token lookup: RCODE = %d, want 0 (forwarded, not refused)", got)
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "high" || trips[0].Label != "external canarytoken" {
		t.Fatalf("trips: %+v", trips)
	}
	if !strings.Contains(eventsBuf.String(), `"reason":"external canary token (forwarded)"`) {
		t.Fatalf("events: %s", eventsBuf.String())
	}
}

func TestExternalTokenConnectForwarded(t *testing.T) {
	// A connection to the token's own host is the token's intended use: the
	// proxy forwards it so the token service can alert, and the trip is
	// recorded at high confidence.
	var hit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	s := &canary.Set{RunID: "ext", Credentials: []canary.Credential{
		{Label: "external canarytoken", Host: "localhost", Value: "localhost", External: true},
	}}
	list, _ := NewAllowList(nil)
	// The token host resolves to loopback here, which the address guard
	// refuses by default: see TestExternalTokenHostToPrivateRefused. A token
	// service self-hosted on a private address is permitted exactly the way a
	// user would permit it.
	if err := list.AddPrivateHost("localhost"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(list, false, io.Discard)
	srv.Canaries = s
	eventsBuf := &syncBuffer{}
	srv.Events = events.NewWriter(eventsBuf, "test")
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)
	buf := make([]byte, 4096)
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), "200 Connection established") {
		t.Fatalf("connect response: %s", buf[:n])
	}
	fmt.Fprintf(c, "GET /canary HTTP/1.1\r\nHost: localhost:%s\r\nConnection: close\r\n\r\n", port)
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "200 OK") || !hit.Load() {
		t.Fatalf("tunnelled response: %q upstream hit=%v", b, hit.Load())
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "high" || trips[0].Host != "localhost" {
		t.Fatalf("trips: %+v", trips)
	}
	// A forwarded connection is a trip, not a refusal. Counting it as denied
	// made the exit summary report a connection it had just forwarded as
	// blocked.
	for _, st := range srv.Stats() {
		if st.Host == "localhost" && st.Denied != 0 {
			t.Fatalf("forwarded connection counted as denied: %+v", st)
		}
	}
	if !strings.Contains(eventsBuf.String(), `"reason":"external canary token (forwarded)"`) {
		t.Fatalf("events: %s", eventsBuf.String())
	}
}

func TestExternalValueTokenDenied(t *testing.T) {
	// A value token (an AWS key pair, a card number) has no host: its use is
	// the string appearing in request bytes, and that use is denied at high
	// confidence. The vendor email cannot fire, because the value never
	// leaves — the local trip is the detection.
	var hit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer upstream.Close()
	s := &canary.Set{RunID: "ext", Credentials: []canary.Credential{
		{Label: "external canarytoken (aws-keys)", Host: "", Value: "AKIABT8EXAMPLEKEY", External: true},
	}}
	list, _ := NewAllowList([]string{"127.0.0.1"})
	list.AllowPrivate = true
	list.AnyPort = true
	srv := NewServer(list, false, io.Discard)
	srv.Canaries = s
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := client.Post(upstream.URL, "text/plain", strings.NewReader("key=AKIABT8EXAMPLEKEY"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || hit.Load() {
		t.Fatalf("status=%d upstream hit=%v", resp.StatusCode, hit.Load())
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "high" || trips[0].Label != "external canarytoken (aws-keys)" {
		t.Fatalf("trips: %+v", trips)
	}
}

func TestExternalTokenDenyFileBeatsForward(t *testing.T) {
	// The deny file cuts a token host off even though the token's own
	// connection would otherwise be forwarded, matching the DNS relay: the
	// trip is recorded, then the connection is refused.
	denyPath := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(denyPath, []byte("localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deny, err := NewDenyFile(denyPath)
	if err != nil {
		t.Fatal(err)
	}
	var hit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	s := &canary.Set{RunID: "ext", Credentials: []canary.Credential{
		{Label: "external canarytoken", Host: "localhost", Value: "localhost", External: true},
	}}
	list, _ := NewAllowList(nil)
	srv := NewServer(list, false, io.Discard)
	srv.Canaries = s
	srv.Deny = deny
	eventsBuf := &syncBuffer{}
	srv.Events = events.NewWriter(eventsBuf, "test")
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "403 Forbidden") || hit.Load() {
		t.Fatalf("response: %q upstream hit=%v", b, hit.Load())
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "high" {
		t.Fatalf("trips: %+v", trips)
	}
	if !strings.Contains(eventsBuf.String(), `"reason":"in deny file`) {
		t.Fatalf("events: %s", eventsBuf.String())
	}
}

func TestExternalTokenHostToPrivateRefused(t *testing.T) {
	// A token host outside the allow-list is forwarded, but its addresses are
	// still vetted: a token (or a project file naming one) that resolves to
	// loopback must not have this unconfined process fetch a host service for
	// the sandbox. The trip is still recorded, because the name was used.
	var hit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	s := &canary.Set{RunID: "ext", Credentials: []canary.Credential{
		{Label: "external canarytoken", Host: "localhost", Value: "localhost", External: true},
	}}
	list, _ := NewAllowList(nil)
	srv := NewServer(list, false, io.Discard)
	srv.Canaries = s
	eventsBuf := &syncBuffer{}
	srv.Events = events.NewWriter(eventsBuf, "test")
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "403 Forbidden") || hit.Load() {
		t.Fatalf("response: %q upstream hit=%v", b, hit.Load())
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "high" {
		t.Fatalf("trips: %+v", trips)
	}
	if !strings.Contains(eventsBuf.String(), "non-public address") {
		t.Fatalf("events: %s", eventsBuf.String())
	}
}

func TestHostBookkeepingIsBounded(t *testing.T) {
	// The confined program chooses the destinations it dials, including names
	// that will be refused, so the host-side tables cannot grow at its pace.
	list, _ := NewAllowList([]string{"allowed.test"})
	srv := NewServer(list, false, io.Discard)
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	// Distinct refused destinations: counted before resolution, so this is the
	// path that would otherwise allocate a Stat each.
	for i := range maxStats + 50 {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT h%d.refused.invalid:443 HTTP/1.1\r\nHost: h%d.refused.invalid\r\n\r\n", i, i)
		_, _ = io.ReadAll(c)
		c.Close()
	}
	if got := len(srv.Stats()); got > maxStats+1 {
		t.Fatalf("stats rows: %d, want at most %d", got, maxStats+1)
	}
	if srv.StatsOverflow() == 0 {
		t.Fatal("expected overflow to be reported")
	}

	// Trips likewise: one canary host tripped past the bound keeps a window.
	s := &canary.Set{RunID: "bnd", Credentials: []canary.Credential{{
		Label: "cloud", Host: "aws-" + strings.Repeat("a", 8) + "-bnd.sandboxcheckr.invalid",
		Value: "sbc_" + strings.Repeat("0", 48),
	}}}
	srv.Canaries = s
	host := s.Credentials[0].Host
	for range maxTrips + 20 {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
		_, _ = io.ReadAll(c)
		c.Close()
	}
	if got := len(srv.Trips()); got != maxTrips {
		t.Fatalf("trips kept: %d, want %d", got, maxTrips)
	}
	if srv.TripOverflow() != 20 {
		t.Fatalf("trip overflow: %d, want 20", srv.TripOverflow())
	}
	for _, st := range srv.Stats() {
		if st.Host == host && len(st.CanaryLabels) > maxLabels {
			t.Fatalf("labels for one host: %d, want at most %d", len(st.CanaryLabels), maxLabels)
		}
	}
}

func TestCanaryStringDeniedBeforeUpstream(t *testing.T) {
	var hit atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer upstream.Close()
	s, err := canary.New("", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	list, _ := NewAllowList([]string{"127.0.0.1"})
	list.AllowPrivate = true
	list.AnyPort = true
	srv := NewServer(list, false, io.Discard)
	srv.Canaries = s
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	req, err := http.NewRequest(http.MethodPost, upstream.URL, strings.NewReader("loot="+s.Credentials[0].Value))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Expect", "100-continue")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || hit.Load() {
		t.Fatalf("status=%d upstream hit=%v", resp.StatusCode, hit.Load())
	}
	trips := srv.Trips()
	if len(trips) != 1 || trips[0].Confidence != "high" {
		t.Fatalf("trips: %+v", trips)
	}
}
