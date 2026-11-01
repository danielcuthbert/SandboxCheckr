package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
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
