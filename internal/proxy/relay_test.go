package proxy

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// The services the 2026 agent swarms used as message boards and ways onward
// (SWM-007) must be recognised, and recognised as relaying on a plain GET.
func TestSwarmRelaysAreGetRelays(t *testing.T) {
	for _, h := range []string{
		"is.gd", "v.gd", "da.gd", "2dd.pl", "vanderbi.lt", "uoft.me", "goto.unm.edu", "u.ethz.ch",
		"r.jina.ai", "pure.md", "markdown.new", "md.succ.ai", "api.microlink.io",
		"allorigins.hexlet.app", "api.cors.lol", "cors.io", "cors.bwa.workers.dev",
		"jqp.vercel.app", "httpbin.org", "docs.google.com", "example-com.translate.goog",
		"urlquery.net", "abc.trycloudflare.com", "x.ngrok-free.app",
	} {
		if RelayKind(h) == "" {
			t.Errorf("%s should be recognised as store-or-forward", h)
		}
		if !RelaysOnGet(h) {
			t.Errorf("%s should be marked as relaying on a plain GET", h)
		}
		if r := SuggestedRule(h); r != "" {
			t.Errorf("%s: no method rule contains a GET relay, but %q was suggested", h, r)
		}
	}
}

// A paste site or registry stores on a write, so a download-only rule still
// means something there.
func TestWriteRelaysStillGetARule(t *testing.T) {
	for _, h := range []string{"registry.npmjs.org", "paste.linuxiarz.pl", "jsonhero.io", "rubygems.org"} {
		if RelayKind(h) == "" {
			t.Errorf("%s should be recognised", h)
		}
		if RelaysOnGet(h) {
			t.Errorf("%s should not be marked GET-relay", h)
		}
		if SuggestedRule(h) == "" {
			t.Errorf("%s should still get a download-only suggestion", h)
		}
	}
}

// Short domain patterns must match whole labels: is.gd must not swallow every
// .gd domain that happens to end in "is".
func TestRelayMatchingIsLabelAware(t *testing.T) {
	for _, h := range []string{"analysis.gd", "notgithub.com", "bit.lyrics.example", "thisisnotis.gd.example"} {
		if k := RelayKind(h); k != "" {
			t.Errorf("%s wrongly flagged as %q", h, k)
		}
	}
	for _, h := range []string{"api.github.com", "GITHUB.COM.", "gist.githubusercontent.com", "my.artifactory.corp"} {
		if RelayKind(h) == "" {
			t.Errorf("%s should still match", h)
		}
	}
}

// Every decision lands in the event log, labelled and classified, so the
// console can show where an agent went — refusals included.
func TestProxyWritesEvents(t *testing.T) {
	upstream := startUpstream(t)
	list, err := NewAllowList([]string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	list.AllowPrivate = true
	list.AnyPort = true
	var buf syncBuffer
	srv := NewServer(list, false, io.Discard)
	srv.Events = events.NewWriter(&buf, "agent-1")
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)

	resp := proxyRequest(t, addr, "http://"+upstream+"/?url=https://is.gd/x")
	resp.Body.Close()

	var evs []events.Event
	for i := 0; i < 50; i++ {
		evs, _ = events.Read(strings.NewReader(buf.String()))
		if len(evs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(evs) == 0 {
		t.Fatal("no events written")
	}
	e := evs[0]
	if e.Agent != "agent-1" || e.Kind != events.KindConnect || e.Decision != events.Deny {
		t.Errorf("got %+v, want a labelled connect/deny", e)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
