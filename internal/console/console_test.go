package console

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

var t0 = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

func ev(sec int, agent, kind, decision, host string, relay string, fetcher bool) events.Event {
	return events.Event{Time: t0.Add(time.Duration(sec) * time.Second), Agent: agent, Kind: kind,
		Decision: decision, Host: host, Port: "443", Relay: relay, Fetcher: fetcher}
}

// A small swarm: two agents, one refused at a shortener then reaching a
// fetcher, both reaching the same paste site.
func sample() []events.Event {
	return []events.Event{
		ev(0, "a1", events.KindConnect, events.Allow, "api.anthropic.com", "", false),
		ev(1, "a1", events.KindConnect, events.Deny, "is.gd", "URL shortener", true),
		ev(2, "a1", events.KindConnect, events.Allow, "r.jina.ai", "fetcher", true),
		ev(3, "a1", events.KindConnect, events.Allow, "paste.example.org", "paste service", false),
		ev(4, "a2", events.KindConnect, events.Allow, "paste.example.org", "paste service", false),
		ev(5, "a2", events.KindConnect, events.Allow, "api.anthropic.com", "", false),
		{Time: t0.Add(6 * time.Second), Agent: "a2", Kind: events.KindClose, Host: "paste.example.org", Port: "443", Sent: 900},
	}
}

func TestAgentsFlagsProbing(t *testing.T) {
	rows := Agents(sample())
	if len(rows) != 2 || rows[0].Agent != "a1" {
		t.Fatalf("want a1 first (most relays), got %+v", rows)
	}
	a1 := rows[0]
	if a1.Relays != 3 || a1.GetRelays != 2 || a1.RelayDeny != 1 || !a1.RetriedAfterDenial {
		t.Errorf("a1 summary wrong: %+v", a1)
	}
	if rows[1].RetriedAfterDenial {
		t.Error("a2 was never refused; it cannot have retried")
	}
}

func TestCanaryTripIsFirstInAgentSummary(t *testing.T) {
	e := ev(7, "a2", events.KindCanary, events.Deny, "db-123.sandboxcheckr.invalid", "", false)
	e.Canary, e.RunID, e.Confidence, e.Method = "database", "123", "medium", "CONNECT"
	evs := append(sample(), e)
	s := Summarise(evs)
	if len(s.Agents) != 2 || s.Agents[0].Agent != "a2" || Verdict(s.Agents[0]) != VerdictCanary {
		t.Fatalf("canary agent should rank first: %+v", s.Agents)
	}
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}}
	c.SetEvents(evs)
	if err := c.Run(context.Background(), "canaries agent=a2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "database") || !strings.Contains(out.String(), "medium") {
		t.Errorf("trip missing from console: %s", out.String())
	}
}

func TestSharedPutsRelaysFirst(t *testing.T) {
	rows := Shared(sample())
	if len(rows) != 2 {
		t.Fatalf("want 2 shared hosts, got %d", len(rows))
	}
	if rows[0].Host != "paste.example.org" {
		t.Errorf("a shared relay must sort before a shared ordinary host; got %s first", rows[0].Host)
	}
}

func TestFilters(t *testing.T) {
	f, err := ParseFilter([]string{"agent=a*", "decision=deny", "relay"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := Select(sample(), f); len(got) != 1 || got[0].Host != "is.gd" {
		t.Errorf("got %+v", got)
	}
	f, _ = ParseFilter([]string{"since=3s"}, t0.Add(6*time.Second))
	if got := Select(sample(), f); len(got) != 4 {
		t.Errorf("since=3s: got %d events, want 4", len(got))
	}
	for _, bad := range [][]string{{"decision=maybe"}, {"colour=red"}, {"since=yesterday"}, {"host"}} {
		if _, err := ParseFilter(bad, t0); err == nil {
			t.Errorf("%v should be rejected", bad)
		}
	}
}

// Output must never carry an escape sequence the sandboxed program chose.
func TestOutputIsSanitised(t *testing.T) {
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}}
	c.SetEvents([]events.Event{ev(0, "a1", events.KindConnect, events.Deny, "x\x1b]0;pwned\x07.example", "", false)})
	for _, cmd := range []string{"agents", "hosts", "events", "denied", "agent a1"} {
		out.Reset()
		if err := c.Run(context.Background(), cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if strings.ContainsAny(out.String(), "\x1b\x07") {
			t.Errorf("%s printed a raw control character: %q", cmd, out.String())
		}
	}
}

func TestCommands(t *testing.T) {
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}, Now: func() time.Time { return t0.Add(time.Minute) }}
	c.SetEvents(sample())
	for cmd, want := range map[string]string{
		"agents":           "tried another relay after refusal",
		"relays":           "! URL shortener",
		"shared":           "paste.example.org",
		"denied":           "is.gd",
		"agent a2":         "paste.example.org",
		"events host=jina": "r.jina.ai",
		"help":             "FILTERS",
	} {
		out.Reset()
		if err := c.Run(context.Background(), cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if !strings.Contains(out.String(), want) {
			t.Errorf("%s: output lacks %q:\n%s", cmd, want, out.String())
		}
	}
	if err := c.Run(context.Background(), "frobnicate"); err == nil {
		t.Error("unknown command should be an error")
	}
	if err := c.Run(context.Background(), "agent nobody"); err == nil {
		t.Error("unknown agent should be an error")
	}
}

func TestSummary(t *testing.T) {
	evs := append(sample(),
		events.Event{Time: t0.Add(7 * time.Second), Agent: "a2", Kind: events.KindUpload, Host: "paste.example.org", Port: "443", Sent: 2 << 20},
		ev(8, "a3", events.KindConnect, events.Allow, "api.anthropic.com", "", false),
	)
	s := Summarise(evs)
	if got := Verdict(s.Agents[0]); got != VerdictUpload || s.Agents[0].Agent != "a2" {
		t.Errorf("worst agent first: got %s %s", s.Agents[0].Agent, got)
	}
	want := map[string]string{"a1": VerdictReached, "a3": VerdictQuiet}
	for _, a := range s.Agents {
		if w, ok := want[a.Agent]; ok && Verdict(a) != w {
			t.Errorf("%s: verdict %s, want %s", a.Agent, Verdict(a), w)
		}
	}
	if s.RelayAttempts != 4 || s.RelayDenied != 1 {
		t.Errorf("relay counts %d/%d, want 4/1", s.RelayAttempts, s.RelayDenied)
	}
	if len(s.Findings) == 0 || s.Findings[0].Severity != 0 {
		t.Fatalf("an upload must be the first finding: %+v", s.Findings)
	}
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}}
	c.SetEvents(evs)
	if err := c.Run(context.Background(), "summary"); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"STATE OF THE NATION", "UPLOADING", "RELAY ACTIVITY", "WHAT TO LOOK AT", "→ agent a2"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("summary lacks %q", w)
		}
	}
}

// A store and a fetcher that share a class name stay separate rows.
func TestSummaryKeepsGetRelaysApart(t *testing.T) {
	s := Summarise([]events.Event{
		ev(0, "a", events.KindConnect, events.Allow, "store.example", "document store", false),
		ev(1, "a", events.KindConnect, events.Allow, "viewer.example", "document store (fetches any URL)", true),
	})
	if len(s.Relays) != 2 {
		t.Errorf("got %d relay rows, want 2: %+v", len(s.Relays), s.Relays)
	}
}

// Habits from other consoles must work: /exit, \q, :q, a trailing semicolon.
func TestQuitSpellings(t *testing.T) {
	c := &Console{Out: Printer{W: &bytes.Buffer{}}}
	for _, in := range []string{"quit", "exit", "/exit", "/exit;", `\q`, ":q", "  QUIT ; ", "/quit"} {
		if err := c.Run(context.Background(), in); err != io.EOF {
			t.Errorf("%q: got %v, want quit", in, err)
		}
	}
	if err := c.Run(context.Background(), "/help"); err != nil {
		t.Errorf("/help: %v", err)
	}
}

// Ctrl-C at the idle prompt hints, twice leaves, and never cancels the next
// command.
func TestREPLInterrupt(t *testing.T) {
	pr, pw := io.Pipe()
	intr := make(chan os.Signal, 1)
	var out syncBuf
	c := &Console{Out: Printer{W: &out}}
	c.SetEvents(sample())
	done := make(chan struct{})
	go func() { c.REPL(pr, true, intr); close(done) }()

	intr <- os.Interrupt
	waitFor(t, &out, "Ctrl-C again to leave")
	fmt.Fprintln(pw, "agents")
	waitFor(t, &out, "a1") // the command ran to completion
	intr <- os.Interrupt
	intr <- os.Interrupt
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("two Ctrl-Cs at the prompt should leave the console")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func waitFor(t *testing.T, b *syncBuf, want string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("output never contained %q:\n%s", want, b.String())
}

func TestBlockUnblock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "deny.txt")
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}, DenyPath: path}
	ctx := context.Background()
	if err := c.Run(ctx, "block is.gd R.JINA.AI."); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "is.gd\n") || !strings.Contains(string(data), "r.jina.ai\n") {
		t.Errorf("deny file lacks entries:\n%s", data)
	}
	// File modes are a Unix invariant (the kill switch must not be group or
	// world writable); Windows has no permission bits to assert.
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("deny file mode %v, want 0600", fi.Mode().Perm())
		}
	}
	if err := c.Run(ctx, "unblock is.gd"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "is.gd") || !strings.Contains(string(data), "r.jina.ai") {
		t.Errorf("unblock removed the wrong lines:\n%s", data)
	}
	if !strings.Contains(string(data), "# SandboxCheckr kill switch") {
		t.Error("the header comment must survive edits")
	}
	if err := c.Run(ctx, "block not;a;host"); err == nil {
		t.Error("an invalid host must be refused")
	}
	out.Reset()
	if err := c.Run(ctx, "blocked"); err != nil || !strings.Contains(out.String(), "r.jina.ai") {
		t.Errorf("blocked: %v\n%s", err, out.String())
	}
}

func TestRefusalClasses(t *testing.T) {
	cases := map[string]string{
		"in deny file (localhost)": "kill switch (deny file)",
		"resolved to non-public address 127.0.0.1; refusing (use --allow-private-host localhost to permit this host only)":             "private address",
		"resolved to non-public address 169.254.169.254; refusing (use --allow-private-host 169.254.169.254 to permit this host only)": "cloud metadata endpoint",
		"not in allow-list":                    "not on the allow-list",
		"port not permitted; use --allow-port": "port not permitted",
		"rule github.com:GET,HEAD:/x/: method PUT not permitted (allowed: GET,HEAD)":  "outside its --rule (method)",
		"rule github.com:GET,HEAD:/x/: path contains traversal or encoded separators": "outside its --rule (path)",
		"canary credential": "canary credential use",
	}
	for in, want := range cases {
		if got := RefusalClass(in); got != want {
			t.Errorf("RefusalClass(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTimelineBuckets(t *testing.T) {
	evs := []events.Event{
		ev(0, "a", events.KindConnect, events.Allow, "h1", "", false),
		ev(30*60, "a", events.KindConnect, events.Deny, "h2", "", false), // 30 min later
	}
	s := Summarise(evs)
	// A 30-minute window gets minute buckets.
	if s.BucketWidth != time.Minute || len(s.Timeline) != 31 {
		t.Fatalf("width %s, %d buckets; want 1m and 31", s.BucketWidth, len(s.Timeline))
	}
	if s.Timeline[0].Conns != 1 || s.Timeline[30].Conns != 1 || s.Timeline[30].Denied != 1 {
		t.Errorf("bucket contents wrong: %+v", s.Timeline[30])
	}
	if s.Timeline[15].Conns != 0 {
		t.Errorf("empty bucket should stay empty: %+v", s.Timeline[15])
	}
	// An eight-day window coalesces to fit one line.
	long := []events.Event{ev(0, "a", events.KindConnect, events.Allow, "h", "", false),
		ev(8*24*3600, "a", events.KindConnect, events.Allow, "h", "", false)}
	s = Summarise(long)
	if len(s.Timeline) > 76 {
		t.Errorf("%d buckets do not fit a line", len(s.Timeline))
	}
	if len(s.Timeline) != int(s.Last.Sub(s.Timeline[0].Start)/s.BucketWidth)+1 {
		t.Errorf("timeline does not cover the window")
	}
}

func TestTopHosts(t *testing.T) {
	evs := append(sample(),
		events.Event{Time: t0.Add(7 * time.Second), Agent: "a2", Kind: events.KindClose, Host: "api.anthropic.com", Sent: 5000},
		events.Event{Time: t0.Add(8 * time.Second), Agent: "a2", Kind: events.KindClose, Host: "quiet.example", Sent: 9000},
	)
	s := Summarise(evs)
	if len(s.TopHosts) == 0 || s.TopHosts[0].Host != "quiet.example" || s.TopHosts[0].Sent != 9000 {
		t.Errorf("top host by sent: %+v", s.TopHosts)
	}
	// The refused shortener must surface as most-refused despite no bytes.
	found := false
	for _, h := range s.TopDenied {
		if h.Host == "is.gd" && h.Denied == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("is.gd missing from most-refused: %+v", s.TopDenied)
	}
}

func TestHighCanaryCountsAgents(t *testing.T) {
	evs := []events.Event{
		{Time: t0, Agent: "a1", Kind: events.KindCanary, Decision: events.Deny, Host: "x.invalid", Canary: "generic-api", Confidence: "high"},
		{Time: t0.Add(time.Second), Agent: "a1", Kind: events.KindCanary, Decision: events.Deny, Host: "y.invalid", Canary: "generic-api", Confidence: "high"},
	}
	if s := Summarise(evs); s.HighCanaries != 1 {
		t.Errorf("HighCanaries %d, want 1 (one agent, two trips)", s.HighCanaries)
	}
}

func TestSummaryShowsNewSections(t *testing.T) {
	// A window long enough to bucket: ACTIVITY is skipped for single-bucket
	// windows, where a strip would say nothing.
	evs := append(sample(),
		events.Event{Time: t0.Add(30 * time.Minute), Agent: "a3", Kind: events.KindConnect, Decision: events.Deny,
			Host: "169.254.169.254", Port: "443",
			Reason: "resolved to non-public address 169.254.169.254; refusing"},
	)
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}}
	c.SetEvents(evs)
	if err := c.Run(context.Background(), "summary"); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"ACTIVITY", "conns", "refused", "TOP DESTINATIONS", "buckets of", "cloud metadata endpoint"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("summary lacks %q", w)
		}
	}
}

// DNS events make their own host:port rows and count as refusals when
// denied, so a host that was only ever looked up is still visible in hosts
// and charged to the agent that looked it up.
func TestHostsAndAgentsCountDns(t *testing.T) {
	dns := func(sec int, agent, decision, host string) events.Event {
		e := ev(sec, agent, events.KindDns, decision, host, "", false)
		e.Port = "53"
		return e
	}
	evs := []events.Event{
		dns(0, "a1", events.Deny, "blocked.test"),
		dns(1, "a1", events.Allow, "allowed.test"),
		dns(2, "a2", events.Deny, "blocked.test"),
	}
	var out bytes.Buffer
	c := &Console{Out: Printer{W: &out}}
	c.SetEvents(evs)
	if err := c.Run(context.Background(), "hosts"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "blocked.test:53") || !strings.Contains(out.String(), "allowed.test:53") {
		t.Fatalf("hosts lacks the dns rows:\n%s", out.String())
	}
	// Two agents were refused at blocked.test; allowed.test was only resolved.
	if !strings.Contains(out.String(), "a1,a2") {
		t.Fatalf("hosts does not attribute the refused lookups:\n%s", out.String())
	}
	var blocked *HostSummary
	for i := range Hosts(evs) {
		if Hosts(evs)[i].Host == "blocked.test" {
			blocked = &Hosts(evs)[i]
		}
	}
	if blocked == nil || blocked.Denied != 2 {
		t.Fatalf("blocked.test row wrong: %+v", blocked)
	}
	var out2 bytes.Buffer
	c2 := &Console{Out: Printer{W: &out2}}
	c2.SetEvents(evs)
	if err := c2.Run(context.Background(), "agents"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2.String(), "a1") {
		t.Fatalf("agents lacks a1:\n%s", out2.String())
	}
	byAgent := map[string]AgentSummary{}
	for _, a := range Agents(evs) {
		byAgent[a.Agent] = a
	}
	if byAgent["a1"].Denied != 1 || byAgent["a2"].Denied != 1 {
		t.Fatalf("agent denials = %d and %d, want 1 each", byAgent["a1"].Denied, byAgent["a2"].Denied)
	}
}
