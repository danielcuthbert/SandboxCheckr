package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
	"github.com/danielcuthbert/sandboxcheckr/internal/projconfig"
)

func adoptEvt(kind, decision, host, port, method, reason, relay string, fetcher bool) events.Event {
	at, _ := time.Parse(time.RFC3339, "2026-11-14T08:00:00Z")
	return events.Event{
		Time: at, Kind: kind, Decision: decision, Host: host, Port: port,
		Method: method, Reason: reason, Relay: relay, Fetcher: fetcher,
		RunID: "run-1",
	}
}

func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	code := fn()
	os.Stdout = saved
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()
	return string(out), code
}

func TestProposeFiltersAndGroups(t *testing.T) {
	evts := []events.Event{
		adoptEvt(events.KindConnect, events.Observe, "Registry.NPMJS.org", "443", "GET", "", "store/forward: package registry", false),
		adoptEvt(events.KindConnect, events.Observe, "registry.npmjs.org", "443", "get", "", "", false),
		adoptEvt(events.KindConnect, events.Deny, "internal.corp", "443", "", "resolved to non-public address 10.0.0.1; refusing (use --allow-private-host internal.corp to permit this host only)", "", false),
		adoptEvt(events.KindConnect, events.Deny, "api.local", "8000", "", "port not permitted; use --allow-port", "", false),
		adoptEvt(events.KindConnect, events.Deny, "sc-hidden.invalid", "443", "", "canary credential use attempted", "", false),
		adoptEvt(events.KindConnect, events.Deny, "denylisted.example", "443", "", "in deny file (denylisted.example)", "", false),
		adoptEvt(events.KindConnect, events.Deny, "metadata.example", "80", "", "resolved to non-public address 169.254.169.254; refusing", "", false),
		adoptEvt(events.KindRequest, events.Deny, "github.com", "443", "PUT", "rule github.com:GET,HEAD:/x/: method PUT not permitted (allowed: GET,HEAD)", "", false),
		adoptEvt(events.KindConnect, events.Allow, "already.allowed.example", "443", "", "", "", false),
		adoptEvt(events.KindClose, events.Allow, "telemetry.example", "443", "", "", "", false),
		adoptEvt(events.KindConnect, events.Observe, "", "443", "", "", "", false),
		adoptEvt(events.KindConnect, events.Observe, "shortener.example", "443", "GET", "", "", true),
	}
	p := propose(evts)
	if p.decisions != 10 {
		t.Fatalf("decisions: %d, want 10", p.decisions)
	}
	if p.runs != 1 {
		t.Fatalf("runs: %d, want 1", p.runs)
	}
	if p.ruledN != 1 {
		t.Fatalf("rule refusals: %d, want 1", p.ruledN)
	}
	var hosts []string
	for _, h := range p.hosts {
		hosts = append(hosts, h.host)
	}
	want := []string{"api.local", "internal.corp", "registry.npmjs.org", "shortener.example"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") {
		t.Fatalf("hosts: %v, want %v", hosts, want)
	}
	npm := p.hosts[2]
	if npm.conns != 2 || strings.Join(npm.methods, ",") != "GET" {
		t.Fatalf("npm: conns=%d methods=%v", npm.conns, npm.methods)
	}
	if npm.relay != "store/forward: package registry" {
		t.Fatalf("npm relay: %q", npm.relay)
	}
	if !p.hosts[1].private {
		t.Fatal("internal.corp must be marked private")
	}
	if !p.hosts[0].ports["8000"] {
		t.Fatalf("api.local ports: %v", p.hosts[0].ports)
	}
	if !p.hosts[3].fetcher {
		t.Fatal("shortener.example must be marked fetcher")
	}
	for _, port := range p.ports {
		if port == "443" || port == "80" {
			t.Fatalf("standard port %s must not be proposed", port)
		}
	}
}

func TestDeltaAgainstExistingPolicy(t *testing.T) {
	p := &proposal{hosts: []*hostStat{
		{host: "a.example", ports: map[string]bool{}},
		{host: "b.example", ports: map[string]bool{}},
		{host: "c.local", private: true, ports: map[string]bool{}},
	}, ports: []string{"8000", "9000"}}
	cfg := &projconfig.Config{Allows: []string{"a.example"}, PrivHosts: []string{"a.example"}, Ports: []string{"8000"}}
	allows, privs, ports := p.deltaAgainst(cfg)
	if strings.Join(allows, ",") != "b.example,c.local" {
		t.Fatalf("allows: %v", allows)
	}
	if strings.Join(privs, ",") != "c.local" {
		t.Fatalf("privs: %v", privs)
	}
	if strings.Join(ports, ",") != "9000" {
		t.Fatalf("ports: %v", ports)
	}
}

func TestRenderConfigRoundTrip(t *testing.T) {
	in := &projconfig.Config{
		Allows:      []string{"a.example", "b.example"},
		Rules:       []string{"b.example:GET,HEAD:/pkg/"},
		PrivHosts:   []string{"c.local"},
		Ports:       []string{"8000"},
		PassEnv:     []string{"API_KEY"},
		RO:          []string{"/home/me/tools"},
		RW:          []string{"/home/me/notes"},
		Events:      "/tmp/events.jsonl",
		Agent:       "npm",
		DenyFile:    "/home/me/deny.txt",
		Observe:     true,
		NoCanary:    true,
		CanaryKill:  true,
		NoAgentAuth: true,
	}
	out := renderConfig(in, "")
	tmp := filepath.Join(t.TempDir(), projconfig.Name)
	if err := os.WriteFile(tmp, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := projconfig.Load(tmp)
	if err != nil {
		t.Fatalf("adopt output does not parse: %v\n%s", err, out)
	}
	if strings.Join(cfg.Allows, ",") != strings.Join(in.Allows, ",") ||
		strings.Join(cfg.Rules, ",") != strings.Join(in.Rules, ",") ||
		strings.Join(cfg.PrivHosts, ",") != strings.Join(in.PrivHosts, ",") ||
		strings.Join(cfg.Ports, ",") != strings.Join(in.Ports, ",") ||
		strings.Join(cfg.PassEnv, ",") != strings.Join(in.PassEnv, ",") ||
		strings.Join(cfg.RO, ",") != strings.Join(in.RO, ",") ||
		strings.Join(cfg.RW, ",") != strings.Join(in.RW, ",") ||
		cfg.Events != in.Events || cfg.Agent != in.Agent || cfg.DenyFile != in.DenyFile ||
		cfg.Observe != in.Observe || cfg.NoCanary != in.NoCanary ||
		cfg.CanaryKill != in.CanaryKill || cfg.NoAgentAuth != in.NoAgentAuth {
		t.Fatalf("round trip mismatch:\nin:  %+v\nout: %+v\n%s", in, cfg, out)
	}
}

func TestRunAdoptEndToEnd(t *testing.T) {
	state := t.TempDir()
	project := t.TempDir()
	t.Chdir(project)
	t.Setenv("XDG_STATE_HOME", state)
	logPath := projectEventsPath(project)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"t":"2026-11-14T08:00:00Z","kind":"connect","decision":"observe","host":"Registry.NPMJS.org","port":"443","method":"GET","relay":"store/forward: package registry","run_id":"r1"}`,
		`{"t":"2026-11-14T08:00:01Z","kind":"connect","decision":"deny","host":"api.local","port":"8000","reason":"port not permitted; use --allow-port","run_id":"r1"}`,
		`{"t":"2026-11-14T08:00:02Z","kind":"connect","decision":"deny","host":"sc-canary.invalid","reason":"canary credential use attempted","run_id":"r1"}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// First adopt: prints the proposal, writes nothing.
	out, code := captureStdout(t, func() int { return runAdopt([]string{}) })
	if code != 0 {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	for _, want := range []string{`allow = ["api.local", "registry.npmjs.org"]`, `allow-port = [8000]`} {
		if !strings.Contains(out, want) {
			t.Fatalf("proposal missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sc-canary.invalid") {
		t.Fatal("canary host must never be proposed")
	}
	if _, err := os.Stat(filepath.Join(project, projconfig.Name)); !os.IsNotExist(err) {
		t.Fatal("adopt without --write must not create the file")
	}
	// --write: file appears and the parser reads it back.
	if code := runAdopt([]string{"--write"}); code != 0 {
		t.Fatalf("adopt --write exit %d", code)
	}
	cfg, err := projconfig.Load(filepath.Join(project, projconfig.Name))
	if err != nil {
		t.Fatalf("written policy does not parse: %v", err)
	}
	if strings.Join(cfg.Allows, ",") != "api.local,registry.npmjs.org" || strings.Join(cfg.Ports, ",") != "8000" {
		t.Fatalf("written policy: %+v", cfg)
	}
	// Adopting again: everything already covered.
	out2, code := captureStdout(t, func() int { return runAdopt([]string{}) })
	if code != 0 {
		t.Fatalf("second adopt exit %d:\n%s", code, out2)
	}
}
