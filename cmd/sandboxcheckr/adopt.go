package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/console"
	"github.com/danielcuthbert/sandboxcheckr/internal/events"
	"github.com/danielcuthbert/sandboxcheckr/internal/projconfig"
)

const adoptUsage = `sandboxcheckr adopt — turn what a run contacted into a policy file

USAGE
  sandboxcheckr adopt [--write] [--events file]

Reads this project's event log (the one "sandboxcheckr run" wrote), collects
the hosts the run was denied or only reached because of --observe, and prints
them as sandboxcheckr.toml lines: allow, allow-port, allow-private-host.
Canary trips and kill-switch refusals are never proposed. With an existing
policy file, only the lines missing from it are printed — the file is never
touched. --write regenerates the file from the union instead (your comments
in it are not preserved).

The usual loop:

  sandboxcheckr run --observe -- npm test   # permitted and logged
  sandboxcheckr adopt                       # review the proposal
  sandboxcheckr adopt --write               # write sandboxcheckr.toml
  sandboxcheckr run -- npm test             # locked to what you approved

A denied enforcing run feeds adopt just as well: the hosts it was refused are
exactly the ones the policy is missing.
`

// hostStat is one destination host, summarised for adoption.
type hostStat struct {
	host    string
	conns   int
	methods []string
	ports   map[string]bool
	private bool   // refused as a private address (needs allow-private-host)
	relay   string // store-or-forward class, when the proxy has one
	fetcher bool   // fetches any URL it is given
}

// proposal is the network policy adopt would add.
type proposal struct {
	hosts     []*hostStat
	ports     []string
	ruledN    int // refusals that need a --rule change, not an allow
	runs      int
	decisions int
}

// propose groups the log's candidate events into per-host stats. A host is a
// candidate when the run was denied reaching it for a reason an allow-list
// line can fix, or when --observe let it through (decision observe): those
// are the destinations a locked policy would need. Already-allowed traffic,
// canary trips, kill-switch cuts, metadata and --rule refusals are not
// adoptable.
func propose(evts []events.Event) *proposal {
	p := &proposal{}
	byHost := map[string]*hostStat{}
	portSet := map[string]bool{}
	seenRuns := map[string]bool{}
	for _, e := range evts {
		if e.Kind != events.KindConnect && e.Kind != events.KindRequest {
			continue
		}
		if e.Host == "" {
			continue
		}
		if e.RunID != "" {
			seenRuns[e.RunID] = true
		}
		p.decisions++
		class := console.RefusalClass(e.Reason)
		candidate := false
		switch e.Decision {
		case events.Observe:
			candidate = true
		case events.Deny:
			switch class {
			case "not on the allow-list", "private address", "port not permitted":
				candidate = true
			case "outside its --rule (method)", "outside its --rule (path)":
				p.ruledN++
			}
		}
		if !candidate {
			continue
		}
		host := strings.ToLower(e.Host)
		h := byHost[host]
		if h == nil {
			h = &hostStat{host: host, ports: map[string]bool{}}
			byHost[host] = h
		}
		h.conns++
		if e.Method != "" {
			h.methods = append(h.methods, strings.ToUpper(e.Method))
		}
		if e.Port != "" && e.Port != "443" && e.Port != "80" {
			h.ports[e.Port] = true
			portSet[e.Port] = true
		}
		if class == "private address" {
			h.private = true
		}
		if h.relay == "" {
			h.relay = e.Relay
		}
		if e.Fetcher {
			h.fetcher = true
		}
	}
	p.runs = len(seenRuns)
	for _, h := range byHost {
		p.hosts = append(p.hosts, h)
	}
	sort.Slice(p.hosts, func(i, j int) bool { return p.hosts[i].host < p.hosts[j].host })
	p.ports = sortedKeys(portSet)
	for _, h := range p.hosts {
		h.methods = unique(h.methods)
	}
	return p
}

// deltaAgainst subtracts what the existing policy file already permits. A
// private host must both resolve (allow-private-host) and be allowed, so a
// new private host lands in both lists.
func (p *proposal) deltaAgainst(cfg *projconfig.Config) (allows, privs, ports []string) {
	in := func(list []string, s string) bool {
		for _, x := range list {
			if strings.EqualFold(x, s) {
				return true
			}
		}
		return false
	}
	for _, h := range p.hosts {
		if !in(cfg.Allows, h.host) {
			allows = append(allows, h.host)
		}
		if h.private && !in(cfg.PrivHosts, h.host) {
			privs = append(privs, h.host)
		}
	}
	for _, port := range p.ports {
		if !in(cfg.Ports, port) {
			ports = append(ports, port)
		}
	}
	return allows, privs, ports
}

// renderDelta emits the policy lines the project is missing, with a legend
// explaining where each host came from, so the proposal is reviewable before
// anything is written anywhere.
func (p *proposal) renderDelta(allows, privs, ports []string) string {
	var b strings.Builder
	if len(allows) > 0 {
		fmt.Fprintf(&b, "allow = [%s]\n", quoteList(allows))
	}
	if len(privs) > 0 {
		fmt.Fprintf(&b, "allow-private-host = [%s]\n", quoteList(privs))
	}
	if len(ports) > 0 {
		fmt.Fprintf(&b, "allow-port = [%s]\n", strings.Join(ports, ", "))
	}
	b.WriteString("\n")
	b.WriteString(p.legend())
	return strings.TrimRight(b.String(), "\n")
}

// legend is one comment line per candidate host: what the run saw there.
func (p *proposal) legend() string {
	var b strings.Builder
	for _, h := range p.hosts {
		detail := []string{fmt.Sprintf("%d conns", h.conns)}
		if len(h.methods) > 0 {
			detail = append(detail, strings.Join(h.methods, ","))
		}
		if ps := sortedKeys(h.ports); len(ps) > 0 {
			detail = append(detail, "port "+strings.Join(ps, ","))
		}
		if h.private {
			detail = append(detail, "private address")
		}
		if h.relay != "" {
			detail = append(detail, h.relay)
		}
		if h.fetcher {
			detail = append(detail, "fetches any URL")
		}
		fmt.Fprintf(&b, "# %-40s %s\n", h.host, strings.Join(detail, "  "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// unionInto folds the adopt deltas into cfg (nil means a fresh project), so
// --write regenerates a complete policy instead of one that silently drops
// the keys the project already had.
func unionInto(cfg *projconfig.Config, allows, privs, ports []string) *projconfig.Config {
	c := &projconfig.Config{}
	if cfg != nil {
		*c = *cfg
	}
	c.Allows = sortedUnique(append(c.Allows, allows...))
	c.PrivHosts = sortedUnique(append(c.PrivHosts, privs...))
	c.Ports = sortedUnique(append(c.Ports, ports...))
	return c
}

// renderConfig emits every key of a policy, in schema order, with the legend
// underneath. Used by --write; the parser reads back exactly what this emits.
func renderConfig(c *projconfig.Config, legend string) string {
	var b strings.Builder
	if len(c.Allows) > 0 {
		fmt.Fprintf(&b, "allow = [%s]\n", quoteList(c.Allows))
	}
	if len(c.Rules) > 0 {
		fmt.Fprintf(&b, "rule = [%s]\n", quoteList(c.Rules))
	}
	if len(c.PrivHosts) > 0 {
		fmt.Fprintf(&b, "allow-private-host = [%s]\n", quoteList(c.PrivHosts))
	}
	if len(c.Ports) > 0 {
		fmt.Fprintf(&b, "allow-port = [%s]\n", strings.Join(c.Ports, ", "))
	}
	if len(c.PassEnv) > 0 {
		fmt.Fprintf(&b, "pass-env = [%s]\n", quoteList(c.PassEnv))
	}
	if len(c.RO) > 0 {
		fmt.Fprintf(&b, "ro = [%s]\n", quoteList(c.RO))
	}
	if len(c.RW) > 0 {
		fmt.Fprintf(&b, "rw = [%s]\n", quoteList(c.RW))
	}
	if c.Events != "" {
		fmt.Fprintf(&b, "events = %q\n", c.Events)
	}
	if c.Agent != "" {
		fmt.Fprintf(&b, "agent = %q\n", c.Agent)
	}
	if c.DenyFile != "" {
		fmt.Fprintf(&b, "deny-file = %q\n", c.DenyFile)
	}
	if c.Observe {
		b.WriteString("observe = true\n")
	}
	if c.NoCanary {
		b.WriteString("no-canary = true\n")
	}
	if c.CanaryKill {
		b.WriteString("canary-kill = true\n")
	}
	if c.NoAgentAuth {
		b.WriteString("no-agent-auth = true\n")
	}
	if legend != "" {
		b.WriteString("\n")
		b.WriteString(legend)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func quoteList(xs []string) string {
	quoted := make([]string, len(xs))
	for i, x := range xs {
		quoted[i] = "\"" + x + "\""
	}
	return strings.Join(quoted, ", ")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedUnique(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func runAdopt(args []string) int {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), adoptUsage); fs.PrintDefaults() }
	eventsFlag := fs.String("events", "", "event log `file` to read (default: this project's log, else the shared log)")
	write := fs.Bool("write", false, "write or regenerate sandboxcheckr.toml instead of printing")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "adopt takes no arguments")
		return 2
	}
	project, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if project, err = filepath.EvalSymlinks(project); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logPath := *eventsFlag
	if logPath == "" {
		logPath = consoleEventsPath()
	}
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no event log at %s yet. Run the command once with: sandboxcheckr run --observe -- <command>\n", logPath)
		return 1
	}
	evts, skipped := events.Read(f)
	_ = f.Close()
	p := propose(evts)
	if p.decisions == 0 {
		fmt.Fprintf(os.Stderr, "no connection decisions in %s%s. Run the command first with: sandboxcheckr run --observe -- <command>\n", logPath, skippedNote(skipped))
		return 1
	}
	target := filepath.Join(project, projconfig.Name)
	cfg, err := projconfig.Load(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var allows, privs, ports []string
	if cfg == nil {
		for _, h := range p.hosts {
			allows = append(allows, h.host)
			if h.private {
				privs = append(privs, h.host)
			}
		}
		ports = p.ports
	} else {
		allows, privs, ports = p.deltaAgainst(cfg)
	}
	if len(allows) == 0 && len(privs) == 0 && len(ports) == 0 {
		if p.ruledN > 0 {
			fmt.Fprintf(os.Stderr, "every host is already allowed, but %d refusal(s) need a --rule change; see: sandboxcheckr console denied\n", p.ruledN)
		} else {
			fmt.Fprintf(os.Stderr, "nothing to adopt: the policy in %s already covers every host the log knows\n", target)
		}
		return 0
	}
	if *write {
		full := unionInto(cfg, allows, privs, ports)
		out := renderConfig(full, p.legend())
		source := "from this project's event log"
		if p.runs > 0 {
			source = fmt.Sprintf("from %d run(s) in this project", p.runs)
		}
		header := fmt.Sprintf("# sandboxcheckr.toml — generated by sandboxcheckr adopt %s.\n", source)
		if cfg != nil {
			header = fmt.Sprintf("# sandboxcheckr.toml — regenerated by sandboxcheckr adopt %s.\n# Comments you had written in the previous file are not preserved.\n", source)
		}
		if err := os.WriteFile(target, []byte(header+out+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "writing policy:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "sandboxcheckr: wrote %s (review it before the next run)\n", target)
		return 0
	}
	fmt.Printf("# proposed for %s — paste in, or write with: sandboxcheckr adopt --write\n%s\n", target, p.renderDelta(allows, privs, ports))
	if p.ruledN > 0 {
		fmt.Fprintf(os.Stderr, "note: %d refusal(s) need a --rule change, which adopt does not guess; see: sandboxcheckr console denied\n", p.ruledN)
	}
	return 0
}

func skippedNote(skipped int) string {
	if skipped == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d unparseable lines skipped)", skipped)
}
