// Package console answers questions about the proxy's event log: which agents
// ran, where each one went, what it tried after it was refused, and which
// relays several agents used — the view the 2026 swarm investigations had to
// reconstruct from other people's logs, here from your own.
//
// It is a plain line-oriented console: commands in, tables out. No cursor
// addressing, no third-party terminal library, so it works the same in a
// terminal, over ssh, piped into grep, or in a CI log.
package console

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// Filter selects events. Zero value selects everything.
type Filter struct {
	Agent    string // exact, or prefix with a trailing '*'
	Host     string // substring
	Decision string // allow, deny, observe
	Kind     string
	Relay    bool // only store-or-forward hosts
	Since    time.Time
}

// ParseFilter reads "key=value" terms: agent=, host=, decision=, kind=,
// since= (a duration such as 10m, or an RFC 3339 time), and the bare word
// "relay". now anchors relative times.
func ParseFilter(terms []string, now time.Time) (Filter, error) {
	var f Filter
	for _, t := range terms {
		if t == "relay" || t == "relays" {
			f.Relay = true
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || v == "" {
			return f, fmt.Errorf("filter %q: want key=value (agent=, host=, decision=, kind=, since=) or relay", t)
		}
		switch strings.ToLower(k) {
		case "agent":
			f.Agent = v
		case "host":
			f.Host = strings.ToLower(v)
		case "decision":
			v = strings.ToLower(v)
			if v == "denied" {
				v = events.Deny
			}
			if v != events.Allow && v != events.Deny && v != events.Observe {
				return f, fmt.Errorf("decision=%s: want allow, deny or observe", v)
			}
			f.Decision = v
		case "kind":
			f.Kind = strings.ToLower(v)
		case "since":
			if d, err := time.ParseDuration(v); err == nil {
				f.Since = now.Add(-d)
			} else if ts, err := time.Parse(time.RFC3339, v); err == nil {
				f.Since = ts
			} else {
				return f, fmt.Errorf("since=%s: want a duration (15m, 2h) or an RFC 3339 time", v)
			}
		default:
			return f, fmt.Errorf("unknown filter %q", k)
		}
	}
	return f, nil
}

// Match reports whether e passes f.
func (f Filter) Match(e events.Event) bool {
	if f.Agent != "" {
		if p, ok := strings.CutSuffix(f.Agent, "*"); ok {
			if !strings.HasPrefix(e.Agent, p) {
				return false
			}
		} else if e.Agent != f.Agent {
			return false
		}
	}
	if f.Host != "" && !strings.Contains(strings.ToLower(e.Host), f.Host) {
		return false
	}
	if f.Decision != "" && e.Decision != f.Decision {
		return false
	}
	if f.Kind != "" && e.Kind != f.Kind {
		return false
	}
	if f.Relay && e.Relay == "" {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	return true
}

// Select returns the events that pass f, in order.
func Select(evs []events.Event, f Filter) []events.Event {
	var out []events.Event
	for _, e := range evs {
		if f.Match(e) {
			out = append(out, e)
		}
	}
	return out
}

// AgentSummary is one agent's activity.
type AgentSummary struct {
	Agent              string
	First, Last        time.Time
	Connects, Denied   int
	Hosts              int
	Relays, RelayDeny  int
	GetRelays          int
	GetRelaysReached   int // GET relays the agent actually got through to
	Uploads            int // hosts that passed the heavy-upload threshold
	Canaries           int
	Writes             int
	Sent               int64
	RetriedAfterDenial bool
}

// Agents summarises activity per agent, busiest first.
func Agents(evs []events.Event) []AgentSummary {
	by := map[string]*AgentSummary{}
	hosts := map[string]map[string]bool{}
	relays := map[string]map[string]bool{}
	deniedRelay := map[string]bool{}
	reached := map[string]map[string]bool{}
	for _, e := range evs {
		a := by[e.Agent]
		if a == nil {
			a = &AgentSummary{Agent: e.Agent, First: e.Time}
			by[e.Agent] = a
			hosts[e.Agent] = map[string]bool{}
			relays[e.Agent] = map[string]bool{}
		}
		if e.Time.Before(a.First) {
			a.First = e.Time
		}
		if e.Time.After(a.Last) {
			a.Last = e.Time
		}
		switch e.Kind {
		case events.KindConnect:
			a.Connects++
			hosts[e.Agent][e.Host] = true
			if e.Decision == events.Deny {
				a.Denied++
			}
			if e.Relay != "" {
				if !relays[e.Agent][e.Host] {
					relays[e.Agent][e.Host] = true
					a.Relays++
					if e.Fetcher {
						a.GetRelays++
					}
				}
				if e.Fetcher && e.Decision != events.Deny && !reached[e.Agent][e.Host] {
					if reached[e.Agent] == nil {
						reached[e.Agent] = map[string]bool{}
					}
					reached[e.Agent][e.Host] = true
					a.GetRelaysReached++
				}
				if e.Decision == events.Deny {
					a.RelayDeny++
					deniedRelay[e.Agent] = true
				} else if deniedRelay[e.Agent] {
					// Refused at one relay, then reached another: probing.
					a.RetriedAfterDenial = true
				}
			}
		case events.KindRequest:
			if e.Decision == events.Deny {
				a.Denied++
			}
		case events.KindDns:
			if e.Decision == events.Deny {
				a.Denied++
			}
			hosts[e.Agent][e.Host] = true
		case events.KindWrite:
			a.Writes++
		case events.KindUpload:
			a.Uploads++
		case events.KindClose:
			a.Sent += e.Sent
		case events.KindCanary:
			a.Canaries++
		}
	}
	out := make([]AgentSummary, 0, len(by))
	for k, a := range by {
		a.Hosts = len(hosts[k])
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Relays != out[j].Relays {
			return out[i].Relays > out[j].Relays
		}
		if out[i].Connects != out[j].Connects {
			return out[i].Connects > out[j].Connects
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

// HostSummary is activity towards one host.
type HostSummary struct {
	Host, Port       string
	Relay            string
	Fetcher          bool
	ModelAPI         bool
	Connects, Denied int
	Agents           []string
	Sent, Recv       int64
}

// Hosts summarises activity per host:port, most-contacted first.
func Hosts(evs []events.Event) []HostSummary {
	by := map[string]*HostSummary{}
	agents := map[string]map[string]bool{}
	for _, e := range evs {
		k := e.Host + ":" + e.Port
		h := by[k]
		if h == nil {
			h = &HostSummary{Host: e.Host, Port: e.Port, Relay: e.Relay, Fetcher: e.Fetcher, ModelAPI: e.ModelAPI}
			by[k] = h
			agents[k] = map[string]bool{}
		}
		switch e.Kind {
		case events.KindConnect:
			h.Connects++
			if e.Decision == events.Deny {
				h.Denied++
			}
			agents[k][e.Agent] = true
		case events.KindRequest:
			if e.Decision == events.Deny {
				h.Denied++
			}
		case events.KindDns:
			if e.Decision == events.Deny {
				h.Denied++
			}
			agents[k][e.Agent] = true
		case events.KindClose:
			h.Sent += e.Sent
			h.Recv += e.Recv
		}
	}
	out := make([]HostSummary, 0, len(by))
	for k, h := range by {
		for a := range agents[k] {
			h.Agents = append(h.Agents, a)
		}
		sort.Strings(h.Agents)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connects != out[j].Connects {
			return out[i].Connects > out[j].Connects
		}
		return out[i].Host+out[i].Port < out[j].Host+out[j].Port
	})
	return out
}

// Shared returns hosts contacted by more than one agent. A relay several
// agents reach is a candidate message board between them (SWM-007).
func Shared(evs []events.Event) []HostSummary {
	var out []HostSummary
	for _, h := range Hosts(evs) {
		if len(h.Agents) > 1 {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Relay != "") != (out[j].Relay != "") {
			return out[i].Relay != ""
		}
		return len(out[i].Agents) > len(out[j].Agents)
	})
	return out
}

// Printer renders console output. Every string from an event passes through
// events.Clean before it is written.
type Printer struct {
	W     io.Writer
	Color bool
	Width int
	ASCII bool
}

func (p Printer) c(code, s string) string {
	if !p.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Printer) width() int {
	if p.Width < 60 {
		return 100
	}
	return p.Width
}

func clean(s string, n int) string { return events.Clean(s, n) }

func hostPort(host, port string) string {
	if port == "" || port == "443" {
		return host
	}
	return host + ":" + port
}

// PrintAgents writes the agent table.
func (p Printer) PrintAgents(rows []AgentSummary) {
	if len(rows) == 0 {
		fmt.Fprintln(p.W, "no agents in the log")
		return
	}
	fmt.Fprintf(p.W, "%-24s %-8s %-8s %6s %6s %6s %7s %6s %9s  %s\n",
		"agent", "first", "last", "conns", "denied", "hosts", "relays", "writes", "sent", "signals")
	for _, a := range rows {
		var sig []string
		if a.GetRelays > 0 {
			sig = append(sig, p.c("31", fmt.Sprintf("%d GET-relay", a.GetRelays)))
		}
		if a.RelayDeny > 0 {
			sig = append(sig, p.c("33", fmt.Sprintf("%d relay refusals", a.RelayDeny)))
		}
		if a.RetriedAfterDenial {
			sig = append(sig, p.c("31;1", "tried another relay after refusal"))
		}
		if a.Writes > 0 {
			sig = append(sig, fmt.Sprintf("sent data to %d hosts", a.Writes))
		}
		if a.Canaries > 0 {
			sig = append(sig, p.c("31;1", fmt.Sprintf("%d CANARY TRIPPED", a.Canaries)))
		}
		fmt.Fprintf(p.W, "%-24s %-8s %-8s %6d %6d %6d %7d %6d %9s  %s\n",
			clean(a.Agent, 24), a.First.Local().Format("15:04:05"), a.Last.Local().Format("15:04:05"),
			a.Connects, a.Denied, a.Hosts, a.Relays, a.Writes, humanBytes(a.Sent), strings.Join(sig, ", "))
	}
}

// PrintHosts writes the host table.
func (p Printer) PrintHosts(rows []HostSummary) {
	if len(rows) == 0 {
		fmt.Fprintln(p.W, "no hosts match")
		return
	}
	hw := len("host")
	for _, h := range rows {
		hw = max(hw, min(48, len(hostPort(h.Host, h.Port))))
	}
	fmt.Fprintf(p.W, "%-*s %6s %6s %9s %9s  %-20s %s\n", hw, "host", "conns", "denied", "sent", "recv", "agents", "class")
	for _, h := range rows {
		class := h.Relay
		if h.Fetcher {
			class = p.c("31", "! "+class)
		} else if class != "" {
			class = p.c("33", class)
		}
		if h.ModelAPI {
			class = strings.TrimSpace(class + " model API")
		}
		ag := strings.Join(h.Agents, ",")
		if len(h.Agents) > 2 {
			ag = fmt.Sprintf("%s +%d", h.Agents[0], len(h.Agents)-1)
		}
		fmt.Fprintf(p.W, "%-*s %6d %6d %9s %9s  %-20s %s\n", hw, clean(hostPort(h.Host, h.Port), 48),
			h.Connects, h.Denied, humanBytes(h.Sent), humanBytes(h.Recv), clean(ag, 20), class)
	}
}

// PrintEvents writes events one per line, oldest first.
func (p Printer) PrintEvents(evs []events.Event, showAgent bool) {
	if len(evs) == 0 {
		fmt.Fprintln(p.W, "no events match")
		return
	}
	for _, e := range evs {
		p.PrintEvent(e, showAgent)
	}
}

// PrintEvent writes one event line.
func (p Printer) PrintEvent(e events.Event, showAgent bool) {
	var b strings.Builder
	b.WriteString(e.Time.Local().Format("15:04:05") + " ")
	if showAgent {
		fmt.Fprintf(&b, "%-16s ", clean(e.Agent, 16))
	}
	verb := strings.ToUpper(e.Decision)
	switch e.Kind {
	case events.KindWrite:
		verb = "WRITE"
	case events.KindUpload:
		verb = "UPLOAD"
	case events.KindClose:
		verb = "bytes"
	case events.KindCanary:
		verb = "CANARY"
	}
	switch verb {
	case "DENY", "UPLOAD", "CANARY":
		verb = p.c("31", fmt.Sprintf("%-7s", verb))
	case "OBSERVE", "WRITE":
		verb = p.c("33", fmt.Sprintf("%-7s", verb))
	default:
		verb = fmt.Sprintf("%-7s", verb)
	}
	b.WriteString(verb + " ")
	target := hostPort(e.Host, e.Port)
	if e.Method != "" {
		target = e.Method + " " + hostPort(e.Host, e.Port) + e.Path
	}
	rest := p.width() - 40
	b.WriteString(clean(target, max(rest, 30)))
	switch e.Kind {
	case events.KindClose:
		fmt.Fprintf(&b, "  ↑%s ↓%s", humanBytes(e.Sent), humanBytes(e.Recv))
	case events.KindUpload:
		fmt.Fprintf(&b, "  %s sent in total", humanBytes(e.Sent))
	case events.KindCanary:
		fmt.Fprintf(&b, "  %s %s (run %s)", clean(e.Confidence, 12), clean(e.Canary, 40), clean(e.RunID, 32))
	}
	if e.Relay != "" && e.Kind == events.KindConnect {
		tag := "[" + e.Relay + "]"
		if e.Fetcher {
			tag = p.c("31", "[! "+e.Relay+"]")
		}
		b.WriteString("  " + tag)
	}
	if e.Reason != "" && e.Decision == events.Deny {
		b.WriteString("  (" + clean(e.Reason, 80) + ")")
	}
	fmt.Fprintln(p.W, b.String())
}

func humanBytes(n int64) string {
	switch {
	case n == 0:
		return "-"
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
}
