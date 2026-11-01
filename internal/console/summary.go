package console

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// Verdicts, worst first. An agent gets the worst one that applies.
const (
	VerdictCanary  = "CANARY TRIPPED"
	VerdictUpload  = "UPLOADING"
	VerdictReached = "RELAY REACHED"
	VerdictProbing = "PROBING"
	VerdictWrote   = "SENT DATA"
	VerdictQuiet   = "quiet"
)

var verdictRank = map[string]int{VerdictCanary: 0, VerdictUpload: 1, VerdictReached: 2, VerdictProbing: 3, VerdictWrote: 4, VerdictQuiet: 5}

// Verdict is the one-word state of an agent: the worst thing it did.
func Verdict(a AgentSummary) string {
	switch {
	case a.Canaries > 0:
		return VerdictCanary
	case a.Uploads > 0:
		return VerdictUpload
	case a.GetRelaysReached > 0:
		return VerdictReached
	case a.RetriedAfterDenial || a.RelayDeny >= 2:
		return VerdictProbing
	case a.Writes > 0:
		return VerdictWrote
	default:
		return VerdictQuiet
	}
}

// RelayClass is relay activity grouped by kind of service.
type RelayClass struct {
	Class            string
	OnGet            bool
	Hosts            int
	Attempts, Denied int
	Agents           int
}

// Finding is one thing worth a look, with the command that shows it.
type Finding struct {
	Severity int // 0 highest
	Text     string
	Command  string
}

// Summary is the state of the nation for a set of events.
type Summary struct {
	First, Last      time.Time
	Events           int
	Agents           []AgentSummary
	Connects, Denied int
	Hosts            int
	RelayAttempts    int
	RelayDenied      int
	Sent             int64
	Relays           []RelayClass
	Findings         []Finding
	VerdictCounts    map[string]int
}

// relayClass reduces "fetcher (fetches any URL it is given)" to "fetcher".
func relayClass(kind string) string {
	if i := strings.Index(kind, " ("); i > 0 {
		return kind[:i]
	}
	return kind
}

// Summarise builds the state of the nation.
func Summarise(evs []events.Event) Summary {
	s := Summary{Events: len(evs), VerdictCounts: map[string]int{}}
	if len(evs) == 0 {
		return s
	}
	s.First, s.Last = evs[0].Time, evs[0].Time
	hosts := map[string]bool{}
	type acc struct {
		RelayClass
		hosts, agents map[string]bool
	}
	classes := map[string]*acc{}
	for _, e := range evs {
		if e.Time.Before(s.First) {
			s.First = e.Time
		}
		if e.Time.After(s.Last) {
			s.Last = e.Time
		}
		switch e.Kind {
		case events.KindClose:
			s.Sent += e.Sent
		case events.KindConnect:
			s.Connects++
			hosts[e.Host] = true
			if e.Decision == events.Deny {
				s.Denied++
			}
			if e.Relay == "" {
				continue
			}
			s.RelayAttempts++
			if e.Decision == events.Deny {
				s.RelayDenied++
			}
			// Keyed on GET-relaying too, so a class name shared by a store and
			// a fetcher never merges the two.
			k := fmt.Sprintf("%s|%v", relayClass(e.Relay), e.Fetcher)
			c := classes[k]
			if c == nil {
				c = &acc{RelayClass: RelayClass{Class: relayClass(e.Relay), OnGet: e.Fetcher}, hosts: map[string]bool{}, agents: map[string]bool{}}
				classes[k] = c
			}
			c.Attempts++
			if e.Decision == events.Deny {
				c.Denied++
			}
			c.hosts[e.Host] = true
			c.agents[e.Agent] = true
		}
	}
	s.Hosts = len(hosts)
	for _, c := range classes {
		c.Hosts, c.Agents = len(c.hosts), len(c.agents)
		s.Relays = append(s.Relays, c.RelayClass)
	}
	sort.Slice(s.Relays, func(i, j int) bool {
		if s.Relays[i].OnGet != s.Relays[j].OnGet {
			return s.Relays[i].OnGet
		}
		if s.Relays[i].Attempts != s.Relays[j].Attempts {
			return s.Relays[i].Attempts > s.Relays[j].Attempts
		}
		return s.Relays[i].Class < s.Relays[j].Class
	})

	s.Agents = Agents(evs)
	sort.SliceStable(s.Agents, func(i, j int) bool {
		return verdictRank[Verdict(s.Agents[i])] < verdictRank[Verdict(s.Agents[j])]
	})
	for _, a := range s.Agents {
		s.VerdictCounts[Verdict(a)]++
	}
	s.Findings = findings(evs, s.Agents)
	return s
}

// findings picks out what a person should look at first.
func findings(evs []events.Event, agents []AgentSummary) []Finding {
	var out []Finding
	for _, e := range evs {
		if e.Kind == events.KindCanary {
			out = append(out, Finding{0, fmt.Sprintf("CANARY TRIPPED: %s used %s (%s) at %s", e.Agent, e.Canary, e.Confidence, e.Host),
				"canaries agent=" + e.Agent})
		}
	}
	// Uploads, with the host they went to.
	for _, e := range evs {
		if e.Kind == events.KindUpload {
			out = append(out, Finding{0, fmt.Sprintf("%s sent %s to %s%s", e.Agent, humanBytes(e.Sent), e.Host, relayNote(e)),
				"agent " + e.Agent})
		}
	}
	// GET relays reached: an allowed route onward. One finding per host,
	// naming every agent that used it.
	reachedBy := map[string][]string{}
	var reachedOrder []string
	kind := map[string]string{}
	for _, e := range evs {
		if e.Kind != events.KindConnect || !e.Fetcher || e.Decision == events.Deny {
			continue
		}
		if _, ok := reachedBy[e.Host]; !ok {
			reachedOrder = append(reachedOrder, e.Host)
			kind[e.Host] = relayClass(e.Relay)
		}
		if !contains(reachedBy[e.Host], e.Agent) {
			reachedBy[e.Host] = append(reachedBy[e.Host], e.Agent)
		}
	}
	for _, h := range reachedOrder {
		out = append(out, Finding{1, fmt.Sprintf("%s relays on a plain GET (%s) and is in the allow-list; reached by %s",
			h, kind[h], joinAgents(reachedBy[h])), "events host=" + h})
	}
	// Probing, most refusals first.
	probing := append([]AgentSummary(nil), agents...)
	sort.SliceStable(probing, func(i, j int) bool { return probing[i].RelayDeny > probing[j].RelayDeny })
	for _, a := range probing {
		if a.RetriedAfterDenial || a.RelayDeny >= 2 {
			out = append(out, Finding{2, fmt.Sprintf("%s was refused at %d relays and kept trying others", a.Agent, a.RelayDeny),
				"agent " + a.Agent})
		}
	}
	// Relays shared between agents: candidate boards. A GET relay already
	// reported above is not repeated.
	for _, h := range Shared(evs) {
		if _, done := reachedBy[h.Host]; done {
			continue
		}
		if h.Relay != "" {
			out = append(out, Finding{2, fmt.Sprintf("%s (%s) was used by %d agents — a possible board between them",
				h.Host, relayClass(h.Relay), len(h.Agents)), "events host=" + h.Host})
		}
	}
	// Rule refusals: a write or path the agent was told it could not do.
	n := map[string]int{}
	for _, e := range evs {
		if e.Kind == events.KindRequest && e.Decision == events.Deny {
			n[e.Agent]++
		}
	}
	for a, k := range n {
		out = append(out, Finding{3, fmt.Sprintf("%s had %s refused by a --rule (writes or paths it was not allowed)", a, plural(k, "request")),
			"denied agent=" + a + " kind=request"})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity < out[j].Severity })
	return out
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func joinAgents(as []string) string {
	if len(as) <= 3 {
		return strings.Join(as, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(as[:3], ", "), len(as)-3)
}

func relayNote(e events.Event) string {
	if e.Relay == "" {
		return ""
	}
	return " (" + relayClass(e.Relay) + ")"
}

func (p Printer) rule(title string) {
	r := "─"
	if p.ASCII {
		r = "-"
	}
	w := min(p.width(), 110)
	fmt.Fprintf(p.W, "\n%s %s %s\n\n", p.c("2", r+r), p.c("1", title), p.c("2", strings.Repeat(r, max(0, w-len(title)-4))))
}

func (p Printer) verdict(v string) string {
	switch v {
	case VerdictCanary, VerdictUpload, VerdictReached:
		return p.c("31;1", fmt.Sprintf("%-13s", v))
	case VerdictProbing, VerdictWrote:
		return p.c("33", fmt.Sprintf("%-13s", v))
	default:
		return p.c("32", fmt.Sprintf("%-13s", v))
	}
}

// PrintSummary writes the state of the nation.
func (p Printer) PrintSummary(s Summary) {
	if s.Events == 0 {
		fmt.Fprintln(p.W, "no events match")
		return
	}
	p.rule("STATE OF THE NATION")
	span := s.Last.Sub(s.First).Round(time.Second)
	fmt.Fprintf(p.W, "  window      %s → %s  (%s)\n", s.First.Local().Format("2006-01-02 15:04:05"), s.Last.Local().Format("15:04:05"), span)
	fmt.Fprintf(p.W, "  agents      %d", len(s.Agents))
	var vs []string
	for _, v := range []string{VerdictCanary, VerdictUpload, VerdictReached, VerdictProbing, VerdictWrote, VerdictQuiet} {
		if n := s.VerdictCounts[v]; n > 0 {
			vs = append(vs, strings.TrimSpace(p.verdict(v))+fmt.Sprintf(" %d", n))
		}
	}
	fmt.Fprintf(p.W, "   %s\n", strings.Join(vs, "  "))
	fmt.Fprintf(p.W, "  traffic     %d connections to %d hosts, %d refused · %s sent\n", s.Connects, s.Hosts, s.Denied, humanBytes(s.Sent))
	fmt.Fprintf(p.W, "  relays      %d attempts, %d refused, %d reached\n", s.RelayAttempts, s.RelayDenied, s.RelayAttempts-s.RelayDenied)

	p.rule("AGENTS")
	fmt.Fprintf(p.W, "  %-13s %-22s %6s %6s %7s %9s  %s\n", "state", "agent", "conns", "denied", "relays", "sent", "last seen")
	for _, a := range s.Agents {
		fmt.Fprintf(p.W, "  %s %-22s %6d %6d %7d %9s  %s\n", p.verdict(Verdict(a)), clean(a.Agent, 22),
			a.Connects, a.Denied, a.Relays, humanBytes(a.Sent), a.Last.Local().Format("15:04:05"))
	}

	if len(s.Relays) > 0 {
		p.rule("RELAY ACTIVITY")
		fmt.Fprintf(p.W, "  %-2s%-24s %6s %9s %8s %8s %7s\n", "", "class", "hosts", "attempts", "refused", "reached", "agents")
		for _, r := range s.Relays {
			mark := "  "
			if r.OnGet {
				mark = p.c("31", "! ")
			}
			reached := fmt.Sprintf("%8d", r.Attempts-r.Denied)
			if r.Attempts-r.Denied > 0 && r.OnGet {
				reached = p.c("31;1", reached)
			}
			fmt.Fprintf(p.W, "  %s%-24s %6d %9d %8d %s %7d\n", mark, clean(r.Class, 24), r.Hosts, r.Attempts, r.Denied, reached, r.Agents)
		}
		fmt.Fprintln(p.W, "  ! relays on a plain GET: no --rule contains it")
	}

	p.rule("WHAT TO LOOK AT")
	if len(s.Findings) == 0 {
		fmt.Fprintln(p.W, "  Nothing stood out: no relay attempts, uploads or rule refusals.")
	}
	const maxFindings = 8
	for i, f := range s.Findings {
		if i == maxFindings {
			fmt.Fprintf(p.W, "  … and %d more\n", len(s.Findings)-maxFindings)
			break
		}
		bullet := []string{p.c("31;1", "●"), p.c("31", "●"), p.c("33", "●"), p.c("2", "●")}[f.Severity]
		if p.ASCII {
			bullet = []string{"!!", "! ", "* ", "- "}[f.Severity]
		}
		fmt.Fprintf(p.W, "  %s %s\n", bullet, clean(f.Text, max(p.width()-6, 100)))
		fmt.Fprintf(p.W, "      %s\n", p.c("2", "→ "+f.Command))
	}
	fmt.Fprintln(p.W, p.c("2", "\n  Not visible here: what was sent inside HTTPS to hosts without a --rule, and relays the list does not name."))
}
