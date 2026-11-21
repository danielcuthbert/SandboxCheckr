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
	case a.RetriedAfterDenial || a.RelayDenyHosts >= 2:
		return VerdictProbing
	case a.Writes > 0:
		return VerdictWrote
	default:
		return VerdictQuiet
	}
}

// Finding is one thing worth a look, with the command that shows it.
type Finding struct {
	Severity int // 0 highest
	Text     string
	Command  string
}

// RelayClass is relay activity grouped by kind of service.
type RelayClass struct {
	Class            string
	OnGet            bool
	Hosts            int
	Attempts, Denied int
	Agents           int
}

// Bucket is one slice of the activity timeline: connections attempted in
// that slice, and how many were refused.
type Bucket struct {
	Start         time.Time
	Conns, Denied int
}

// HostStat is one destination, totals across agents.
type HostStat struct {
	Host          string
	Conns, Denied int
	Sent          int64
}

// ReasonCount counts refusals by what caused them.
type ReasonCount struct {
	Class string
	N     int
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
	Timeline         []Bucket
	BucketWidth      time.Duration
	TopHosts         []HostStat
	TopDenied        []HostStat
	Refusals         []ReasonCount
	HighCanaries     int
}

// relayClass reduces "fetcher (fetches any URL it is given)" to "fetcher".
func relayClass(kind string) string {
	if i := strings.Index(kind, " ("); i > 0 {
		return kind[:i]
	}
	return kind
}

// bucketWidth picks a timeline grain for a window: fine enough to show a
// burst, coarse enough to fit on one line (the printer coalesces further
// if the window is very long).
func bucketWidth(span time.Duration) time.Duration {
	switch {
	case span <= 2*time.Hour:
		return time.Minute
	case span <= 48*time.Hour:
		return 15 * time.Minute
	case span <= 10*24*time.Hour:
		return time.Hour
	default:
		return 24 * time.Hour
	}
}

// RefusalClass reduces a refusal reason to a comparable class. The proxy's
// reasons carry fixes and addresses; the summary wants the category.
func RefusalClass(reason string) string {
	switch {
	case strings.HasPrefix(reason, "in deny file"):
		return "kill switch (deny file)"
	case strings.Contains(reason, "non-public address") && strings.Contains(reason, "169.254"):
		return "cloud metadata endpoint"
	case strings.Contains(reason, "non-public address"):
		return "private address"
	case strings.HasPrefix(reason, "rule "):
		if strings.Contains(reason, "traversal") {
			return "outside its --rule (path)"
		}
		return "outside its --rule (method)"
	case strings.Contains(reason, "canary credential"):
		return "canary credential use"
	case strings.Contains(reason, "port not permitted"):
		return "port not permitted"
	case strings.Contains(reason, "not in allow-list"):
		return "not on the allow-list"
	default:
		if len(reason) > 40 {
			return reason[:40] + "…"
		}
		return reason
	}
}

// humanDur renders a timeline grain briefly.
func humanDur(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return d.String()
	}
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
		case events.KindDns:
			if e.Decision == events.Deny {
				s.Denied++
			}
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

	// Per-destination totals, refusal reasons and the activity timeline:
	// the shape of a run over time is often the first thing that tells a
	// story (a burst of refusals is probing; a long flat line is quiet).
	type hostAcc struct{ HostStat }
	byHost := map[string]*hostAcc{}
	reasons := map[string]int{}
	highAgents := map[string]bool{}
	width := bucketWidth(s.Last.Sub(s.First))
	for int(s.Last.Sub(s.First.Truncate(width))/width)+1 > 76 {
		width *= 2
	}
	start := s.First.Truncate(width)
	buckets := map[int64]*Bucket{}
	for _, e := range evs {
		h := byHost[e.Host]
		if h == nil {
			h = &hostAcc{HostStat{Host: e.Host}}
			byHost[e.Host] = h
		}
		refused := e.Decision == events.Deny
		switch e.Kind {
		case events.KindConnect:
			h.Conns++
			if refused {
				h.Denied++
			}
			if refused && e.Reason != "" {
				reasons[RefusalClass(e.Reason)]++
			}
		case events.KindRequest:
			if refused && e.Reason != "" {
				reasons[RefusalClass(e.Reason)]++
			}
		case events.KindDns:
			if refused {
				h.Denied++
				if e.Reason != "" {
					reasons[RefusalClass(e.Reason)]++
				}
			}
		case events.KindClose:
			h.Sent += e.Sent
		case events.KindCanary:
			if refused {
				h.Denied++
			}
			if e.Confidence == "high" {
				highAgents[e.Agent] = true
			}
		}
		if e.Kind == events.KindConnect || e.Kind == events.KindCanary {
			idx := int64(e.Time.Sub(start) / width)
			b := buckets[idx]
			if b == nil {
				b = &Bucket{Start: start.Add(time.Duration(idx) * width)}
				buckets[idx] = b
			}
			b.Conns++
			if refused {
				b.Denied++
			}
		}
	}
	n := int(s.Last.Sub(start)/width) + 1
	s.BucketWidth = width
	s.HighCanaries = len(highAgents)
	for i := range n {
		if b := buckets[int64(i)]; b != nil {
			s.Timeline = append(s.Timeline, *b)
		} else {
			s.Timeline = append(s.Timeline, Bucket{Start: start.Add(time.Duration(i) * width)})
		}
	}
	for _, h := range byHost {
		s.TopHosts = append(s.TopHosts, h.HostStat)
		if h.Denied > 0 {
			s.TopDenied = append(s.TopDenied, h.HostStat)
		}
	}
	sort.Slice(s.TopHosts, func(i, j int) bool {
		if s.TopHosts[i].Sent != s.TopHosts[j].Sent {
			return s.TopHosts[i].Sent > s.TopHosts[j].Sent
		}
		return s.TopHosts[i].Conns > s.TopHosts[j].Conns
	})
	if len(s.TopHosts) > 6 {
		s.TopHosts = s.TopHosts[:6]
	}
	sort.Slice(s.TopDenied, func(i, j int) bool { return s.TopDenied[i].Denied > s.TopDenied[j].Denied })
	if len(s.TopDenied) > 5 {
		s.TopDenied = s.TopDenied[:5]
	}
	for class, n := range reasons {
		s.Refusals = append(s.Refusals, ReasonCount{class, n})
	}
	sort.Slice(s.Refusals, func(i, j int) bool { return s.Refusals[i].N > s.Refusals[j].N })

	s.Agents = Agents(evs)
	sort.SliceStable(s.Agents, func(i, j int) bool {
		vi, vj := verdictRank[Verdict(s.Agents[i])], verdictRank[Verdict(s.Agents[j])]
		if vi != vj {
			return vi < vj
		}
		// Same verdict: the biggest first, so a hundred one-and-done shells
		// never bury the one agent that moved megabytes.
		if s.Agents[i].Sent != s.Agents[j].Sent {
			return s.Agents[i].Sent > s.Agents[j].Sent
		}
		if s.Agents[i].Connects != s.Agents[j].Connects {
			return s.Agents[i].Connects > s.Agents[j].Connects
		}
		return s.Agents[i].Last.After(s.Agents[j].Last)
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
	// Canary trips grouped by canary kind and confidence: fifteen bullets
	// that differ only in the host name are one fact with a count.
	type canaryKey struct{ canary, conf string }
	groups := map[canaryKey][]string{}
	var groupOrder []canaryKey
	agentsBy := map[canaryKey][]string{}
	for _, e := range evs {
		if e.Kind != events.KindCanary {
			continue
		}
		k := canaryKey{e.Canary, e.Confidence}
		if _, ok := groups[k]; !ok {
			groupOrder = append(groupOrder, k)
		}
		if !contains(groups[k], e.Host) {
			groups[k] = append(groups[k], e.Host)
		}
		if !contains(agentsBy[k], e.Agent) {
			agentsBy[k] = append(agentsBy[k], e.Agent)
		}
	}
	for _, k := range groupOrder {
		who, hs := agentsBy[k], groups[k]
		where := fmt.Sprintf("at %d distinct canary hosts", len(hs))
		if len(hs) == 1 {
			where = "at " + hs[0]
		}
		if len(who) == 1 {
			out = append(out, Finding{0, fmt.Sprintf("CANARY TRIPPED: %s used %s (%s) %s", who[0], k.canary, k.conf, where),
				"canaries agent=" + who[0]})
			continue
		}
		out = append(out, Finding{0, fmt.Sprintf("CANARY TRIPPED: %s (%s) used by %d agents (%s and %d more) %s", k.canary, k.conf,
			len(who), who[0], len(who)-1, where), "canaries"})
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
	// Probing, most doors refused first. The count is of distinct hosts: an
	// agent that knocked twice on one closed door tried one relay, not two.
	probing := append([]AgentSummary(nil), agents...)
	sort.SliceStable(probing, func(i, j int) bool {
		if probing[i].RelayDenyHosts != probing[j].RelayDenyHosts {
			return probing[i].RelayDenyHosts > probing[j].RelayDenyHosts
		}
		return probing[i].RelayDeny > probing[j].RelayDeny
	})
	for _, a := range probing {
		if a.RetriedAfterDenial || a.RelayDenyHosts >= 2 {
			out = append(out, Finding{2, fmt.Sprintf("%s was refused at %d relays and kept trying others", a.Agent, a.RelayDenyHosts),
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

// printTimeline draws two strips over the same scale: connections attempted
// and how many were refused. A refusal spike next to a quiet connect line is
// probing; a tall connect line that is mostly refused is something hammering
// a closed door.
func (p Printer) printTimeline(s Summary) {
	blocks := []rune("▁▂▃▄▅▆▇█")
	ascii := []rune(" .:-=+*#%@")
	zero, asciiZero := '·', ' '
	max := 1
	for _, b := range s.Timeline {
		if b.Conns > max {
			max = b.Conns
		}
		if b.Denied > max {
			max = b.Denied
		}
	}
	strip := func(get func(Bucket) int) string {
		var sb strings.Builder
		for _, b := range s.Timeline {
			n := get(b)
			if n == 0 {
				if p.ASCII {
					sb.WriteRune(asciiZero)
				} else {
					sb.WriteRune(zero)
				}
				continue
			}
			i := n * len(blocks) / max
			if i >= len(blocks) {
				i = len(blocks) - 1
			}
			if i < 1 {
				i = 1
			}
			if p.ASCII {
				sb.WriteRune(ascii[i])
			} else {
				sb.WriteRune(blocks[i])
			}
		}
		return sb.String()
	}
	fmt.Fprintf(p.W, "  conns       %s\n", strip(func(b Bucket) int { return b.Conns }))
	fmt.Fprintf(p.W, "  refused     %s\n", strip(func(b Bucket) int { return b.Denied }))
	first, last := s.Timeline[0].Start.Local(), s.Timeline[len(s.Timeline)-1].Start.Local().Add(s.BucketWidth)
	captFmt := "15:04"
	if last.Day() != first.Day() || last.Month() != first.Month() || last.Year() != first.Year() {
		captFmt = "2006-01-02 15:04"
	}
	fmt.Fprintf(p.W, "  %s\n", p.c("2", fmt.Sprintf("%d buckets of %s, %s → %s (same scale for both strips)",
		len(s.Timeline), humanDur(s.BucketWidth),
		first.Format(captFmt), last.Format(captFmt))))
}

// PrintSummary writes the state of the nation.
func (p Printer) PrintSummary(s Summary) {
	if s.Events == 0 {
		fmt.Fprintln(p.W, "no events match")
		return
	}
	p.rule("STATE OF THE NATION")
	endFmt := "15:04:05"
	if end := s.Last.Local(); end.Day() != s.First.Local().Day() || end.Month() != s.First.Local().Month() || end.Year() != s.First.Local().Year() {
		endFmt = "2006-01-02 15:04:05"
	}
	span := s.Last.Sub(s.First).Round(time.Second)
	fmt.Fprintf(p.W, "  window      %s → %s  (%s)\n", s.First.Local().Format("2006-01-02 15:04:05"), s.Last.Local().Format(endFmt), span)
	fmt.Fprintf(p.W, "  agents      %d", len(s.Agents))
	var vs []string
	for _, v := range []string{VerdictCanary, VerdictUpload, VerdictReached, VerdictProbing, VerdictWrote, VerdictQuiet} {
		if n := s.VerdictCounts[v]; n > 0 {
			label := fmt.Sprintf(" %d", n)
			if v == VerdictCanary && s.HighCanaries > 0 {
				label += fmt.Sprintf(" (%d high)", s.HighCanaries)
			}
			vs = append(vs, strings.TrimSpace(p.verdict(v))+label)
		}
	}
	fmt.Fprintf(p.W, "   %s\n", strings.Join(vs, "  "))
	fmt.Fprintf(p.W, "  traffic     %d connections to %d hosts, %d refused · %s sent\n", s.Connects, s.Hosts, s.Denied, humanBytes(s.Sent))
	if len(s.Refusals) > 0 {
		parts := make([]string, 0, 5)
		for i, r := range s.Refusals {
			if i == 5 {
				parts = append(parts, "…")
				break
			}
			parts = append(parts, fmt.Sprintf("%d %s", r.N, r.Class))
		}
		fmt.Fprintf(p.W, "  refused     %s\n", strings.Join(parts, ", "))
	}
	fmt.Fprintf(p.W, "  relays      %d attempts, %d refused, %d reached\n", s.RelayAttempts, s.RelayDenied, s.RelayAttempts-s.RelayDenied)

	if len(s.Timeline) > 1 {
		p.rule("ACTIVITY")
		p.printTimeline(s)
	}

	p.rule("AGENTS")
	fmt.Fprintf(p.W, "  %-13s %-22s %6s %6s %7s %9s  %s\n", "state", "agent", "conns", "denied", "relays", "sent", "last seen")
	collapsed := 0
	for _, a := range s.Agents {
		// One-and-done shells say nothing worth a row; they stay in the
		// event log and `console agents` still lists every one of them.
		if Verdict(a) == VerdictQuiet && a.Connects <= 2 && a.Denied == 0 && a.Relays == 0 && a.Sent < 1024 {
			collapsed++
			continue
		}
		fmt.Fprintf(p.W, "  %s %-22s %6d %6d %7d %9s  %s\n", p.verdict(Verdict(a)), clean(a.Agent, 22),
			a.Connects, a.Denied, a.Relays, humanBytes(a.Sent), a.Last.Local().Format("15:04:05"))
	}
	if collapsed > 0 {
		fmt.Fprintf(p.W, "  %s\n", p.c("2", fmt.Sprintf("+ %d more, quiet with nothing denied or relayed; console agents lists all", collapsed)))
	}

	if len(s.TopHosts) > 0 {
		p.rule("TOP DESTINATIONS")
		fmt.Fprintf(p.W, "  %-30s %6s %8s %10s\n", "host", "conns", "refused", "sent")
		for _, h := range s.TopHosts {
			fmt.Fprintf(p.W, "  %-30s %6d %8d %10s\n", clean(h.Host, 30), h.Conns, h.Denied, humanBytes(h.Sent))
		}
		if len(s.TopDenied) > 0 {
			parts := make([]string, 0, len(s.TopDenied))
			for _, h := range s.TopDenied {
				parts = append(parts, fmt.Sprintf("%s (%d)", clean(h.Host, 26), h.Denied))
			}
			fmt.Fprintf(p.W, "  %s\n", p.c("2", "most refused: "+strings.Join(parts, ", ")))
		}
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
		fmt.Fprintln(p.W, "  ! fetcher relays reached on a plain GET: without a --rule the proxy sees only the host, not what was fetched or carried")
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
