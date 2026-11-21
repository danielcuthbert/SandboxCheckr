// Package sblint statically analyses a macOS Seatbelt (.sb) profile and reports
// the anti-patterns that make a sandbox weaker than it looks.
//
// It is the automated form of reading a profile by hand: does it deny by
// default or allow by default; is egress actually denied or merely narrowed on
// paper; does it lock writes while leaving reads wide open (the shape that
// protects against tampering but not secret theft); is mach-lookup a blanket
// grant. The checks are deliberately heuristic — a Seatbelt profile is an
// s-expression document and this does not fully parse it — so findings are
// framed as "worth a look", not proof. It never executes anything.
package sblint

import "strings"

// EgressPosture summarises how a profile treats outbound network.
type EgressPosture string

const (
	// EgressOpen: the profile permits outbound network broadly — allow-default
	// with no network deny, (allow network*), or a bare (allow network-outbound).
	EgressOpen EgressPosture = "open"
	// EgressProxied: outbound is denied except a loopback/unix path — the
	// egress-via-local-proxy pattern.
	EgressProxied EgressPosture = "proxied"
	// EgressDenied: outbound is denied with no allow-back.
	EgressDenied EgressPosture = "denied"
	// EgressUnknown: the rules did not fit a clear shape.
	EgressUnknown EgressPosture = "unknown"
)

// Finding is one issue in a profile.
type Finding struct {
	Severity string // "high" | "medium" | "low"
	Title    string
	Detail   string
	Line     int // 1-based; 0 when not tied to a line
}

// Result is the linter's verdict on a profile.
type Result struct {
	// Egress is the profile's outbound-network posture.
	Egress EgressPosture
	// ReadsOpen is true when the profile leaves filesystem reads broadly
	// permitted (so secrets outside the workdir are readable).
	ReadsOpen bool
	// Cooperative is true when egress is NOT enforced by the sandbox — i.e. the
	// profile leaves direct sockets open, so any egress control depends on the
	// program voluntarily using a proxy (bypassable). This is the v1-vs-v2
	// distinction: a proxy that isn't backed by a socket deny is cooperative.
	Cooperative bool
	Findings    []Finding
}

// Lint analyses a Seatbelt profile.
func Lint(profile string) Result {
	stripped := stripComments(profile)
	lines := strings.Split(stripped, "\n")
	// Every match below runs against spacing-normalised lowercase text. A
	// cosmetic variant such as "( allow  default )" is the same rule to
	// Seatbelt, and a linter that only knows the flush form loses a high
	// finding on it. The line numbers reported by lineOf stay the original
	// ones, taken from `lines`.
	norm := make([]string, len(lines))
	for i, l := range lines {
		norm[i] = normalise(l)
	}
	low := strings.Join(norm, "\n")

	has := func(sub string) bool { return strings.Contains(low, strings.ToLower(sub)) }
	lineOf := func(sub string) int {
		sub = strings.ToLower(sub)
		for i, l := range norm {
			if strings.Contains(l, sub) {
				return i + 1
			}
		}
		return 0
	}
	// depth[i] is the paren depth at the start of line i. Seatbelt rules are
	// top-level forms, so a rule begins on a line of depth 0; that is how the
	// enclosing form of a rule written across several lines is found.
	depth := make([]int, len(norm)+1)
	for i, l := range norm {
		depth[i+1] = max(depth[i]+parenDelta(l), 0)
	}

	var r Result
	var f []Finding

	allowDefault := has("(allow default)")
	denyDefault := has("(deny default)")
	// Only a blanket read deny closes reads under allow-default. A deny of one
	// directory — (deny file-read* (subpath "~/.secrets")) — leaves ~/.ssh,
	// ~/.aws and the rest readable, and must not count.
	denyRead := has("(deny file-read*)")
	denyWrite := has("(deny file-write*")
	allowWriteList := has("(allow file-write*")

	// --- default posture ---
	if allowDefault {
		f = append(f, Finding{
			Severity: "high", Line: lineOf("(allow default)"),
			Title:  "Allows everything by default",
			Detail: "(allow default) permits every operation unless a later rule denies it. A sandbox should deny by default and grant back the minimum; allow-default means anything not explicitly removed is permitted.",
		})
	} else if !denyDefault {
		f = append(f, Finding{
			Severity: "medium",
			Title:    "No explicit default posture",
			Detail:   "The profile has neither (allow default) nor (deny default). Behaviour then depends on Seatbelt's defaults and rule order, which is hard to reason about — state (deny default) explicitly.",
		})
	}

	// --- egress ---
	r.Egress = classifyEgress(has, denyDefault)
	switch r.Egress {
	case EgressOpen:
		f = append(f, Finding{
			Severity: "high", Line: egressLine(lineOf),
			Title:  "Outbound network is open",
			Detail: "The profile permits outbound sockets broadly, so a piped download runs and anything readable can be exfiltrated directly. Egress should be denied, with a narrow allow only for a vetted proxy or host.",
		})
	case EgressProxied:
		// Healthy — no finding, but recorded in r.Egress.
	case EgressDenied:
		// Also healthy (strictest).
	}

	// Cooperative egress: sockets open means any proxy-based control is
	// bypassable — the exact trap where HTTP_PROXY is set but the sandbox does
	// not force it. Only flagged when egress is open (proxied/denied are enforced).
	if r.Egress == EgressOpen {
		r.Cooperative = true
	}

	// --- reads ---
	// A read grant of "/" is obvious; a grant of a whole home directory is the
	// same leak wearing workdir clothing, so it counts too.
	homeRead := homeReadLine(norm)
	broadRead := has(`(subpath "/")`) || has(`(literal "/")`) || homeRead > 0
	r.ReadsOpen = (allowDefault && !denyRead) || broadRead
	if allowDefault && !denyRead && !broadRead {
		f = append(f, Finding{
			Severity: "high", Line: lineOf("(allow default)"),
			Title:  "Filesystem reads are open",
			Detail: "Under (allow default), reads are permitted everywhere not explicitly denied. Denying one directory (a secrets folder) leaves ~/.ssh, ~/.aws, ~/.config, browser profiles, shell history and every project's .env readable. List what may be read instead, starting from (deny file-read*).",
		})
	}
	if broadRead {
		f = append(f, Finding{
			Severity: "medium", Line: broadReadLine(lineOf, homeRead),
			Title:  "Filesystem reads are broadly allowed",
			Detail: `A read rule grants "/" (whole filesystem) or an entire home directory. The confined process can read ~/.ssh, ~/.aws, browser profiles and the keychain files. Restrict reads to the workdir and the system paths a program needs to start.`,
		})
	}

	// --- writes locked, reads open ---
	// Writes are locked either by an explicit deny of file-write* under
	// allow-default, or by the default itself under (deny default) with an
	// allow-list handed back. Either way the profile guards against tampering
	// and not against reading.
	writesLocked := allowWriteList && (denyWrite || denyDefault)
	if writesLocked && r.ReadsOpen {
		line := lineOf("(deny file-write*)")
		if line == 0 {
			line = lineOf("(allow file-write*") // under (deny default) the default does the denying
		}
		f = append(f, Finding{
			Severity: "high", Line: line,
			Title:  "Restricts writes but not reads",
			Detail: "Writes are denied outside an allow-list (good against tampering and persistence) but reads are left open. This protects the machine from being modified, not your secrets from being read and exfiltrated — the two are different threats and this covers only one.",
		})
	}

	// --- mach-lookup blanket ---
	if has("(allow mach-lookup)") && !has("(allow mach-lookup (global-name") {
		f = append(f, Finding{
			Severity: "medium", Line: lineOf("(allow mach-lookup)"),
			Title:  "Unrestricted mach-lookup",
			Detail: "(allow mach-lookup) with no global-name filter exposes every system service over Mach — pasteboard, Apple Events, and historically networking daemons. Prefer an allow-list of the specific services the program needs.",
		})
	}

	// --- holes in an otherwise enforced network deny ---
	// Each of these is the shape of a published profile that denies network
	// and then pokes "harmless" holes for localhost, unix sockets and DNS
	// (agent-seatbelt-sandbox, 2026). The deny holds for TCP; these do not.
	if r.Egress == EgressProxied || r.Egress == EgressDenied {
		if n := lineOf("mdnsresponder"); n > 0 && allowOutboundLine(norm, depth, n) {
			f = append(f, Finding{
				Severity: "high", Line: n,
				Title:  "DNS resolver reachable despite the network deny",
				Detail: "Allowing network-outbound to mDNSResponder lets the process resolve any name, and a lookup of <data>.attacker.example carries data to whoever runs that domain's nameserver. DNS tunnelling survives every other network rule. If egress goes through a proxy, the proxy resolves names; the sandbox does not need DNS at all.",
			})
		}
		if n := bareUnixSocketLine(norm, depth); n > 0 {
			f = append(f, Finding{
				Severity: "high", Line: n,
				Title:  "Any unix socket is reachable",
				Detail: "(remote unix-socket) with no path filter permits connecting to every unix socket the process can name: the Docker or Colima socket (docker run -v /:/host is a full escape), the SSH and GPG agents (sign as you without the key file), and other local daemons. Allow only the specific socket paths the program needs, with (remote unix-socket (path-literal ...)).",
			})
		}
		if n := lineOf(`remote ip "localhost:*"`); n > 0 {
			f = append(f, Finding{
				Severity: "medium", Line: n,
				Title:  "Every loopback port is reachable",
				Detail: "localhost:* opens every local TCP service to the sandbox, not just the proxy: databases and dev servers, a Docker TCP API, local model servers and MCP servers, and other sandboxes' proxies, which also makes loopback a channel between agents. If egress goes through a proxy, allow only its port.",
			})
		}
	}

	r.Findings = f
	return r
}

// maxRuleLines bounds the walk that looks for the enclosing form of a rule. A
// .sb rule is a handful of lines; a file that keeps the scan going past this
// is malformed, and "no rule found" beats scanning the whole profile.
const maxRuleLines = 64

// normalise lowercases a line, collapses every run of whitespace to one space,
// and drops the space beside a parenthesis, so a match does not depend on how
// the profile was formatted: "( allow  default )" is the rule Seatbelt sees as
// (allow default). A rule whose quoted path contains "( " or " )" is formatted
// differently by this than it is on disk; nothing matched keys on that.
func normalise(line string) string {
	s := strings.ToLower(strings.Join(strings.Fields(line), " "))
	s = strings.ReplaceAll(s, "( ", "(")
	return strings.ReplaceAll(s, " )", ")")
}

// parenDelta is the change in s-expression depth a line makes.
func parenDelta(line string) int {
	d := 0
	for i := range len(line) {
		switch line[i] {
		case '(':
			d++
		case ')':
			d--
		}
	}
	return d
}

// ruleText returns the normalised text of the top-level form containing 1-based
// line n, or "" when it cannot be found. Judging the whole form rather than a
// fixed window of preceding lines is what lets a rule written as
//
//	(allow network-outbound
//	  (remote unix-socket))
//
// still be read as the one rule it is.
func ruleText(norm []string, depth []int, n int) string {
	if n < 1 || n > len(norm) {
		return ""
	}
	start := n - 1
	for start > 0 && depth[start] != 0 && n-1-start < maxRuleLines {
		start--
	}
	if depth[start] != 0 {
		return ""
	}
	d, end := 0, start
	for end < len(norm) && end-start < maxRuleLines {
		d += parenDelta(norm[end])
		if d <= 0 {
			break
		}
		end++
	}
	return strings.Join(norm[start:min(end+1, len(norm))], " ")
}

// allowOutboundLine reports whether the rule containing 1-based line n is an
// allow network-outbound rule.
func allowOutboundLine(norm []string, depth []int, n int) bool {
	rule := ruleText(norm, depth, n)
	if rule == "" || strings.Contains(rule, "(deny ") {
		return false
	}
	return strings.Contains(rule, "(allow network-outbound") || strings.Contains(rule, "(allow network*")
}

// bareUnixSocketLine finds an allowed (remote unix-socket) with no path
// filter, returning its 1-based line or 0. The path filter may sit on another
// line, so the whole enclosing form is tested.
func bareUnixSocketLine(norm []string, depth []int) int {
	const needle = "(remote unix-socket"
	for i, l := range norm {
		if !strings.Contains(l, needle) || !allowOutboundLine(norm, depth, i+1) {
			continue
		}
		for _, rest := range strings.Split(ruleText(norm, depth, i+1), needle)[1:] {
			if strings.HasPrefix(strings.TrimLeft(rest, " "), ")") {
				return i + 1
			}
		}
	}
	return 0
}

// classifyEgress determines the outbound posture from the presence of key rules.
// denyDefault counts as a network deny: under (deny default) everything the
// profile does not allow back is already refused, so a profile that never
// allows outbound is as closed as one with an explicit (deny network*).
func classifyEgress(has func(string) bool, denyDefault bool) EgressPosture {
	allowDefault := has("(allow default)")
	denyNet := denyDefault || has("(deny network*") || has("(deny network-outbound")
	allowNetStar := has("(allow network*")
	allowOutbound := has("(allow network-outbound")
	bareOutbound := has("(allow network-outbound)")
	proxyAllow := allowOutbound && (has(`remote ip "localhost`) ||
		has(`remote ip "127.0.0.1`) || has("remote unix-socket"))

	switch {
	case allowNetStar || bareOutbound:
		return EgressOpen
	case allowDefault && !denyNet:
		return EgressOpen
	case denyNet && proxyAllow:
		return EgressProxied
	case denyNet && !allowOutbound && !allowNetStar:
		return EgressDenied
	case denyNet && allowOutbound:
		// denied then narrowed to specific non-loopback hosts: enforced, but not
		// via a local proxy. Treat as proxied-class (enforced) for posture.
		return EgressProxied
	default:
		return EgressUnknown
	}
}

func egressLine(lineOf func(string) int) int {
	for _, s := range []string{"(allow network*", "(allow network-outbound)", "(allow default)"} {
		if n := lineOf(s); n > 0 {
			return n
		}
	}
	return 0
}

// homeReadNeedles are subpath forms that grant a home directory rather than a
// workdir. Lowercased, matched against a normalised line.
var homeReadNeedles = []string{
	`(subpath "/users`, `(subpath "/private/users`, `(subpath "~`, `(subpath "$home`,
}

// homeReadLine finds an allow file-read* rule granting a whole home directory,
// returning its 1-based line or 0. Under (deny default) such a grant is the
// whole leak: SSH keys, cloud credentials and browser cookie stores sit under
// one path. Only allow rules count; denying ~/.secrets is not a grant.
func homeReadLine(norm []string) int {
	for i, l := range norm {
		if !strings.Contains(l, "(allow file-read") {
			continue
		}
		for _, n := range homeReadNeedles {
			if strings.Contains(l, n) {
				return i + 1
			}
		}
	}
	return 0
}

func broadReadLine(lineOf func(string) int, homeRead int) int {
	for _, s := range []string{`(literal "/")`, `(subpath "/")`} {
		if n := lineOf(s); n > 0 {
			return n
		}
	}
	return homeRead
}

// stripComments removes Seatbelt line comments (starting with ';') while
// preserving line count, so finding line numbers stay accurate.
func stripComments(profile string) string {
	lines := strings.Split(profile, "\n")
	for i, l := range lines {
		if idx := commentIndex(l); idx >= 0 {
			lines[i] = l[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

// commentIndex returns the offset of the ';' that starts a line comment, or -1.
// A ';' inside a quoted path is part of the path: cutting (subpath
// "/opt/tools;bin") at that semicolon deleted the rest of the rule from the
// analysis and could flip the answer. A backslash escapes the next character,
// which is the only way a '"' appears inside a Seatbelt string. The loop
// advances i itself to skip an escape, so it is not a range loop.
func commentIndex(l string) int {
	quoted := false
	for i := 0; i < len(l); i++ {
		switch l[i] {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		case ';':
			if !quoted {
				return i
			}
		}
	}
	return -1
}
