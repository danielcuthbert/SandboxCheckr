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
	low := strings.ToLower(stripped)
	lines := strings.Split(stripped, "\n")

	has := func(sub string) bool { return strings.Contains(low, sub) }
	lineOf := func(sub string) int {
		sub = strings.ToLower(sub)
		for i, l := range lines {
			if strings.Contains(strings.ToLower(l), sub) {
				return i + 1
			}
		}
		return 0
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
	r.Egress = classifyEgress(has)
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
	broadRead := has(`(subpath "/")`) || has(`(literal "/")`)
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
			Severity: "medium", Line: broadReadLine(lineOf),
			Title:  "Filesystem reads are broadly allowed",
			Detail: `A read rule grants "/" (whole filesystem). The confined process can read ~/.ssh, ~/.aws, browser profiles and the keychain files. Restrict reads to the workdir and the system paths a program needs to start.`,
		})
	}

	// --- writes locked, reads open ---
	if allowDefault && denyWrite && allowWriteList && r.ReadsOpen {
		f = append(f, Finding{
			Severity: "high", Line: lineOf("(deny file-write*)"),
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
		if n := lineOf("mdnsresponder"); n > 0 && allowOutboundLine(lines, n) {
			f = append(f, Finding{
				Severity: "high", Line: n,
				Title:  "DNS resolver reachable despite the network deny",
				Detail: "Allowing network-outbound to mDNSResponder lets the process resolve any name, and a lookup of <data>.attacker.example carries data to whoever runs that domain's nameserver. DNS tunnelling survives every other network rule. If egress goes through a proxy, the proxy resolves names; the sandbox does not need DNS at all.",
			})
		}
		if n := bareUnixSocketLine(lines); n > 0 {
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

// allowOutboundLine reports whether the rule at 1-based line n (or the rule
// it continues) is an allow network-outbound rule.
func allowOutboundLine(lines []string, n int) bool {
	for i := n - 1; i >= 0 && i >= n-4; i-- {
		l := strings.ToLower(lines[i])
		if strings.Contains(l, "(allow network-outbound") || strings.Contains(l, "(allow network*") {
			return true
		}
		if strings.Contains(l, "(deny ") {
			return false
		}
	}
	return false
}

// bareUnixSocketLine finds an allowed (remote unix-socket) with no path
// filter, returning its 1-based line or 0.
func bareUnixSocketLine(lines []string) int {
	for i, l := range lines {
		low := strings.ToLower(l)
		if !strings.Contains(low, "(remote unix-socket") || !allowOutboundLine(lines, i+1) {
			continue
		}
		rest := low[strings.Index(low, "(remote unix-socket")+len("(remote unix-socket"):]
		if strings.HasPrefix(strings.TrimSpace(rest), ")") {
			return i + 1
		}
	}
	return 0
}

// classifyEgress determines the outbound posture from the presence of key rules.
func classifyEgress(has func(string) bool) EgressPosture {
	allowDefault := has("(allow default)")
	denyNet := has("(deny network*") || has("(deny network-outbound")
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

func broadReadLine(lineOf func(string) int) int {
	if n := lineOf(`(literal "/")`); n > 0 {
		return n
	}
	return lineOf(`(subpath "/")`)
}

// stripComments removes Seatbelt line comments (starting with ';') while
// preserving line count, so finding line numbers stay accurate.
func stripComments(profile string) string {
	lines := strings.Split(profile, "\n")
	for i, l := range lines {
		if idx := strings.Index(l, ";"); idx >= 0 {
			lines[i] = l[:idx]
		}
	}
	return strings.Join(lines, "\n")
}
