// Package proxy implements an allow-listing egress proxy.
//
// It exists because neither Seatbelt nor a network namespace can express "this
// program may reach api.anthropic.com and nothing else". They gate sockets and
// ports, not destinations. That leaves two honest options for anything that
// needs network — allow everything, or route through something that understands
// hostnames — and this is the second.
//
// The sandbox is configured to deny all direct network access except a
// connection to this proxy on loopback. Because the confined program no longer
// resolves names itself, DNS can stay denied entirely, which also closes the
// DNS-tunnelling channel that a plain "allow network" profile leaves open.
package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Rule is one allow-list entry.
//
// A leading dot means "this domain and its subdomains"; anything else must
// match exactly. Exact-by-default is deliberate: a reader who writes
// "anthropic.com" should not silently also permit every host anybody ever
// parks under it.
type Rule struct {
	pattern  string
	wildcard bool
}

// ParseRule builds a Rule from an allow-list string.
func ParseRule(s string) (Rule, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return Rule{}, fmt.Errorf("empty allow-list entry")
	}
	if s == "*" || s == "." {
		return Rule{}, fmt.Errorf("%q would allow every host, which defeats the proxy", s)
	}
	if strings.HasPrefix(s, "*.") {
		return Rule{pattern: s[1:], wildcard: true}, nil
	}
	if strings.HasPrefix(s, ".") {
		return Rule{pattern: s, wildcard: true}, nil
	}
	return Rule{pattern: s, wildcard: false}, nil
}

// Matches reports whether host satisfies the rule.
func (r Rule) Matches(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if r.wildcard {
		// ".example.com" matches "a.example.com" and "example.com" itself.
		return strings.HasSuffix(host, r.pattern) || host == strings.TrimPrefix(r.pattern, ".")
	}
	return host == r.pattern
}

func (r Rule) String() string { return r.pattern }

// AllowList decides which destinations may be reached.
type AllowList struct {
	rules []Rule
	// AllowPrivate disables the private-address guard for every host. Off by
	// default, and deliberately blunt: it also opens the cloud metadata
	// endpoint. Prefer PrivateHosts.
	AllowPrivate bool
	// PrivateHosts are the only hosts permitted to resolve to private
	// addresses — an internal registry, say — while the guard stays on for
	// everything else. Without this, reaching one internal service meant
	// --allow-private, which opened the metadata endpoint and the whole
	// internal network along with it.
	PrivateHosts []Rule
	// HostRules narrow what may be done on specific allowed hosts (methods,
	// path prefixes). Hosts with a rule are TLS-inspected; see HostRule.
	HostRules []HostRule
	// Ports are the destination ports permitted for allowed hosts. Empty means
	// DefaultPorts.
	Ports []string
	// AnyPort disables the port restriction. Not exposed on the command line;
	// it exists for tests whose upstream binds a random port.
	AnyPort bool
}

// DefaultPorts are HTTPS and HTTP. Anything else must be asked for explicitly.
var DefaultPorts = []string{"443", "80"}

// PermitsPort reports whether the destination port is allowed.
func (a *AllowList) PermitsPort(port string) bool {
	if a.AnyPort {
		return true
	}
	ports := a.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// NewAllowList parses a set of patterns.
func NewAllowList(patterns []string) (*AllowList, error) {
	a := &AllowList{}
	for _, p := range patterns {
		r, err := ParseRule(p)
		if err != nil {
			return nil, err
		}
		a.rules = append(a.rules, r)
	}
	return a, nil
}

// Rules returns the configured patterns, for reporting.
func (a *AllowList) Rules() []string {
	out := make([]string, len(a.rules))
	for i, r := range a.rules {
		out[i] = r.String()
	}
	return out
}

// PermitsHost reports whether the hostname is allow-listed.
func (a *AllowList) PermitsHost(host string) bool {
	for _, r := range a.rules {
		if r.Matches(host) {
			return true
		}
	}
	return false
}

// CheckAddr validates a resolved address before the proxy connects to it.
//
// Name matching alone is not enough. An allow-listed name whose DNS an attacker
// controls can be pointed at 169.254.169.254 or an address inside your network,
// and the proxy would faithfully fetch it on the sandbox's behalf — turning the
// one component trusted to reach the network into the confused deputy. So every
// resolved address is checked, and private, loopback and link-local space is
// refused unless explicitly permitted.
func (a *AllowList) CheckAddr(ip net.IP) error {
	return a.CheckHostAddr("", ip)
}

// CheckHostAddr is CheckAddr with per-host private access: a host named in
// PrivateHosts may resolve to private space, except the link-local range,
// which holds the cloud metadata endpoint and is never a legitimate home for
// an internal service.
func (a *AllowList) CheckHostAddr(host string, ip net.IP) error {
	if a.AllowPrivate {
		return nil
	}
	if !isRestrictedIP(ip) {
		return nil
	}
	if host != "" && ip != nil && !ip.IsLinkLocalUnicast() {
		for _, r := range a.PrivateHosts {
			if r.Matches(host) {
				return nil
			}
		}
	}
	return fmt.Errorf("resolved to non-public address %s; refusing (use --allow-private-host %s to permit this host only)", ip, host)
}

// AddPrivateHost permits one host (and, with a leading '.', its subdomains)
// to resolve to private addresses.
func (a *AllowList) AddPrivateHost(pattern string) error {
	r, err := ParseRule(pattern)
	if err != nil {
		return err
	}
	a.PrivateHosts = append(a.PrivateHosts, r)
	return nil
}

// isRestrictedIP reports whether an address is outside routable public space.
func isRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1]&0xf0 == 16:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 169 && ip4[1] == 254: // link-local, incl. cloud metadata
			return true
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // carrier-grade NAT
			return true
		case ip4[0] == 127:
			return true
		}
		return false
	}
	// IPv6 unique-local.
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

// SplitHostPort separates a CONNECT target, defaulting the port.
func SplitHostPort(target string, defaultPort string) (host, port string, err error) {
	if !strings.Contains(target, ":") {
		return target, defaultPort, nil
	}
	host, port, err = net.SplitHostPort(target)
	if err != nil {
		return "", "", fmt.Errorf("malformed destination %q: %w", target, err)
	}
	return host, port, nil
}

// ValidHostname reports whether h is a syntactically valid DNS name or IP
// literal. Hostnames reaching the proxy come from the sandboxed program, so
// anything echoed back for a user to paste into a shell must pass this first.
func ValidHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// ValidPort reports whether p is a decimal port number in 1-65535.
func ValidPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}
