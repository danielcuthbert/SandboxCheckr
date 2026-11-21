package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// HostRule restricts what may be done on an allowed host, not just whether it
// can be reached.
//
// Destination filtering alone cannot tell a package download from an upload:
// both are "a connection to the registry". That is exactly the gap the 2026
// OpenAI–Hugging Face agents used — writes to an allowed registry became their
// message board, and its upstream-fetch feature became their way out. A
// HostRule says which METHODS and PATHS are permitted, so "trust the registry"
// can become "trust downloads from the registry".
//
// Enforcing a HostRule over HTTPS requires seeing the request, so hosts with a
// rule are TLS-inspected using a local CA (see CA). Hosts without one are
// tunnelled untouched, as before.
type HostRule struct {
	host    Rule
	methods map[string]bool // empty = any method
	paths   []string        // path prefixes; empty = any path
	raw     string
}

// ParseHostRule parses "host[:METHOD,METHOD][:/prefix,/prefix]".
//
//	registry.internal:GET,HEAD
//	registry.internal:GET,HEAD:/api/npm/npm-remote/,/api/pypi/
//	.github.com:GET
//
// Methods are case-insensitive. A host must already be on the allow-list for
// a rule to matter; the rule only narrows what is allowed there.
func ParseHostRule(s string) (HostRule, error) {
	parts := strings.SplitN(s, ":", 3)
	r, err := ParseRule(parts[0])
	if err != nil {
		return HostRule{}, err
	}
	hr := HostRule{host: r, methods: map[string]bool{}, raw: s}
	if len(parts) > 1 && parts[1] != "" {
		for _, m := range strings.Split(parts[1], ",") {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m == "" {
				continue
			}
			if m == "CONNECT" {
				return HostRule{}, fmt.Errorf("%q: CONNECT is the tunnel itself and cannot be a permitted method", s)
			}
			hr.methods[m] = true
		}
	}
	if len(parts) > 2 && parts[2] != "" {
		for _, p := range strings.Split(parts[2], ",") {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "/") {
				return HostRule{}, fmt.Errorf("%q: path prefix %q must start with /", s, p)
			}
			hr.paths = append(hr.paths, p)
		}
	}
	if len(hr.methods) == 0 && len(hr.paths) == 0 {
		return HostRule{}, fmt.Errorf("%q: a rule needs at least one method or path (e.g. %s:GET,HEAD)", s, parts[0])
	}
	return hr, nil
}

// Permits reports whether a request is allowed under this rule, and why not.
func (r HostRule) Permits(req *http.Request) (bool, string) {
	if len(r.methods) > 0 && !r.methods[req.Method] {
		return false, "method " + req.Method + " not permitted (allowed: " + r.methodList() + ")"
	}
	if len(r.paths) > 0 {
		p := req.URL.Path
		// Reject traversal outright rather than trying to normalise it: a
		// server may resolve ".." or encoded separators differently from us.
		// %2e is the encoded dot, without which %2e%2e walks up.
		lowerRaw := ""
		if req.URL.RawPath != "" {
			lowerRaw = strings.ToLower(req.URL.RawPath)
		}
		if strings.Contains(p, "..") || lowerRaw != "" &&
			(strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%2e")) {
			return false, "path contains traversal or encoded separators"
		}
		ok := false
		for _, pre := range r.paths {
			// A prefix matches at a path boundary only. Prefix matching alone
			// let --rule host:GET,/acme admit /acmeevil and /acme-secret, which
			// matters because a path rule is the only thing separating "trust
			// this code host" from "fetch anyone's payload" (SBX-011).
			base := strings.TrimSuffix(pre, "/")
			if p == base || strings.HasPrefix(p, base+"/") {
				ok = true
				break
			}
		}
		if !ok {
			return false, "path " + p + " not under an allowed prefix (" + strings.Join(r.paths, ", ") + ")"
		}
	}
	return true, ""
}

func (r HostRule) methodList() string {
	var out []string
	for m := range r.methods {
		out = append(out, m)
	}
	return strings.Join(out, ",")
}

func (r HostRule) String() string { return r.raw }

// HasPaths reports whether the rule restricts paths, not only methods.
func (r HostRule) HasPaths() bool { return len(r.paths) > 0 }

// RuleFor returns the rule governing host, if any.
func (a *AllowList) RuleFor(host string) (HostRule, bool) {
	for _, r := range a.HostRules {
		if r.host.Matches(host) {
			return r, true
		}
	}
	return HostRule{}, false
}

// AddHostRule adds a request rule.
func (a *AllowList) AddHostRule(s string) error {
	r, err := ParseHostRule(s)
	if err != nil {
		return err
	}
	a.HostRules = append(a.HostRules, r)
	return nil
}
