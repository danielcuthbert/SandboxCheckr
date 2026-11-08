package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// This file enumerates routes data can leave by.
//
// The distinction from the net.* probes matters. Blocking outbound TCP is not
// the same as blocking exfiltration, and treating them as equivalent is how a
// sandbox comes to look airtight while data walks out sideways. In the July
// 2026 OpenAI–Hugging Face incident the escape path was a shared internal
// package registry, used first as a message board and then — via its
// remote-repository proxy — as the route to the internet, and credentials were
// harvested by reading server process environment variables. See
// docs/THREAT_MODEL.md for sources.
//
// Every probe here is capability-only. They establish that a channel is open
// and never move anything sensitive through it: secret-shaped environment
// variables are reported by NAME and never by value, the DNS probe sends a
// fixed benign label, and filesystem probes write a marker they then delete.

// secretEnvPatterns are substrings that mark an environment variable as likely
// to hold a credential. Matching on names alone is deliberate — we report which
// secrets are exposed without ever reading, logging or transmitting their
// values.
var secretEnvPatterns = []string{
	"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
	"AUTH", "APIKEY", "ACCESS_KEY", "PRIVATE",
}

// benignEnvNames match the patterns above but never hold credentials.
var benignEnvNames = map[string]bool{
	"SSH_AUTH_SOCK":       true,
	"GPG_AGENT_INFO":      true,
	"KEYBOARD":            true,
	"XDG_CURRENT_DESKTOP": true,
}

// benignEnvSuffixes name configuration about credentials rather than
// credentials themselves — CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS lists
// provider names, it does not contain a secret.
//
// The list is kept short on purpose. Matching is on names only and the result
// is a hint, so over-reporting costs a reader one glance while under-reporting
// hides an exposed key; when in doubt this errs toward reporting.
var benignEnvSuffixes = []string{
	"_PROVIDER", "_PROVIDERS", "_ENABLED", "_DISABLED", "_BUNDLE", "_CAFILE",
}

// cloudSyncDirs are folders whose contents are uploaded by a background agent.
// A write here leaves the machine without the sandboxed process making a single
// network call, so no egress rule can stop it.
var cloudSyncDirs = map[string][]string{
	"darwin": {
		"Library/Mobile Documents/com~apple~CloudDocs",
		"Dropbox",
		"OneDrive",
		"Google Drive",
	},
	"linux": {
		"Dropbox",
		"OneDrive",
		"Nextcloud",
		"ownCloud",
	},
	"windows": {
		"OneDrive",
		"Dropbox",
		"iCloudDrive",
		"Google Drive",
	},
}

// sharedScratchDirs are writable locations that more than one sandboxed process
// is likely to see.
var sharedScratchDirs = func() []string {
	if runtime.GOOS == "windows" {
		// C:\Users\Public is writable by every user and every process on the
		// machine; C:\Windows\Temp is commonly writable too.
		return []string{`C:\Users\Public`, `C:\Windows\Temp`}
	}
	return []string{"/tmp", "/private/tmp", "/var/tmp", "/dev/shm"}
}()

// proxyEnvVars carry an inherited HTTP proxy.
var proxyEnvVars = []string{
	"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
}

// tunnelLabel is a fixed, meaningless label. Using a constant rather than
// encoding anything real is what keeps this a capability check: if the query
// escapes, an attacker could have encoded data in its place, but we did not.
const tunnelLabel = "sandboxcheckr-probe-0000000000000000000000000000"

// tunnelDomain is deliberately non-existent. Reaching a resolver produces
// NXDOMAIN, which proves the query left the sandbox while contacting nothing
// that belongs to anyone.
//
// Caveat that shaped the probe below: on macOS, Go resolves through libSystem
// and mDNSResponder, which answers ".invalid" locally (RFC 6761) without any
// network traffic. An NXDOMAIN for this label therefore proves nothing on its
// own, so the probe only counts it when an ordinary lookup also succeeds from
// the same process — i.e. when the resolver is demonstrably reachable.
const tunnelDomain = ".invalid"

// RunExfilBattery enumerates exfiltration channels.
func RunExfilBattery(h home) []model.ProbeResult {
	return []model.ProbeResult{
		probeEnvSecrets(),
		probeSharedScratch(),
		probeSyncDirs(h),
		probeProxyEnv(),
		probeClipboard(),
		probeDNSTunnel(),
	}
}

// probeEnvSecrets reports credentials reachable through the environment.
//
// Reports names only. A tool that printed the values would itself become the
// exfiltration channel it is warning about, and its output lands in terminals,
// CI logs and JSON artifacts.
func probeEnvSecrets() model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilEnvSecrets, Want: model.VerdictBlocked}

	var found []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || benignEnvNames[name] {
			continue
		}
		upper := strings.ToUpper(name)
		if hasAnySuffix(upper, benignEnvSuffixes) {
			continue
		}
		for _, pat := range secretEnvPatterns {
			if strings.Contains(upper, pat) {
				found = append(found, name)
				break
			}
		}
	}

	// On Linux the environment is also readable as a file, so a bug that only
	// grants a file read — no code execution — is enough to take every
	// credential in it. Reading process environment variables through an
	// arbitrary-file-read flaw is how credentials were harvested in the 2026
	// OpenAI–Hugging Face incident.
	environReadable := false
	if runtime.GOOS == "linux" {
		if f, err := os.Open("/proc/self/environ"); err == nil {
			_ = f.Close()
			environReadable = true
		}
	}

	switch {
	case len(found) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "credential-shaped environment variables are visible to the sandboxed " +
			"process: " + strings.Join(found, ", ")
		if environReadable {
			r.Detail += "; /proc/self/environ is also readable, so they can be exfiltrated " +
				"by a file read alone"
		}
	case environReadable:
		r.Verdict = model.VerdictAllowed
		r.Detail = "/proc/self/environ is readable; any credential placed in the environment " +
			"could be exfiltrated by a file read alone"
	default:
		r.Verdict = model.VerdictBlocked
		r.Detail = "no credential-shaped environment variables are exposed"
	}
	return r
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// probeSharedScratch reports writable directories other sandboxed processes can
// also see. This is the message-board channel.
func probeSharedScratch() model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilSharedScratch, Want: model.VerdictBlocked}

	// The mechanism told us /tmp is a private per-sandbox tmpfs: writable, but
	// two sandboxes cannot see each other's files there, so there is no peer
	// channel. Report that instead of a false alarm from writability alone.
	if os.Getenv("SANDBOXCHECKR_PRIVATE_TMP") == "1" {
		r.Verdict = model.VerdictBlocked
		r.Detail = "/tmp is a private per-sandbox tmpfs: writable, but not shared between sandboxes"
		return r
	}

	var writable []string
	for _, dir := range sharedScratchDirs {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		f, err := os.CreateTemp(dir, ".sandboxcheckr-shared-*")
		if err != nil {
			continue
		}
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		writable = append(writable, dir)
	}

	if len(writable) == 0 {
		r.Verdict = model.VerdictBlocked
		r.Detail = "no world-shared scratch directory is writable"
		return r
	}
	r.Verdict = model.VerdictAllowed
	r.Detail = "shared scratch directories are writable (" + strings.Join(writable, ", ") +
		"), so two separately-sandboxed processes can pass messages and stage data " +
		"through them without any network access"
	return r
}

// probeSyncDirs reports writable cloud-synced folders. A write here is
// exfiltration performed by a trusted background daemon on the process's
// behalf, which no egress policy applied to the sandbox can intercept.
func probeSyncDirs(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilSyncDirs, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict, r.Err = model.VerdictErrored, "home directory unknown"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}
	home := h.path

	var present, writable []string
	for _, rel := range cloudSyncDirs[runtime.GOOS] {
		dir := filepath.Join(home, rel)
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		present = append(present, rel)
		f, err := os.CreateTemp(dir, ".sandboxcheckr-sync-*")
		if err != nil {
			continue
		}
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		writable = append(writable, rel)
	}

	switch {
	case len(present) == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "no cloud-synced folders found on this machine"
	case len(writable) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "cloud-synced folders are writable (" + strings.Join(writable, ", ") +
			"); a file written here is uploaded off the machine by the sync agent, with no " +
			"network call the sandbox could block"
	default:
		r.Verdict = model.VerdictBlocked
		r.Detail = "cloud-synced folders are present but not writable"
	}
	return r
}

// probeProxyEnv reports an inherited HTTP proxy, which is a working egress path
// even where direct sockets are refused.
func probeProxyEnv() model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilProxyEnv, Want: model.VerdictBlocked}

	var set []string
	var relaying, enforcing, unclear []string
	// Several variables usually point at the same proxy; report each endpoint
	// once rather than repeating it per variable name.
	seenProxy := map[string]bool{}
	for _, name := range proxyEnvVars {
		v := os.Getenv(name)
		if v == "" {
			continue
		}
		set = append(set, name)
		hp := proxyHostPort(v)
		if hp == "" || seenProxy[hp] {
			continue
		}
		seenProxy[hp] = true
		switch proxyRelays(hp) {
		case relayYes:
			relaying = append(relaying, hp)
		case relayRefused:
			enforcing = append(enforcing, hp)
		case relayUnknown:
			unclear = append(unclear, hp)
		}
	}

	// The question is not "is a proxy reachable" but "will it carry traffic to
	// an arbitrary destination". An allow-listing proxy that refuses is the
	// control working, not a leak — counting it as one would score the
	// proxied sandbox below the unproxied one for having egress control.
	switch {
	case len(set) == 0:
		r.Verdict = model.VerdictBlocked
		r.Detail = "no HTTP proxy is configured in the environment"
	case len(relaying) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "an inherited HTTP proxy relays to arbitrary destinations (" + strings.Join(relaying, ", ") +
			"); this is a working egress path regardless of direct socket rules"
	case len(unclear) > 0:
		r.Verdict = model.VerdictErrored
		r.Detail = "an inherited HTTP proxy is reachable (" + strings.Join(unclear, ", ") +
			") but whether it relays arbitrary destinations could not be determined"
	case len(enforcing) > 0:
		r.Verdict = model.VerdictBlocked
		r.Detail = "the configured proxy (" + strings.Join(enforcing, ", ") +
			") refused a tunnel to an unlisted destination, so it is enforcing an allow-list"
	default:
		r.Verdict = model.VerdictBlocked
		r.Detail = "proxy variables are set (" + strings.Join(set, ", ") + ") but unreachable"
	}
	return r
}

type relayResult int

const (
	relayUnreachable relayResult = iota
	relayYes
	relayRefused
	relayUnknown
)

// proxyRelays asks the proxy to tunnel to egressAddr, a literal IP no sane
// allow-list contains, and reads only the status line. Nothing is sent through
// the tunnel if it opens.
func proxyRelays(hp string) relayResult {
	conn, err := net.DialTimeout("tcp", hp, dialTimeout)
	if err != nil {
		return relayUnreachable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * dialTimeout))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", egressAddr, egressAddr); err != nil {
		return relayUnknown
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return relayUnknown
	}
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
		return relayUnknown
	}
	switch {
	case strings.HasPrefix(f[1], "2"):
		return relayYes
	case f[1] == "403" || f[1] == "405" || f[1] == "407":
		// 407 (authentication required) is not a refusal of the destination,
		// but without credentials the sandbox cannot use it; credentials in the
		// environment are reported separately by exfil.env.secrets.
		return relayRefused
	default:
		// 502/504 usually mean the proxy tried and the upstream failed, which
		// on an offline host says nothing either way.
		return relayUnknown
	}
}

// proxyHostPort extracts host:port from a proxy URL, defaulting the port.
func proxyHostPort(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return net.JoinHostPort(s, "80")
	}
	return s
}

// probeClipboard reports whether the system pasteboard is reachable.
//
// It reads rather than writes, and discards the result without inspecting it.
// Writing would clobber whatever the user has copied, and inspecting would mean
// this tool handling the user's clipboard contents — neither is acceptable for
// a check that only needs to know whether the channel exists.
func probeClipboard() model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilClipboard, Want: model.VerdictBlocked}

	var tool string
	switch runtime.GOOS {
	case "darwin":
		tool = "/usr/bin/pbpaste"
	default:
		r.Verdict = model.VerdictSkipped
		r.Detail = "clipboard probing is only implemented for macOS"
		if runtime.GOOS == "windows" {
			r.Detail = "clipboard probing is not implemented for Windows yet"
		}
		return r
	}
	if _, err := os.Stat(tool); err != nil {
		r.Verdict = model.VerdictSkipped
		r.Detail = "no clipboard tool present"
		return r
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool)
	cmd.Stdout = nil // discarded: we never look at clipboard contents
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		r.Err = err.Error()
		if ctx.Err() != nil {
			r.Verdict = model.VerdictErrored
			r.Detail = "pasteboard probe timed out; not counted as contained"
			return r
		}
		// pbpaste exits non-zero when the pasteboard server refuses it. Any exit
		// status from a process that started is the server answering "no",
		// whereas failing to start at all is an exec failure we learned nothing
		// from.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			r.Verdict = model.VerdictBlocked
			r.Detail = "the system pasteboard is not reachable"
			return r
		}
		r.Verdict, r.Errno = classify(err)
		r.Detail = "pbpaste could not be run, so pasteboard reachability is unknown"
		if r.Verdict == model.VerdictBlocked {
			r.Detail = "pbpaste could not be executed inside the sandbox, so the pasteboard is not reachable from it"
		}
		return r
	}
	r.Verdict = model.VerdictAllowed
	r.Detail = "the system pasteboard is reachable; it is a cross-process channel that " +
		"filesystem and network rules do not cover"
	return r
}

// probeDNSTunnel reports whether an arbitrary attacker-chosen label reaches a
// resolver.
//
// Distinct from net.egress.dns: resolving a normal hostname shows lookups work,
// whereas tunnelling requires the query NAME itself to carry outward data. A
// resolver answering NXDOMAIN for a label nobody has ever registered proves the
// label left the machine, which is the whole primitive.
func probeDNSTunnel() model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilDNSTunnel, Want: model.VerdictBlocked}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	res := &net.Resolver{}
	_, err := res.LookupHost(ctx, tunnelLabel+tunnelDomain)
	if err == nil {
		// A wildcard resolver answered. The label certainly escaped.
		r.Verdict = model.VerdictAllowed
		r.Detail = "arbitrary DNS labels reach a resolver, so data can be encoded in query " +
			"names and tunnelled out"
		return r
	}

	// NXDOMAIN only proves the label left the process if a real resolver is
	// reachable from here. Check that with an ordinary name: if it does not
	// resolve, the NXDOMAIN was synthesised locally and no query escaped.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		ctx2, cancel2 := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel2()
		if addrs, cerr := res.LookupHost(ctx2, egressHost); cerr == nil && len(addrs) > 0 {
			r.Verdict = model.VerdictAllowed
			r.Detail = "a resolver answered NXDOMAIN for an arbitrary label and ordinary names " +
				"resolve too, so query names reach a real resolver; data can be exfiltrated by " +
				"encoding it in them"
			return r
		}
		if HostOnline {
			r.Verdict = model.VerdictBlocked
			r.Detail = "only a locally synthesised NXDOMAIN came back; ordinary names do not " +
				"resolve from inside even though they do outside, so query names are not leaving"
			return r
		}
		r.Verdict = model.VerdictErrored
		r.Detail = "no resolver was reachable, but this host may simply be offline; not counted as contained"
		return r
	}

	// Only a refusal is evidence of containment. A timeout or a missing
	// resolver looks identical on an offline laptop, and counting it would
	// credit the sandbox for the Wi-Fi being off.
	r.Err = err.Error()
	var detail string
	r.Verdict, r.Errno, detail = classifyNet(err)
	if r.Verdict == model.VerdictBlocked {
		r.Detail = "arbitrary DNS labels do not reach a resolver: " + detail
		return r
	}
	if errors.As(err, &dnsErr) && !dnsErr.IsTimeout && !dnsErr.IsNotFound && sandboxedLookupError(err) {
		r.Verdict = model.VerdictBlocked
		r.Detail = "arbitrary DNS labels do not reach a resolver: the lookup was refused"
		return r
	}
	r.Verdict = model.VerdictErrored
	r.Detail = "DNS tunnelling reachability is inconclusive (" + err.Error() + "); not counted as contained"
	return r
}

// sandboxedLookupError recognises the resolver failures a sandbox produces
// when it refuses the socket outright, as opposed to an unreachable network.
func sandboxedLookupError(err error) bool {
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "operation not permitted") ||
		strings.Contains(low, "permission denied") ||
		strings.Contains(low, "connection refused")
}
