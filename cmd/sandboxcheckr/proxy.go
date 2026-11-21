package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
	"github.com/danielcuthbert/sandboxcheckr/internal/events"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

// defaultAllow is a deliberately minimal starting point: the one host a Claude
// Code session cannot work without.
//
// It is short on purpose. A generous default list would be guesswork dressed up
// as a recommendation, and every entry is a host you are choosing to trust. Use
// --observe to discover what your program actually contacts, then allow those.
var defaultAllow = []string{"api.anthropic.com"}

// systemBundles are where the OS keeps its trusted roots as a PEM file. The
// inspection bundle starts from these so hosts WITHOUT a rule — which are not
// intercepted — still verify normally in tools that read a single bundle file.
var systemBundles = []string{
	"/etc/ssl/cert.pem",                  // macOS, Alpine
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
	"/etc/ssl/ca-bundle.pem",             // openSUSE
}

const proxyUsage = `sandboxcheckr proxy — allow-listing HTTP/HTTPS egress proxy, bound to loopback only

USAGE
  sandboxcheckr proxy [flags]

The run command and emitted *-proxy runners start this for you, on a free port
of their own. Run it
by hand to discover what a program contacts (--observe), or to enforce an
allow-list for something you launch yourself with HTTPS_PROXY=http://127.0.0.1:<port>.

WHAT IT CONTROLS
  hosts      only --allow'ed hosts are reachable (default: api.anthropic.com;
             --deny-all permits none)
  ports      443 and 80 only, unless --allow-port
  addresses  names resolving to private, loopback or link-local space (incl. cloud
             metadata) are refused; --allow-private-host opens one host, not all
  requests   --rule narrows what may be done on a host: methods and path prefixes.
             Ruled hosts are TLS-inspected with a per-run CA constrained to those
             hosts and trusted only inside the sandbox; other hosts are never
             decrypted.
  uploads    bytes sent to each host are counted; a host receiving more than 1 MiB
             is flagged, since downloads and API calls send little
  writes     the first request that sends data (POST, PUT, …) to each host is
             logged as a WARN, whatever its size — where the proxy can see the
             request: plain HTTP and --rule hosts
  code hosts raw.githubusercontent.com, gist, gitlab, huggingface serve anyone's
             content; the proxy suggests a path rule (host:GET,HEAD:/your-org/),
             not just download-only
  model APIs flagged in the log and summary: whatever the program reads can be
             sent to the model endpoint, which no proxy rule can prevent
  relays     URL shorteners, fetchers, CORS proxies, tunnels and user-hosted apps
             store data or fetch onward on a plain GET, so a download-only rule
             does not contain them. Attempts to reach one — allowed or refused —
             get their own section in the summary
  kill switch --deny-file names a file of hosts to refuse, re-read on every
             connection: add a line and that host is cut off at once, open
             connections included, even if allow-listed. It only takes access
             away. Runners point it at ~/.config/sandboxcheckr/deny.txt, and
             sandboxcheckr console's block / unblock commands edit it
  events     --events writes one JSON line per decision and visible request,
             labelled with --agent; read it with: sandboxcheckr console --events <file>
  canaries   --canaries loads a per-run set; reserved hosts and visible token
             strings are denied even in observe mode. Trips are logged and
             make the proxy exit non-zero. --canary-kill stops the runner's
             sandbox process on a high-confidence trip.

On exit it prints what was contacted, per host and port, with bytes in each
direction, store-or-forward hosts, model APIs and data-sending requests marked,
and a ready-to-paste ALLOW= line.

FLAGS
`

const proxyExamples = `
EXAMPLES
  sandboxcheckr proxy --observe --port 8899
  sandboxcheckr proxy --port 8899 --allow api.anthropic.com --allow .github.com
  # an internal registry, downloads only:
  sandboxcheckr proxy --allow api.anthropic.com --allow registry.internal \
      --allow-private-host registry.internal \
      --rule registry.internal:GET,HEAD:/api/npm/npm-remote/ \
      --ca-bundle-out ./ca.pem
`

// effectiveAllowPatterns decides the starting allow-list: whatever was given,
// or the api.anthropic.com default unless the caller denied all hosts. The
// default exists for a bare `sandboxcheckr proxy`; `run` passes --deny-all for
// commands with no provider default of their own.
func effectiveAllowPatterns(given []string, observe, denyAll bool) []string {
	if len(given) > 0 || observe || denyAll {
		return given
	}
	return defaultAllow
}

// runProxy serves the allow-listing egress proxy.
func runProxy(args []string) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), proxyUsage)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), proxyExamples)
	}

	var allows, ports, privHosts, rules multiFlag
	fs.Var(&allows, "allow", "`host` to permit; repeatable. A leading '.' also permits subdomains (.github.com)")
	fs.Var(&ports, "allow-port", "destination `port` to permit for allowed hosts; repeatable (default 443 and 80)")
	fs.Var(&privHosts, "allow-private-host", "let this `host` resolve to a private address (an internal registry); repeatable. Link-local/metadata stays refused")
	denyAll := fs.Bool("deny-all", false, "with no --allow, permit no host at all instead of the api.anthropic.com default")
	fs.Var(&rules, "rule", "restrict an allowed host: `host:METHODS[:/path,/path]`, e.g. registry.internal:GET,HEAD; repeatable. Ruled hosts are TLS-inspected")
	port := fs.Int("port", 0, "loopback `port` to bind (0 picks a free one; the address is printed on stdout)")
	unixSock := fs.String("unix", "", "listen on this unix socket `path` instead of a loopback TCP port")
	dnsUnix := fs.String("dns-unix", "", "serve the sandbox's gated DNS relay on this unix `path` (runner scripts point the sandbox resolver here)")
	observe := fs.Bool("observe", false,
		"permit ordinary destinations and log them; configured canary trips stay blocked")
	allowPrivate := fs.Bool("allow-private", false,
		"let EVERY host resolve to private, loopback or link-local addresses, incl. cloud metadata (unsafe; prefer --allow-private-host)")
	caOut := fs.String("ca-bundle-out", "", "with --rule: write a CA bundle (system roots + this run's inspection CA) to `file`, for the sandboxed program to trust")
	readyFile := fs.String("ready-file", "", "write the bound address to `file` once listening (used by runner scripts)")
	logPath := fs.String("log", "", "write decision lines to `file` instead of stderr")
	quiet := fs.Bool("quiet", false, "do not log decisions (the exit summary is still printed)")
	eventsPath := fs.String("events", "", "append a JSON line per decision and visible request to `file`, for sandboxcheckr console")
	agent := fs.String("agent", "", "`label` for this run in the --events log (default: proxy-<pid>)")
	denyPath := fs.String("deny-file", "", "refuse hosts listed in `file` (one per line, subdomains included), re-read live; open connections to a newly listed host are cut")
	canaryPath := fs.String("canaries", "", "read this run's canary set from `file`; trips are denied even in observe mode")
	tripFile := fs.String("canary-trip-file", "", "append a marker to `file` on every trip (used by runners)")
	canaryKill := fs.Bool("canary-kill", false, "stop the sandbox process on the first high-confidence trip")
	canaryPID := fs.String("canary-pid-file", "", "runner's sandbox process ID file, used with --canary-kill")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// Die with the runner shell even if `run` was SIGKILLed and never got to
	// clean up (see pdeathsig_linux.go).
	armSelfPdeathsig()
	if *canaryKill && (*canaryPath == "" || *canaryPID == "") {
		fmt.Fprintln(os.Stderr, "--canary-kill requires --canaries and --canary-pid-file")
		return 2
	}
	// Same checks `run` makes. An entry that can never match is worse than a
	// rejected one: the user sees unexplained DENYs and the documented way out
	// is --observe or --allow-private, so a typo buys a policy downgrade.
	for i, host := range allows {
		if strings.HasPrefix(host, "*.") {
			host = host[1:]
		}
		if !proxy.ValidHostname(strings.TrimPrefix(host, ".")) {
			fmt.Fprintf(os.Stderr, "--allow: invalid hostname %q\n", allows[i])
			return 2
		}
		if _, err := proxy.ParseRule(allows[i]); err != nil {
			fmt.Fprintln(os.Stderr, "--allow:", err)
			return 2
		}
	}
	for _, port := range ports {
		if !proxy.ValidPort(port) {
			fmt.Fprintf(os.Stderr, "--allow-port: invalid port %q\n", port)
			return 2
		}
	}
	for _, host := range privHosts {
		if strings.HasPrefix(host, "*.") {
			host = host[1:]
		}
		if !proxy.ValidHostname(strings.TrimPrefix(host, ".")) {
			fmt.Fprintf(os.Stderr, "--allow-private-host: invalid hostname %q\n", host)
			return 2
		}
	}
	for _, r := range rules {
		if !safeProxyWord(r) {
			fmt.Fprintf(os.Stderr, "--rule: unsupported shell characters in %q\n", r)
			return 2
		}
		if _, err := proxy.ParseHostRule(r); err != nil {
			fmt.Fprintln(os.Stderr, "--rule:", err)
			return 2
		}
	}

	patterns := effectiveAllowPatterns(allows, *observe, *denyAll)
	if len(allows) == 0 && !*observe && !*denyAll {
		fmt.Fprintf(os.Stderr, "no --allow given; defaulting to %s\n", strings.Join(defaultAllow, ", "))
	}

	list, err := proxy.NewAllowList(patterns)
	if err != nil {
		fmt.Fprintln(os.Stderr, "allow-list:", err)
		return 1
	}
	list.AllowPrivate = *allowPrivate
	list.Ports = ports
	for _, h := range privHosts {
		if err := list.AddPrivateHost(h); err != nil {
			fmt.Fprintln(os.Stderr, "--allow-private-host:", err)
			return 1
		}
	}
	var ruled []string
	for _, r := range rules {
		if err := list.AddHostRule(r); err != nil {
			fmt.Fprintln(os.Stderr, "--rule:", err)
			return 1
		}
		host := strings.SplitN(r, ":", 2)[0]
		if !list.PermitsHost(strings.TrimPrefix(host, ".")) && !*observe {
			fmt.Fprintf(os.Stderr, "--rule %s: %s is not in the allow-list, so the rule has no effect; add --allow %s\n", r, host, host)
			return 1
		}
		ruled = append(ruled, host)
	}

	var logw io.Writer = os.Stderr
	if *quiet {
		logw = nil
	} else if *logPath != "" {
		f, err := proxy.OpenAppendNoFollow(*logPath, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--log:", err)
			return 1
		}
		defer f.Close()
		logw = f
	}
	srv := proxy.NewServer(list, *observe, logw)
	if *canaryPath != "" {
		set, err := canary.Read(*canaryPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--canaries:", err)
			return 1
		}
		srv.Canaries = set
		srv.TripFile = *tripFile
		if *canaryKill {
			srv.CanaryKillPIDFile = *canaryPID
		}
	}
	if *denyPath != "" {
		d, err := proxy.NewDenyFile(*denyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--deny-file:", err)
			return 1
		}
		srv.Deny = d
	}
	if *eventsPath != "" {
		f, err := proxy.OpenAppendNoFollow(*eventsPath, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--events:", err)
			return 1
		}
		defer f.Close()
		label := *agent
		if label == "" {
			label = fmt.Sprintf("proxy-%d", os.Getpid())
		}
		w := events.NewWriter(f, label)
		// A dropped event is lost evidence, and nothing else would say so: the
		// proxy keeps deciding happily while a full disk swallows the record.
		w.Log = os.Stderr
		srv.Events = w
	}

	if len(ruled) > 0 {
		ca, err := proxy.NewCA(ruled)
		if err != nil {
			fmt.Fprintln(os.Stderr, "creating inspection CA:", err)
			return 1
		}
		srv.CA = ca
		if *caOut != "" {
			if err := writeBundle(*caOut, ca.CertPEM()); err != nil {
				fmt.Fprintln(os.Stderr, "--ca-bundle-out:", err)
				return 1
			}
		} else {
			fmt.Fprintln(os.Stderr, "note: --rule hosts are TLS-inspected; the client must trust this run's CA. "+
				"Use --ca-bundle-out (runner scripts do this for you).")
		}
	}

	var addr string
	if *unixSock != "" {
		_ = os.Remove(*unixSock)
		addr, err = srv.ListenOn("unix", *unixSock)
		defer os.Remove(*unixSock)
	} else {
		addr, err = srv.Listen(*port)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	if *dnsUnix != "" {
		if err := srv.ListenDNS(*dnsUnix); err != nil {
			fmt.Fprintln(os.Stderr, "dns listen:", err)
			return 1
		}
		defer os.Remove(*dnsUnix)
		fmt.Fprintln(os.Stderr, "dns relay: name resolution inside the sandbox is gated by the allow-list, "+
			"and refusals are logged like connections")
	}

	// Printed to stdout so a wrapper script can capture it; everything else
	// goes to stderr.
	fmt.Println(addr)
	if *readyFile != "" {
		// Written atomically, last, so a runner that sees the file knows the
		// listener AND the CA bundle are both ready.
		if err := proxy.WriteFileNoFollow(*readyFile, []byte(addr+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "--ready-file:", err)
			return 1
		}
		defer os.Remove(*readyFile)
	}

	if *observe {
		fmt.Fprintln(os.Stderr,
			"OBSERVE MODE: disallowed destinations are permitted and logged. The port gate, private-address refusals and canary trips still enforce. This is NOT full enforcement.")
	} else if rules := list.Rules(); len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "enforcing allow-list: nothing (every destination is refused)")
	} else {
		fmt.Fprintf(os.Stderr, "enforcing allow-list: %s\n", strings.Join(rules, ", "))
	}
	// The rest of the configured policy, so what was configured and what was
	// later observed (the exit summary) read as two separate things.
	if len(ports) > 0 {
		fmt.Fprintf(os.Stderr, "permitted ports: %s (besides 443 and 80)\n", strings.Join(ports, ", "))
	}
	if len(privHosts) > 0 {
		fmt.Fprintf(os.Stderr, "private-address hosts: %s\n", strings.Join(privHosts, ", "))
	}
	for _, r := range rules {
		fmt.Fprintf(os.Stderr, "request rule: %s (TLS-inspected)\n", r)
	}
	if srv.Deny != nil {
		entries, invalid := srv.Deny.Entries()
		fmt.Fprintf(os.Stderr, "kill switch: %s (%d hosts", srv.Deny.Path(), len(entries))
		if invalid > 0 {
			fmt.Fprintf(os.Stderr, ", %d invalid lines ignored", invalid)
		}
		fmt.Fprintln(os.Stderr, "; edit it to cut a host off mid-run)")
	}
	if *allowPrivate {
		fmt.Fprintln(os.Stderr,
			"WARNING: --allow-private permits private and link-local destinations for every host, "+
				"including the cloud metadata endpoint.")
	}
	for _, h := range list.Rules() {
		bare := strings.TrimPrefix(h, ".")
		rule, ruled := list.RuleFor(bare)
		if k := proxy.RelayKind(h); k != "" && proxy.RelaysOnGet(h) {
			fmt.Fprintf(os.Stderr, "WARNING: %s (%s) relays on a plain GET: it can store data or fetch "+
				"another host, so no --rule makes it download-only. Allowing it opens a route to the "+
				"wider internet and a message board between agents.\n", h, k)
		} else if k != "" && !ruled {
			fmt.Fprintf(os.Stderr, "note: %s is a %s — it can store what it is sent or fetch onward. "+
				"Consider --rule %s so only downloads are allowed.\n", h, k, proxy.SuggestedRule(h))
		}
		if proxy.IsCodeHost(h) && (!ruled || !rule.HasPaths()) {
			fmt.Fprintf(os.Stderr, "note: %s serves anyone's content. A download-only rule still lets a "+
				"payload staged in someone else's repository in; scope it to your own with a path, "+
				"e.g. --rule %s:GET,HEAD:/your-org/\n", h, h)
		}
		if proxy.IsModelAPI(h) {
			fmt.Fprintf(os.Stderr, "note: %s is a model API. Whatever the program reads can be sent there "+
				"in a prompt; the proxy cannot stop that. Keep secrets out of the sandbox if you do not "+
				"trust the model.\n", h)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}

	trips := srv.Trips()
	if srv.Canaries != nil {
		if len(srv.Canaries.Credentials) == 0 {
			fmt.Fprintf(os.Stderr, "\nCANARY — run %s\n  No canaries planted: all groups were skipped for passed credentials or config paths.\n", srv.Canaries.RunID)
		} else {
			printCanarySummary(os.Stderr, srv.Canaries.RunID, trips)
		}
	}
	printSummary(os.Stderr, srv.Stats(), list, *observe, srv.StatsOverflow())
	if srv.Events != nil {
		// The summary is read as a complete account of the run. It is not, if
		// the log could not be written, and that has to be said here rather
		// than left for someone to discover while reading the file.
		if n := srv.Events.Dropped(); n > 0 {
			fmt.Fprintf(os.Stderr, "\nEVENTS — %d event(s) could not be written to %s: the log is incomplete\n", n, *eventsPath)
		}
	}
	if len(trips) > 0 {
		return 3
	}
	return 0
}

func printCanarySummary(w io.Writer, runID string, trips []proxy.Trip) {
	fmt.Fprintf(w, "\nCANARY — run %s\n", runID)
	if len(trips) == 0 {
		fmt.Fprintln(w, "  No canary was used or sent through the proxy. This does not show the run was clean:")
		fmt.Fprintln(w, "  Unruled HTTPS hides its contents; later bytes in large bodies are not scanned; direct proxy bypass is blocked by the sandbox, but model prompts and unplanted secrets remain blind spots.")
		return
	}
	for _, t := range trips {
		fmt.Fprintf(w, "  %s  %s  %s %s:%s  — see CANARY TRIPPED in the proxy log\n",
			strings.ToUpper(t.Confidence), events.Clean(t.Label, 40), events.Clean(t.Method, 20),
			events.Clean(t.Host, 253), events.Clean(t.Port, 10))
	}
}

// writeBundle writes system roots plus the inspection CA. Tools that read a
// single bundle (OpenSSL's SSL_CERT_FILE, curl, git, Python requests) replace
// their trust store with it, so it must still contain the real roots, or every
// host that is NOT inspected would fail to verify.
func writeBundle(path string, ca []byte) error {
	var b []byte
	for _, p := range append([]string{os.Getenv("SSL_CERT_FILE")}, systemBundles...) {
		if p == "" {
			continue
		}
		if data, err := os.ReadFile(p); err == nil {
			b = append(b, data...)
			b = append(b, '\n')
			if p != os.Getenv("SSL_CERT_FILE") {
				break
			}
		}
	}
	b = append(b, ca...)
	return proxy.WriteFileNoFollow(path, b, 0o644)
}

// printSummary reports what was contacted, per host:port, and ends with an
// allow-list a reader can paste. Port is kept separate from host because
// enforcing a non-web port needs --allow-port: merging them hid that.
func printSummary(w io.Writer, stats []proxy.Stat, list *proxy.AllowList, observe bool, overflow int) {
	if len(stats) == 0 {
		fmt.Fprintln(w, "\nno destinations were contacted")
		return
	}
	// Hostnames arrive from the sandboxed program. Anything that is not a
	// well-formed hostname and port is left out of the summary entirely: it
	// would otherwise reach the terminal (escape sequences) and the ALLOW line
	// a user pastes into a shell (command substitution).
	valid := stats[:0:0]
	invalid := 0
	var aggregate *proxy.Stat
	for i, s := range stats {
		if s.Host == proxy.AggregateHost {
			// The bucket every destination past the row limit falls into. It is
			// not a host name, so it has to be taken out before the filter or
			// the counts for everything it stands for vanish from the one place
			// anyone reads them.
			aggregate = &stats[i]
			continue
		}
		if proxy.ValidHostname(s.Host) && proxy.ValidPort(s.Port) {
			valid = append(valid, s)
		} else {
			invalid++
		}
	}
	stats = valid
	if len(stats) == 0 {
		fmt.Fprintf(w, "\nno valid destinations were contacted (%d malformed names omitted)\n", invalid)
		return
	}
	fmt.Fprintln(w, "\nDestinations contacted:")
	hw := len("host:port")
	for _, s := range stats {
		hw = max(hw, len(s.Host)+1+len(s.Port))
	}
	fmt.Fprintf(w, "  %-*s %6s %6s %10s %10s  %s\n", hw, "host:port", "conns", "denied", "sent", "received", "notes")
	var hosts []string
	extraPorts := map[string]bool{}
	seenHost := map[string]bool{}
	var relays []string
	for _, s := range stats {
		var notes []string
		if k := proxy.RelayKind(s.Host); k != "" {
			notes = append(notes, "store/forward: "+k)
			if !seenHost[s.Host] {
				relays = append(relays, s.Host)
			}
		}
		if proxy.IsModelAPI(s.Host) {
			notes = append(notes, "model API")
		}
		if s.Sent >= proxy.UploadWarnBytes {
			notes = append(notes, "HEAVY UPLOAD")
		}
		if s.Writes > 0 {
			notes = append(notes, fmt.Sprintf("SENT DATA ×%d", s.Writes))
		}
		if s.CanaryTrips > 0 {
			notes = append(notes, fmt.Sprintf("CANARY TRIPPED ×%d", s.CanaryTrips))
		}
		if len(s.Methods) > 0 {
			var ms []string
			for m, n := range s.Methods {
				ms = append(ms, fmt.Sprintf("%s×%d", m, n))
			}
			sort.Strings(ms)
			notes = append(notes, strings.Join(ms, " "))
		}
		fmt.Fprintf(w, "  %-*s %6d %6d %10s %10s  %s\n", hw, s.Host+":"+s.Port, s.Conns, s.Denied,
			proxy.HumanBytes(s.Sent), proxy.HumanBytes(s.Received), strings.Join(notes, "; "))
		if !seenHost[s.Host] && s.CanaryTrips == 0 {
			seenHost[s.Host] = true
			hosts = append(hosts, s.Host)
		}
		if s.Port != "443" && s.Port != "80" {
			extraPorts[s.Port] = true
		}
	}
	if aggregate != nil {
		note := "counted together"
		if overflow > 0 {
			note = fmt.Sprintf("counted together: %d further destinations past the row limit", overflow)
		}
		fmt.Fprintf(w, "  %-*s %6d %6d %10s %10s  %s\n", hw, aggregate.Host+":"+aggregate.Port,
			aggregate.Conns, aggregate.Denied,
			proxy.HumanBytes(aggregate.Sent), proxy.HumanBytes(aggregate.Received), note)
	}
	if invalid > 0 {
		fmt.Fprintf(w, "  (%d destinations with malformed host names or ports omitted)\n", invalid)
	}
	printRelayAttempts(w, stats)

	if !observe {
		return
	}
	var flags []string
	for _, h := range hosts {
		flags = append(flags, "--allow "+h)
	}
	var portList []string
	for p := range extraPorts {
		portList = append(portList, p)
	}
	sort.Strings(portList)
	if len(portList) > 0 {
		for _, p := range append([]string{"443", "80"}, portList...) {
			flags = append(flags, "--allow-port "+p)
		}
	}
	codeHosts := false
	var getRelays []string
	for _, h := range relays {
		r := proxy.SuggestedRule(h)
		if r == "" {
			getRelays = append(getRelays, h)
			continue
		}
		flags = append(flags, "--rule "+r)
		codeHosts = codeHosts || proxy.IsCodeHost(h)
	}
	fmt.Fprintln(w, "\nReview these. To enforce exactly what was seen, run the sandbox with:")
	// Single-quoted, so the shell expands nothing in it when pasted. Every
	// host passed ValidHostname above, so none can contain a quote.
	fmt.Fprintf(w, "  ALLOW='%s'\n", strings.Join(flags, " "))
	if len(portList) > 0 {
		fmt.Fprintln(w, "  (--allow-port applies to every allowed host, not only the one that used it.)")
	}
	if len(relays) > 0 {
		fmt.Fprintln(w, "  The --rule entries make store-or-forward hosts download-only; drop one if the program "+
			"genuinely needs to publish there.")
	}
	if len(getRelays) > 0 {
		fmt.Fprintf(w, "  %s relay on a plain GET, so no --rule is suggested for them: remove them from the "+
			"list unless the program genuinely needs them, and know that leaving them in opens a route "+
			"onward.\n", strings.Join(getRelays, ", "))
	}
	if codeHosts {
		fmt.Fprintln(w, "  Replace /YOUR-ORG/ with the repository paths the program really needs. A code host "+
			"serves anyone's content, so download-only is not enough; left unedited, the placeholder "+
			"matches nothing and every request to that host is refused.")
	}
}

// printRelayAttempts lists every store-or-forward host the program tried,
// allowed or not. A refused connection to a URL shortener or fetcher is not
// noise: it is the program looking for a way out or a place to leave a
// message — the first step of the 2026 swarm incidents (SWM-007).
func printRelayAttempts(w io.Writer, stats []proxy.Stat) {
	var rows []proxy.Stat
	for _, s := range stats {
		if s.Relay != "" {
			rows = append(rows, s)
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].RelaysOnGet != rows[j].RelaysOnGet {
			return rows[i].RelaysOnGet
		}
		return rows[i].Denied > rows[j].Denied
	})
	fmt.Fprintln(w, "\nStore-or-forward hosts the program tried (relays, message boards, ways onward):")
	for _, s := range rows {
		status := "reached"
		switch {
		case s.Denied >= s.Conns:
			status = "REFUSED"
		case s.Denied > 0:
			status = fmt.Sprintf("reached, %d refused", s.Denied)
		}
		mark := " "
		if s.RelaysOnGet {
			mark = "!"
		}
		fmt.Fprintf(w, "  %s %-32s %-22s %s\n", mark, s.Host+":"+s.Port, fmt.Sprintf("%d× %s", s.Conns, status), s.Relay)
	}
	fmt.Fprintln(w, "  ! relays on a plain GET: no --rule contains it.")
	fmt.Fprintln(w, "  A program that was refused and tried another relay is probing for a route; see "+
		"sandboxcheckr console for the order of attempts.")
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
