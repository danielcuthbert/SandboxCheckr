package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// dialTimeout bounds an upstream connection attempt.
const dialTimeout = 10 * time.Second

// lookupTimeout bounds a host-side resolution. A stalled resolver must not be
// able to pin a handler goroutine on the sandbox's behalf: the confined
// program chooses the names.
const lookupTimeout = 5 * time.Second

// headerReadTimeout bounds reading the first request line and headers from an
// accepted connection. Once we are relaying there is deliberately no idle
// deadline: an agent streams a model response for minutes over one tunnel, and
// cutting it would break the work, so the concurrency bound below is what
// limits how many goroutines a program can hold open.
const headerReadTimeout = 30 * time.Second

// maxConns and maxDNSConns bound concurrent handlers. The proxy and its DNS
// relay are reachable from inside the sandbox by design (that is how egress is
// mediated), so an unbounded accept loop is a resource limit the confined
// program controls. Beyond the bound a connection is closed with a line in the
// log rather than silently dropped.
const (
	maxConns    = 1024
	maxDNSConns = 64
)

// maxStats, maxTrips and maxLabels bound the host-side bookkeeping a confined
// program can drive. Denied destinations are counted too, so without a cap a
// loop over invented hostnames allocates a Stat (and its Methods map) each in
// the unconfined proxy.
const (
	maxStats    = 4096
	maxTrips    = 256
	maxLabels   = 16
	overflowKey = "*overflow*"
)

// lookupResolver resolves destination names on the host side. A net.Resolver
// is used rather than the package-level LookupIP so the call can carry a
// context deadline: the confined program chooses the name, so it must not be
// able to pin a handler goroutine by naming one the resolver never answers for.
var lookupResolver = new(net.Resolver)

// UploadWarnBytes is the bytes-sent-upstream level at which a host is flagged.
// Package installs, API calls and git fetches send little upstream; a host
// receiving megabytes is being written to — an upload, a message board, or
// data leaving. Counted without decrypting anything.
const UploadWarnBytes = 1 << 20

// Server is an allow-listing HTTP/CONNECT proxy bound to loopback.
type Server struct {
	Allow *AllowList
	// Observe permits destinations outside the allow-list and records them.
	// Canary credentials and the live deny file still cause refusals.
	//
	// This is how you build an allow-list from evidence rather than guesswork.
	// Nobody knows offhand which hosts a toolchain contacts, and a list written
	// from memory is either too tight (the program breaks and the user disables
	// the proxy) or too loose (it permits things nobody examined). Run once in
	// observe mode, read the log, then enforce.
	Observe bool
	// Log receives one line per decision.
	Log io.Writer
	// CA, when set, is used to inspect HTTPS for hosts with a HostRule. It is
	// required whenever Allow has HostRules.
	CA *CA
	// UpstreamRoots overrides the roots used to verify real servers when
	// inspecting. Nil means the system roots; tests set it.
	UpstreamRoots *x509.CertPool
	// Events, when set, receives a structured record of every decision and
	// visible request, for sandboxcheckr console. Nil records nothing.
	Events *events.Writer
	// Deny, when set, is a live kill switch: hosts in it are refused even if
	// allow-listed, and open connections to them are cut when it changes.
	Deny              *DenyFile
	Canaries          *canary.Set
	TripFile          string
	CanaryKillPIDFile string

	mu          sync.Mutex
	stats       map[string]*Stat
	trips       []Trip
	tripOver    int
	statOver    int
	clsMu       sync.Mutex
	cls         map[string]classification
	denyErr     string
	matcherOnce sync.Once
	matcher     *canary.Matcher
	ln          net.Listener
	// dnsLn carries relayed DNS queries from the sandbox's bridge, when
	// ListenDNS has bound it.
	dnsLn net.Listener
	// Resolver is the host-side resolver the DNS relay forwards allowed
	// queries to, as host:port speaking DNS over TCP. Empty means the first
	// nameserver in /etc/resolv.conf, parsed once.
	Resolver     string
	resolverOnce sync.Once
	resolverHost string
	resolverErr  error
	// live holds open tunnels, so a deny-file edit can cut them.
	live map[net.Conn]string
}

// Stat is what the proxy saw for one host:port.
type Stat struct {
	Host string
	Port string
	// Conns is the number of connections (or requests, for inspected hosts).
	Conns int
	// Denied counts refusals, including rule refusals on an allowed host.
	Denied       int
	CanaryTrips  int
	CanaryLabels []string
	// Sent and Received are bytes from the client to the host and back.
	Sent, Received int64
	// Methods counts request methods seen on inspected hosts.
	Methods map[string]int
	// Writes counts requests that send data (POST, PUT, PATCH, WebDAV and
	// the like) that were allowed through. Only requests the proxy can see
	// are counted: plain HTTP and TLS-inspected (--rule) hosts.
	Writes int
	// Relay is the store-or-forward class of Host, if it has one.
	Relay string
	// RelaysOnGet marks a host where a GET alone can store data or fetch
	// another host, so no method rule contains it.
	RelaysOnGet bool
}

type Trip struct {
	RunID, Label, Confidence, Host, Port, Method string
}

func (s *Server) Trips() []Trip {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Trip(nil), s.trips...)
}

// TripOverflow reports how many trips were dropped because Trips had reached
// its bound. A confined program can trip a canary as often as it likes; the
// bound keeps the host-side list from growing at its pace, and this is how a
// reader knows the list is a window rather than the whole story.
func (s *Server) TripOverflow() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tripOver
}

// StatsOverflow reports how many distinct destinations were folded into the
// overflow row rather than given their own Stat.
func (s *Server) StatsOverflow() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statOver
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (s *Server) canaryMatcher() *canary.Matcher {
	if s.Canaries == nil {
		return nil
	}
	s.matcherOnce.Do(func() { s.matcher = canary.NewMatcher(s.Canaries) })
	return s.matcher
}

// trip records a canary use. denied says whether the request was also
// refused: a forwarded external token is a trip without a refusal, and
// counting it as denied would make the exit summary report a forwarded
// connection as blocked.
func (s *Server) trip(c canary.Credential, host, port, method, confidence string, denied bool) {
	t := Trip{RunID: s.Canaries.RunID, Label: c.Label, Confidence: confidence, Host: host, Port: port, Method: method}
	s.count(host, port, func(st *Stat) {
		if denied {
			st.Denied++
		}
		st.CanaryTrips++
		// The same token trips on every request to its host; the label list is
		// a set with a bound, not a history.
		if len(st.CanaryLabels) < maxLabels && !containsString(st.CanaryLabels, c.Label) {
			st.CanaryLabels = append(st.CanaryLabels, c.Label)
		}
	})
	s.mu.Lock()
	if len(s.trips) < maxTrips {
		s.trips = append(s.trips, t)
	} else {
		s.tripOver++
	}
	s.mu.Unlock()
	s.logf("CANARY TRIPPED [%s] %s %s:%s  %s (run %s)", confidence, method, host, port, c.Label, t.RunID)
	s.event(events.Event{Kind: events.KindCanary, Decision: events.Deny, Host: host, Port: port,
		Method: method, Canary: c.Label, RunID: t.RunID, Confidence: confidence})
	if s.TripFile != "" {
		if f, err := OpenAppendNoFollow(s.TripFile, 0o600); err == nil {
			_, _ = fmt.Fprintln(f, t.RunID, confidence, c.Label)
			_ = f.Close()
		}
	}
	if confidence == "high" && s.CanaryKillPIDFile != "" {
		if b, err := os.ReadFile(s.CanaryKillPIDFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
				}
			}
		}
	}
}

// scanVisible checks request metadata and at most 64 KiB of body. The bytes
// read for inspection are put back so an allowed request is not changed.
func (s *Server) scanVisible(req *http.Request, host, port string, client io.Writer) (canary.Credential, bool) {
	if s.Canaries == nil {
		return canary.Credential{}, false
	}
	m := s.canaryMatcher()
	var visible bytes.Buffer
	// One allocation for the whole visible view rather than a regrowth per
	// header: this runs for every request the proxy can read.
	size := len(req.Method) + len(req.Host) + 2
	if req.URL != nil {
		size += len(req.URL.Path) + len(req.URL.RawQuery) + len(req.URL.Host) + len(req.URL.Scheme)
	}
	for k, values := range req.Header {
		size += len(k)
		for _, v := range values {
			size += len(v)
		}
	}
	visible.Grow(size)
	visible.WriteString(req.Method)
	visible.WriteByte(' ')
	visible.WriteString(req.URL.String())
	visible.WriteString(req.Host)
	for k, values := range req.Header {
		visible.WriteString(k)
		for _, v := range values {
			visible.WriteString(v)
		}
	}
	if req.Body != nil {
		if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
			_, _ = io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n")
			req.Header.Del("Expect")
		}
		b, _ := io.ReadAll(io.LimitReader(req.Body, 64<<10))
		visible.Write(b)
		req.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(b), req.Body), closer: req.Body}
	}
	if c, ok := m.Bytes(visible.Bytes()); ok {
		if c.External && c.Host == host {
			// A request aimed at the token's own host is the token's
			// intended use, not a leak of it: leave it to the connect gate,
			// which forwards it.
			return c, false
		}
		confidence := "high"
		if c.Host == host && !c.External {
			confidence = "medium"
		}
		s.trip(c, host, port, req.Method, confidence, true)
		return c, true
	}
	return canary.Credential{}, false
}

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (r *replayBody) Close() error { return r.closer.Close() }

// readOnlyMethods are the methods that do not ask a server to store anything.
var readOnlyMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// noteWrite counts an allowed data-sending request and warns on the first one
// per host. Size does not matter: the .env in ProjectDiscovery's demo was 415
// bytes, far below any volume threshold, so the first write to a host is
// itself the signal.
func (s *Server) noteWrite(host, port, method, path string) {
	if readOnlyMethods[method] {
		return
	}
	first := false
	s.count(host, port, func(st *Stat) {
		st.Writes++
		first = st.Writes == 1
	})
	if first {
		s.logf("WARN  %s %s%s  first request sending data to this host — check that the program "+
			"is meant to publish here", method, host, path)
		s.event(events.Event{Kind: events.KindWrite, Host: host, Port: port, Method: method, Path: path})
	}
}

// NewServer constructs a proxy.
func NewServer(allow *AllowList, observe bool, logw io.Writer) *Server {
	return &Server{Allow: allow, Observe: observe, Log: logw, stats: map[string]*Stat{},
		cls: map[string]classification{}, live: map[net.Conn]string{}}
}

// Listen binds to loopback. Binding to 127.0.0.1 rather than all interfaces is
// not a detail: an allow-listing proxy reachable from the network is an open
// relay for anyone who can route to it.
func (s *Server) Listen(port int) (string, error) {
	return s.ListenOn("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

// ListenOn binds to an explicit endpoint: a loopback TCP address, or a unix
// socket path. The unix form exists for sandboxes with no network namespace
// access at all (bubblewrap --unshare-net), where loopback inside the sandbox
// is a different loopback from the host's and only a bind-mounted socket can
// cross the boundary.
func (s *Server) ListenOn(network, addr string) (string, error) {
	if network == "tcp" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return "", err
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("refusing to bind %s: the proxy must listen on loopback only", addr)
		}
	}
	if len(s.Allow.HostRules) > 0 && s.CA == nil {
		return "", fmt.Errorf("request rules (--rule) need an inspection CA; none was configured")
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return "", err
	}
	s.ln = ln
	return ln.Addr().String(), nil
}

// Addr returns the bound address.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Serve accepts connections until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return fmt.Errorf("proxy is not listening")
	}
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
		if s.dnsLn != nil {
			_ = s.dnsLn.Close()
		}
	}()
	if s.Deny != nil {
		go s.watchDeny(ctx)
	}
	if s.dnsLn != nil {
		go s.acceptDNS(ctx)
	}

	conns := make(chan struct{}, maxConns)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		// The proxy is reachable from inside the sandbox by design, so the
		// number of handlers is a limit the confined program would otherwise
		// own. Over the bound the connection is closed and said so in the log:
		// a program that legitimately needs a thousand concurrent connections
		// will see it, and refusing quietly would look like a broken network.
		select {
		case conns <- struct{}{}:
		default:
			s.logf("DENY  (too many concurrent connections; over the %d limit)", maxConns)
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-conns }()
			s.handle(ctx, conn)
		}()
	}
}

// Stats returns what the proxy saw, most-contacted first.
func (s *Server) Stats() []Stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Stat, 0, len(s.stats))
	for _, st := range s.stats {
		c := *st
		c.Methods = map[string]int{}
		for k, v := range st.Methods {
			c.Methods[k] = v
		}
		c.CanaryLabels = append([]string(nil), st.CanaryLabels...)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// AggregateHost labels the row carrying the counts of every destination past
// maxStats. Exported because whoever prints the rows must show it as its own
// line: it is not a host name, and a filter that keeps only well-formed hosts
// would drop the counts of everything it stands for.
const AggregateHost = "many other destinations"

// count updates the bookkeeping for one host:port, creating it on first sight.
// Distinct destinations are bounded because denied names are counted as well
// as allowed ones: without a cap a confined program looping over invented
// hostnames allocates a Stat and its Methods map each, in the unconfined
// proxy. Past maxStats the counts for new destinations fall into one row.
func (s *Server) count(host, port string, f func(*Stat)) {
	// Classification walks the relay and model-API pattern lists. Do it before
	// taking the lock, so building a fresh Stat does not re-enter it.
	c := s.classifyHost(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := host + ":" + port
	st, ok := s.stats[k]
	if !ok {
		if len(s.stats) >= maxStats {
			s.statOver++
			st, ok = s.stats[overflowKey]
			if !ok {
				st = &Stat{Host: AggregateHost, Port: "-", Methods: map[string]int{}}
				s.stats[overflowKey] = st
			}
		} else {
			st = &Stat{Host: host, Port: port, Methods: map[string]int{},
				Relay: c.relay, RelaysOnGet: c.onGet}
			s.stats[k] = st
		}
	}
	f(st)
}

// classification is what the pattern lists say about one host.
type classification struct {
	relay string
	onGet bool
	model bool
}

// classifyHost answers the pattern-list questions about a host once per host.
// The lists run to over a hundred entries and were being walked again for
// every log line, event and decision on the connection.
func (s *Server) classifyHost(host string) classification {
	s.clsMu.Lock()
	c, ok := s.cls[host]
	s.clsMu.Unlock()
	if ok {
		return c
	}
	kind, onGet := classify(host)
	c = classification{relay: kind, onGet: onGet, model: IsModelAPI(host)}
	s.clsMu.Lock()
	if len(s.cls) < maxStats {
		s.cls[host] = c
	}
	s.clsMu.Unlock()
	return c
}

// event records e, filling in what the proxy knows about its host.
func (s *Server) event(e events.Event) {
	if s.Events == nil {
		return
	}
	c := s.classifyHost(e.Host)
	e.Relay = c.relay
	e.Fetcher = c.onGet
	e.ModelAPI = c.model
	if e.RunID == "" && s.Canaries != nil {
		e.RunID = s.Canaries.RunID
	}
	s.Events.Write(e)
}

func (s *Server) logf(format string, args ...any) {
	if s.Log == nil {
		return
	}
	fmt.Fprintf(s.Log, time.Now().Format("15:04:05")+" "+format+"\n", args...)
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	// Bound only the reading of the request line and headers. Once the request
	// has been judged, relaying is deliberately left without an idle deadline:
	// an agent streams a model response for minutes over one connection, and an
	// idle timeout there would break the work the sandbox exists to allow.
	_ = client.SetReadDeadline(time.Now().Add(headerReadTimeout))
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		s.handleConnect(ctx, client, req)
		return
	}
	// Anything already buffered in br beyond this request is deliberately
	// dropped: one request per connection, so a second, unchecked request
	// cannot ride along behind an allowed one.
	s.handlePlain(ctx, client, req)
}

// decide applies the canary gate, the allow-list and the address guard,
// returning the upstream address to dial.
func (s *Server) decide(host, port, method string) (string, bool) {
	s.count(host, port, func(st *Stat) { st.Conns++ })
	note := ""
	c := s.classifyHost(host)
	if c.relay != "" {
		note = "  [can store/forward: " + c.relay + "]"
		if c.onGet {
			note = "  [relays on a plain GET: " + c.relay + "]"
		}
	}
	if c.model {
		note += "  [model API: receives whatever the agent reads]"
	}
	deny := func(why string) (string, bool) {
		s.count(host, port, func(st *Stat) { st.Denied++ })
		s.logf("DENY  %s:%s  (%s)%s", host, port, why, note)
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: why})
		return "", false
	}
	forward := false
	if s.Canaries != nil {
		if c, ok := s.canaryMatcher().Host(host); ok {
			if c.External {
				// A connection to the token's own host is the token's
				// intended use, not a leak of it, so forward it and let the
				// token service alert. The trip is recorded either way.
				forward = true
				s.trip(c, host, port, method, "high", false)
				s.logf("ALLOW %s:%s  [external canary token]", host, port)
				s.event(events.Event{Kind: events.KindConnect, Decision: events.Allow, Host: host, Port: port, Reason: "external canary token (forwarded)"})
			} else {
				s.trip(c, host, port, method, "medium", true)
				s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: "canary credential"})
				return "", false
			}
		}
	}
	if forward {
		// The deny file beats a forwarded token, as it does in the DNS relay.
		if entry, hit := s.Deny.Match(host); hit {
			return deny("in deny file (" + entry + ")")
		}
		// Vetted like every other destination. The token host sits outside the
		// allow-list by design, so nothing else has checked where it resolves:
		// dialling the name would let a token host that points at loopback or
		// the metadata endpoint have this unconfined process fetch it for the
		// sandbox. --allow-private-host covers a self-hosted token service.
		addrs, why, ok := s.resolveAndVet(host, port)
		if !ok {
			return deny(why)
		}
		return addrs, true
	}
	// The kill switch comes first and holds in observe mode too: it exists to
	// take access away, so nothing else may give it back.
	if entry, hit := s.Deny.Match(host); hit {
		return deny("in deny file (" + entry + ")")
	}

	permitted := s.Allow.PermitsHost(host)
	if !permitted && !s.Observe {
		return deny("not in allow-list")
	}
	// Restrict ports even for allowed hosts. Allowing "github.com" is meant to
	// allow HTTPS to it, not SSH on 22 or SMTP on 25 — a CONNECT tunnel carries
	// any protocol, so an unrestricted port turns one allowed name into a
	// general-purpose relay.
	portOK := s.Allow.PermitsPort(port)
	if !portOK && !s.Observe {
		return deny("port not permitted; use --allow-port")
	}
	if !portOK {
		// In observe mode a non-web port is recorded as would-be-denied, so the
		// evidence includes the ports a program needs as well as the hosts.
		permitted = false
	}

	addrs, why, ok := s.resolveAndVet(host, port)
	if !ok {
		return deny(why)
	}

	if permitted {
		s.logf("ALLOW %s:%s%s", host, port, note)
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Allow, Host: host, Port: port})
	} else {
		s.logf("OBSERVE %s:%s  (would be DENIED when enforcing)%s", host, port, note)
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Observe, Host: host, Port: port,
			Reason: "not in allow-list"})
	}
	return addrs, true
}

// resolveAndVet resolves host on the host side and refuses it unless every
// address passes the private-address guard, returning the literals to dial.
// Resolution is bounded: the confined program chooses the name, and a resolver
// that never answers must not pin a handler goroutine here.
func (s *Server) resolveAndVet(host, port string) (addrs string, why string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	ips, err := lookupResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return "", "resolution failed", false
	}
	for _, ip := range ips {
		if err := s.Allow.CheckHostAddr(host, ip); err != nil {
			return "", err.Error(), false
		}
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = net.JoinHostPort(ip.String(), port)
	}
	return strings.Join(out, ","), "", true
}

// dialAny connects to the first reachable of the comma-separated addresses
// decide returned. Only addresses that passed the private-address guard are
// ever in the list, so falling back cannot reach anything the guard refused.
func dialAny(ctx context.Context, addrs string) (net.Conn, error) {
	var last error
	for _, a := range strings.Split(addrs, ",") {
		c, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", a)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// handleConnect tunnels HTTPS.
//
// For hosts with no request rule, the tunnel is passed through byte-for-byte
// and TLS is never terminated: the proxy sees only the CONNECT hostname. For a
// host WITH a rule, TLS is terminated with a certificate from the scoped local
// CA, each request is checked against the rule, and allowed requests are
// re-encrypted to the real server (whose certificate is verified normally).
func (s *Server) handleConnect(ctx context.Context, client net.Conn, req *http.Request) {
	host, port, err := SplitHostPort(req.Host, "443")
	if err != nil {
		writeStatus(client, http.StatusBadRequest, err.Error())
		return
	}
	if c, ok := s.scanVisible(req, host, port, client); ok {
		s.count(host, port, func(st *Stat) { st.Conns++ })
		reason := "canary credential"
		if c.External {
			reason = "external canary token"
		}
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: reason})
		writeStatus(client, http.StatusForbidden, "SandboxCheckr proxy: canary credential tripped")
		return
	}

	upstream, ok := s.decide(host, port, "CONNECT")
	if !ok {
		writeStatus(client, http.StatusForbidden,
			fmt.Sprintf("SandboxCheckr proxy: %s:%s is not permitted", host, port))
		return
	}

	s.track(client, host)
	defer s.untrack(client)

	if rule, ok := s.Allow.RuleFor(host); ok && s.CA != nil {
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		s.inspect(ctx, client, host, port, upstream, rule)
		return
	}

	server, err := dialAny(ctx, upstream)
	if err != nil {
		writeStatus(client, http.StatusBadGateway, err.Error())
		return
	}
	defer server.Close()
	s.track(server, host)
	defer s.untrack(server)

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	sent, recv := pipe(client, server)
	s.finish(host, port, sent, recv)
}

// inspect terminates TLS from the client and enforces rule on every request.
func (s *Server) inspect(ctx context.Context, client net.Conn, host, port, upstream string, rule HostRule) {
	leaf, err := s.CA.leaf(host)
	if err != nil {
		s.logf("DENY  %s:%s  (cannot inspect: %v)", host, port, err)
		return
	}
	tlsClient := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		// HTTP/1.1 only: requests are checked one at a time on the stream.
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.HandshakeContext(ctx); err != nil {
		s.logf("DENY  %s:%s  (client rejected the inspection certificate — is the CA trusted in the sandbox? %v)", host, port, err)
		return
	}
	defer tlsClient.Close()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialAny(ctx, upstream)
		},
		// The real server's certificate is verified against the system roots
		// under its real name, exactly as the client would have.
		TLSClientConfig:   &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: s.UpstreamRoots},
		ForceAttemptHTTP2: false,
		Proxy:             nil,
	}
	defer transport.CloseIdleConnections()

	cr := &countingReader{r: tlsClient}
	br := bufio.NewReader(cr)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			s.finish(host, port, cr.n, 0)
			return
		}
		s.count(host, port, func(st *Stat) { st.Methods[req.Method]++ })
		if c, ok := s.scanVisible(req, host, port, tlsClient); ok {
			reason := "canary credential"
			if c.External {
				reason = "external canary token"
			}
			s.event(events.Event{Kind: events.KindRequest, Decision: events.Deny, Host: host, Port: port,
				Method: req.Method, Reason: reason})
			writeStatus(tlsClient, http.StatusForbidden, "SandboxCheckr proxy: canary credential tripped")
			return
		}
		if ok, why := rule.Permits(req); !ok {
			s.count(host, port, func(st *Stat) { st.Denied++ })
			s.logf("DENY  %s %s%s  (rule %s: %s)", req.Method, host, req.URL.Path, rule, why)
			s.event(events.Event{Kind: events.KindRequest, Decision: events.Deny, Host: host, Port: port,
				Method: req.Method, Path: requestTarget(req.URL), Reason: "rule " + rule.String() + ": " + why})
			_, _ = io.Copy(io.Discard, req.Body)
			writeStatus(tlsClient, http.StatusForbidden,
				fmt.Sprintf("SandboxCheckr proxy: %s %s is not permitted on %s (%s)", req.Method, req.URL.Path, host, why))
			continue
		}
		s.logf("ALLOW %s %s%s", req.Method, host, req.URL.Path)
		s.event(events.Event{Kind: events.KindRequest, Decision: events.Allow, Host: host, Port: port,
			Method: req.Method, Path: requestTarget(req.URL)})
		s.noteWrite(host, port, req.Method, req.URL.Path)

		req.URL.Scheme = "https"
		req.URL.Host = net.JoinHostPort(host, port)
		req.RequestURI = ""
		resp, err := transport.RoundTrip(req.WithContext(ctx))
		if err != nil {
			writeStatus(tlsClient, http.StatusBadGateway, err.Error())
			return
		}
		rc := &countingWriter{w: tlsClient}
		err = resp.Write(rc)
		resp.Body.Close()
		s.count(host, port, func(st *Stat) { st.Received += rc.n })
		if err != nil || resp.Close || req.Close {
			s.finish(host, port, cr.n, 0)
			return
		}
	}
}

// handlePlain proxies a non-CONNECT (plain HTTP) request. Request rules apply
// here directly, since the request is visible without any interception.
func (s *Server) handlePlain(ctx context.Context, client net.Conn, req *http.Request) {
	target := req.URL
	if target == nil || target.Host == "" {
		// A proxy receives absolute-form request URIs. A relative one means the
		// client is not talking to us as a proxy.
		writeStatus(client, http.StatusBadRequest, "expected an absolute-form request URI")
		return
	}
	host, port, err := SplitHostPort(target.Host, "80")
	if err != nil {
		writeStatus(client, http.StatusBadRequest, err.Error())
		return
	}

	if c, ok := s.scanVisible(req, host, port, client); ok {
		s.count(host, port, func(st *Stat) { st.Conns++; st.Methods[req.Method]++ })
		reason := "canary credential"
		if c.External {
			reason = "external canary token"
		}
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: reason})
		writeStatus(client, http.StatusForbidden, "SandboxCheckr proxy: canary credential tripped")
		return
	}
	upstream, ok := s.decide(host, port, req.Method)
	if !ok {
		writeStatus(client, http.StatusForbidden,
			fmt.Sprintf("SandboxCheckr proxy: %s:%s is not permitted", host, port))
		return
	}
	s.count(host, port, func(st *Stat) { st.Methods[req.Method]++ })
	if rule, ok := s.Allow.RuleFor(host); ok {
		if ok, why := rule.Permits(req); !ok {
			s.count(host, port, func(st *Stat) { st.Denied++ })
			s.logf("DENY  %s %s%s  (rule %s: %s)", req.Method, host, target.Path, rule, why)
			s.event(events.Event{Kind: events.KindRequest, Decision: events.Deny, Host: host, Port: port,
				Method: req.Method, Path: requestTarget(target), Reason: "rule " + rule.String() + ": " + why})
			writeStatus(client, http.StatusForbidden,
				fmt.Sprintf("SandboxCheckr proxy: %s %s is not permitted on %s (%s)", req.Method, target.Path, host, why))
			return
		}
	}

	s.event(events.Event{Kind: events.KindRequest, Decision: events.Allow, Host: host, Port: port,
		Method: req.Method, Path: requestTarget(target)})
	s.noteWrite(host, port, req.Method, target.Path)

	server, err := dialAny(ctx, upstream)
	if err != nil {
		writeStatus(client, http.StatusBadGateway, err.Error())
		return
	}
	defer server.Close()

	// Forward in origin form, preserving the Host header so virtual hosting
	// still works.
	outReq := *req
	outReq.URL = &url.URL{Path: target.Path, RawQuery: target.RawQuery}
	outReq.Host = target.Host
	// One request per connection: ask the server to close after replying, so
	// the copy below ends with this response.
	outReq.Close = true
	cw := &countingWriter{w: server}
	if err := outReq.Write(cw); err != nil {
		// Count what was sent even when the server hung up part-way: an
		// upload that was cut short is still an upload.
		s.finish(host, port, cw.n, 0)
		return
	}
	n, _ := io.Copy(client, server)
	s.finish(host, port, cw.n, n)
}

// finish records byte counts for a connection and flags heavy upload.
func (s *Server) finish(host, port string, sent, recv int64) {
	var before, after int64
	s.count(host, port, func(st *Stat) {
		before = st.Sent
		st.Sent += sent
		st.Received += recv
		after = st.Sent
	})
	if sent > 0 || recv > 0 {
		s.event(events.Event{Kind: events.KindClose, Host: host, Port: port, Sent: sent, Recv: recv})
	}
	if before < UploadWarnBytes && after >= UploadWarnBytes {
		s.event(events.Event{Kind: events.KindUpload, Host: host, Port: port, Sent: after})
		s.logf("WARN  %s:%s  has now received %s from the sandbox — far more than downloads, API "+
			"calls or git fetches send. Something is being uploaded to it.", host, port, HumanBytes(after))
	}
}

// ListenDNS binds a second unix socket that carries DNS queries relayed by
// the sandbox's bridge. It must be called before Serve.
func (s *Server) ListenDNS(path string) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	s.dnsLn = ln
	return nil
}

// acceptDNS serves the DNS relay socket until the context is cancelled. The
// bridge keeps one connection for the run's lifetime, so the bound is generous
// for it and a limit on anything else inside the sandbox that opens the socket
// directly, which it can: the private directory is bind-mounted in.
func (s *Server) acceptDNS(ctx context.Context) {
	conns := make(chan struct{}, maxDNSConns)
	for {
		c, err := s.dnsLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		select {
		case conns <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-conns }()
			s.handleDNS(ctx, c)
		}()
	}
}

// frameReadTimeout bounds reading one framed query from a relay connection.
// The connection itself stays open between queries for the run's lifetime, so
// the deadline covers a frame in progress rather than the idle gap.
const frameReadTimeout = 30 * time.Second

// handleDNS serves one bridge relay connection: a sequence of framed queries,
// one response each, in order. The framing is a 4-byte big-endian length plus
// the raw DNS message — the bridge speaks it, nothing else sees the socket.
func (s *Server) handleDNS(ctx context.Context, c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var lenBuf [4]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(frameReadTimeout))
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 || n > 65535 {
			return
		}
		query := make([]byte, n)
		_ = c.SetReadDeadline(time.Now().Add(frameReadTimeout))
		if _, err := io.ReadFull(br, query); err != nil {
			return
		}
		// Answering can take as long as the resolver allows, so the deadline is
		// not held across the gate or the relay to the host resolver.
		_ = c.SetReadDeadline(time.Time{})
		resp := s.answerDNS(ctx, query)
		out := make([]byte, 4+len(resp))
		binary.BigEndian.PutUint32(out, uint32(len(resp)))
		copy(out[4:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// answerDNS gates one query and, for allowed names, relays it to the
// host-side resolver over TCP. Resolution follows the same policy as
// connections — canary, kill switch, allow-list — because a query name is
// itself information leaving the sandbox, and because a resolution is only
// useful when the connection it enables could be allowed anyway. The
// connection gate still applies afterwards: resolving a name permits nothing.
func (s *Server) answerDNS(ctx context.Context, query []byte) []byte {
	name, qtype, ok := dnsQuestion(query)
	if !ok {
		// Judged, but invisible unless it is logged: a query the gate cannot
		// parse is still traffic the program sent, so record the refusal.
		s.dnsEvent("", "", events.Deny, "unparseable query")
		return dnsError(query, dnsRCODEServFail)
	}
	name = strings.TrimSuffix(name, ".")
	forward := false
	if s.Canaries != nil {
		if c, ok := s.canaryMatcher().Host(name); ok {
			if c.External {
				// An external token only alerts when the lookup reaches the
				// token service's own nameserver, so forward the query and
				// answer normally. The trip is recorded either way.
				forward = true
				s.trip(c, name, "53", "DNS", "high", false)
				s.dnsEvent(name, qtype, events.Allow, "external canary token (forwarded)")
			} else {
				s.trip(c, name, "53", "DNS", "medium", true)
				s.dnsEvent(name, qtype, events.Deny, "canary credential")
				return dnsError(query, dnsRCODERefused)
			}
		}
	}
	if s.Deny != nil {
		if entry, hit := s.Deny.Match(name); hit {
			s.dnsEvent(name, qtype, events.Deny, "in deny file ("+entry+")")
			return dnsError(query, dnsRCODERefused)
		}
	}
	observe := false
	if !forward && !s.Allow.PermitsHost(name) {
		if !s.Observe {
			s.dnsEvent(name, qtype, events.Deny, "not in allow-list")
			return dnsError(query, dnsRCODERefused)
		}
		observe = true
	}
	resp, err := s.resolveDNS(ctx, query)
	if err != nil {
		s.logf("DNS   %s (%s)  (relay failed: %v)", name, qtype, err)
		s.dnsEvent(name, qtype, events.Deny, "resolution failed")
		return dnsError(query, dnsRCODEServFail)
	}
	if observe {
		s.logf("DNS   %s (%s)  (would be DENIED when enforcing)", name, qtype)
		s.dnsEvent(name, qtype, events.Observe, "not in allow-list")
	} else if forward {
		s.logf("DNS   %s (%s)  (external canary token)", name, qtype)
	} else {
		s.logf("DNS   %s (%s)", name, qtype)
		s.dnsEvent(name, qtype, events.Allow, "")
	}
	return resp
}

// dnsEvent records one resolution. It stays out of the connection stats: a
// lookup is not a connection, and the summaries count connections.
func (s *Server) dnsEvent(host, qtype, decision, reason string) {
	s.event(events.Event{Kind: events.KindDns, Decision: decision, Host: host,
		Port: "53", Method: qtype, Reason: reason})
}

// resolveDNS forwards the raw query to the host-side resolver over TCP
// (RFC 7766): two-byte length prefix in, the same out. The resolver is
// reached from the host, where it lives; the sandbox never sees an address.
func (s *Server) resolveDNS(ctx context.Context, query []byte) ([]byte, error) {
	resolver, err := s.relayResolver()
	if err != nil {
		return nil, err
	}
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", resolver)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// relayResolver returns the resolver to relay to: the Server's explicit
// override, else the first nameserver in /etc/resolv.conf, parsed once.
func (s *Server) relayResolver() (string, error) {
	if s.Resolver != "" {
		return s.Resolver, nil
	}
	s.resolverOnce.Do(func() {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			s.resolverErr = err
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if ns, found := strings.CutPrefix(line, "nameserver "); found {
				ns = strings.TrimSpace(ns)
				if ip := net.ParseIP(ns); ip != nil {
					s.resolverHost = net.JoinHostPort(ns, "53")
					return
				}
			}
		}
		s.resolverErr = fmt.Errorf("no nameserver in /etc/resolv.conf")
	})
	if s.resolverErr != nil {
		return "", s.resolverErr
	}
	return s.resolverHost, nil
}

// DNS response codes for synthesized refusals.
const (
	dnsRCODEServFail = 2
	dnsRCODERefused  = 5
)

// dnsError answers a query with just a response code: the question echoed, no
// answers, QR set. A refusal or failure is honest with the program — it
// retries, gives up or reports, exactly as with an unreachable resolver —
// without inventing a lie like NXDOMAIN. When the question cannot be echoed
// (truncated or malformed wire form) a bare header still goes out: the
// program gets a real rcode, never an empty datagram.
func dnsError(query []byte, rcode int) []byte {
	bare := func() []byte {
		resp := make([]byte, 12)
		if len(query) >= 2 {
			copy(resp, query[:2]) // echo the id so the program can match
		}
		resp[2] = 0x80 // QR=1
		resp[3] = byte(rcode)
		return resp
	}
	if len(query) < 12 {
		return bare()
	}
	end := 12
	qd := binary.BigEndian.Uint16(query[4:6])
	if qd == 1 {
		// Walk the question so the echo stops after it.
		pos := 12
		for {
			if pos >= len(query) {
				return bare()
			}
			n := int(query[pos])
			pos++
			if n == 0 {
				break
			}
			if n > 63 || pos+n > len(query) {
				return bare()
			}
			pos += n
		}
		if pos+4 > len(query) {
			return bare()
		}
		end = pos + 4
	} else {
		qd = 0
	}
	resp := make([]byte, end)
	copy(resp, query[:end])
	resp[2] = query[2]&0x78 | 0x80 // QR=1, opcode preserved, rest cleared
	resp[3] = byte(rcode)
	binary.BigEndian.PutUint16(resp[4:6], qd)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

// dnsQuestion extracts the question name and type from a DNS query: a 12-byte
// header, then QNAME as length-prefixed labels, then qtype and qclass.
// Compression pointers cannot appear in a question, so the parse is flat.
func dnsQuestion(query []byte) (name, qtype string, ok bool) {
	if len(query) < 12 {
		return "", "", false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 {
		return "", "", false
	}
	pos := 12
	var labels []string
	for {
		if pos >= len(query) {
			return "", "", false
		}
		n := int(query[pos])
		pos++
		if n == 0 {
			break
		}
		if n > 63 || pos+n > len(query) {
			return "", "", false
		}
		labels = append(labels, string(query[pos:pos+n]))
		pos += n
	}
	if pos+4 > len(query) {
		return "", "", false
	}
	switch t := binary.BigEndian.Uint16(query[pos : pos+2]); t {
	case 1:
		qtype = "A"
	case 28:
		qtype = "AAAA"
	default:
		qtype = fmt.Sprintf("type%d", t)
	}
	return strings.Join(labels, "."), qtype, true
}

func (s *Server) track(c net.Conn, host string) {
	s.mu.Lock()
	s.live[c] = host
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.live, c)
	s.mu.Unlock()
}

// watchDeny re-reads the deny file once a second and, when it changes, cuts
// open connections to hosts it now names. Refusing new connections alone
// would not be a kill switch: an agent holds HTTPS connections open for
// minutes, and everything it sends rides the one it already has.
func (s *Server) watchDeny(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := s.Deny.Refresh()
		if err != nil {
			// The kill switch is a security control. If the file has been
			// replaced by something unreadable, the list in force is the last
			// good one and the operator believes hosts are blocked: say so once
			// per distinct failure rather than freezing silently.
			if msg := err.Error(); msg != s.denyErr {
				s.denyErr = msg
				s.logf("DENYFILE re-read failed, keeping the previous list: %v", err)
			}
			continue
		}
		if !changed {
			continue
		}
		s.denyErr = ""
		entries, invalid := s.Deny.Entries()
		extra := ""
		if invalid > 0 {
			extra = fmt.Sprintf(", %d invalid lines ignored", invalid)
		}
		if truncated := s.Deny.Truncated(); truncated {
			extra += ", TRUNCATED at 1 MiB: hosts past that are not enforced"
		}
		s.logf("DENYFILE reloaded: %d hosts%s", len(entries), extra)
		var cut []net.Conn
		var hosts []string
		s.mu.Lock()
		for c, h := range s.live {
			if _, hit := s.Deny.match(h); hit {
				cut = append(cut, c)
				hosts = append(hosts, h)
			}
		}
		s.mu.Unlock()
		for i, c := range cut {
			_ = c.Close()
			s.logf("CUT   %s  (open connection closed: host added to the deny file)", hosts[i])
			s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: hosts[i],
				Reason: "open connection cut: host added to deny file"})
		}
	}
}

// requestTarget is the path and query of u, for the event log. The query is
// kept because that is where a GET carries data — a shortener's target URL, a
// fetcher's inner URL, a key in ?api_key=. It is capped so one request cannot
// fill the log.
func requestTarget(u *url.URL) string {
	if u == nil {
		return ""
	}
	t := u.EscapedPath()
	if u.RawQuery != "" {
		t += "?" + u.RawQuery
	}
	const max = 2048
	if len(t) > max {
		t = t[:max] + "…"
	}
	return t
}

// pipe copies in both directions until either side closes, returning bytes
// sent client→server and server→client.
func pipe(client, server net.Conn) (sent, recv int64) {
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(server, client); atomic.StoreInt64(&sent, n); done <- struct{}{} }()
	go func() { n, _ := io.Copy(client, server); atomic.StoreInt64(&recv, n); done <- struct{}{} }()
	<-done
	// Unblock the other direction so its count is final.
	_ = client.SetDeadline(time.Now())
	_ = server.SetDeadline(time.Now())
	<-done
	return atomic.LoadInt64(&sent), atomic.LoadInt64(&recv)
}

// countingReader and countingWriter tally bytes on one connection. Each is
// used by a single goroutine and read only by that goroutine, so the plain
// field is enough; the two directions of a CONNECT tunnel, which really are two
// goroutines, use their own atomics (see pipe).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// HumanBytes formats a byte count for logs and summaries.
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func writeStatus(w io.Writer, code int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// KnownLimits describes what this proxy does not solve. They are printed with
// the generated wrapper rather than left for the reader to discover.
func KnownLimits() []string {
	return []string{
		"An allow-listed host that stores or forwards is still an exfiltration route. " +
			"A package registry, a paste service or anything with an upload endpoint can be " +
			"used to stage data and relay requests onward — in the 2026 OpenAI–Hugging Face " +
			"incident, agents reached the internet through a package registry's remote-repository " +
			"proxy. Narrow such hosts with --rule (e.g. registry.internal:GET,HEAD) so only downloads " +
			"are allowed; the allow-list alone chooses who you trust, it does not prove data cannot leave.",
		"Hosts WITHOUT a --rule are tunnelled untouched: the proxy sees only the hostname and the " +
			"byte counts, never the content. Hosts WITH a rule are TLS-inspected using a per-run CA that " +
			"is constrained to those hosts and trusted only inside the sandbox.",
		"Canaries detect use of their reserved .invalid hostnames and visible token strings. An encrypted " +
			"request to a host without --rule can carry a canary string unseen; bodies are scanned only " +
			"through the first 64 KiB. No trip does not prove the agent behaved safely.",
		"Even with a rule, data can leave inside a permitted request — a long URL or query string on " +
			"an allowed GET. Rules shrink the channel; they do not close it.",
		"A download-only rule does not stop a malicious download. Code hosts (raw.githubusercontent.com, " +
			"gist, gitlab, huggingface) serve anyone's content from a domain you trust — the backdoored model " +
			"in ProjectDiscovery's 2026 demo fetched its payload that way. Scope them to your own repositories " +
			"with a path rule, e.g. --rule raw.githubusercontent.com:GET,HEAD:/your-org/.",
		"The model API is itself a destination. Whatever the agent reads can be sent to the model endpoint " +
			"in the next prompt, and the proxy must allow that host for the agent to work. If you do not trust " +
			"the model — an abliterated or fine-tuned build of unknown origin — keep secrets out of the " +
			"sandbox, or serve the model locally and run with no egress at all.",
		"Some hosts relay on a plain GET: URL shorteners (a link and its statistics page are written " +
			"by a query string), fetchers and CORS proxies (r.jina.ai/<any URL>), tunnels and user-hosted " +
			"apps (*.workers.dev, *.vercel.app). No --rule makes these download-only. In the 2026 agent swarm " +
			"incidents, agents used dozens of them as message boards and as a way onward; the proxy names the " +
			"ones it knows, and cannot know them all.",
		"Upload accounting is by volume for tunnelled hosts: a small secret (a few hundred bytes) sent to " +
			"an allowed host without a --rule is not flagged. Write requests are flagged on first use only " +
			"where the proxy can see them: plain HTTP and --rule hosts.",
		"The proxy binds to loopback only. Do not expose it on another interface; an " +
			"allow-listing proxy reachable from the network is an open relay.",
	}
}

// Sanitise trims a host for logging.
func Sanitise(h string) string { return strings.TrimSpace(strings.ToLower(h)) }
