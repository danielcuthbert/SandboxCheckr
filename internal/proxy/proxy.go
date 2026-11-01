package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	matcherOnce sync.Once
	matcher     *canary.Matcher
	ln          net.Listener
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

func (s *Server) canaryMatcher() *canary.Matcher {
	if s.Canaries == nil {
		return nil
	}
	s.matcherOnce.Do(func() { s.matcher = canary.NewMatcher(s.Canaries) })
	return s.matcher
}

func (s *Server) trip(c canary.Credential, host, port, method, confidence string) {
	t := Trip{RunID: s.Canaries.RunID, Label: c.Label, Confidence: confidence, Host: host, Port: port, Method: method}
	s.count(host, port, func(st *Stat) { st.Denied++; st.CanaryTrips++; st.CanaryLabels = append(st.CanaryLabels, c.Label) })
	s.mu.Lock()
	s.trips = append(s.trips, t)
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
func (s *Server) scanVisible(req *http.Request, host, port string, client io.Writer) bool {
	if s.Canaries == nil {
		return false
	}
	m := s.canaryMatcher()
	var visible bytes.Buffer
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
		confidence := "high"
		if c.Host == host {
			confidence = "medium"
		}
		s.trip(c, host, port, req.Method, confidence)
		return true
	}
	return false
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
	return &Server{Allow: allow, Observe: observe, Log: logw, stats: map[string]*Stat{}, live: map[net.Conn]string{}}
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
	}()
	if s.Deny != nil {
		go s.watchDeny(ctx)
	}

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
		go s.handle(ctx, conn)
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

func (s *Server) stat(host, port string) *Stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := host + ":" + port
	st, ok := s.stats[k]
	if !ok {
		st = &Stat{Host: host, Port: port, Methods: map[string]int{},
			Relay: RelayKind(host), RelaysOnGet: RelaysOnGet(host)}
		s.stats[k] = st
	}
	return st
}

func (s *Server) count(host, port string, f func(*Stat)) {
	st := s.stat(host, port)
	s.mu.Lock()
	f(st)
	s.mu.Unlock()
}

// event records e, filling in what the proxy knows about its host.
func (s *Server) event(e events.Event) {
	if s.Events == nil {
		return
	}
	e.Relay = RelayKind(e.Host)
	e.Fetcher = RelaysOnGet(e.Host)
	e.ModelAPI = IsModelAPI(e.Host)
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

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(ctx, client, req)
		return
	}
	// Anything already buffered in br beyond this request is deliberately
	// dropped: one request per connection, so a second, unchecked request
	// cannot ride along behind an allowed one.
	s.handlePlain(ctx, client, req)
}

// decide applies the allow-list and the address guard, returning the upstream
// address to dial.
func (s *Server) decide(host, port, method string) (string, bool) {
	s.count(host, port, func(st *Stat) { st.Conns++ })
	if s.Canaries != nil {
		if c, ok := s.canaryMatcher().Host(host); ok {
			s.trip(c, host, port, method, "medium")
			s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: "canary credential"})
			return "", false
		}
	}
	note := ""
	if k := RelayKind(host); k != "" {
		note = "  [can store/forward: " + k + "]"
		if RelaysOnGet(host) {
			note = "  [relays on a plain GET: " + k + "]"
		}
	}
	if IsModelAPI(host) {
		note += "  [model API: receives whatever the agent reads]"
	}
	deny := func(why string) (string, bool) {
		s.count(host, port, func(st *Stat) { st.Denied++ })
		s.logf("DENY  %s:%s  (%s)%s", host, port, why, note)
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: why})
		return "", false
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

	// Resolve here rather than letting the dialer do it, so the resulting
	// addresses can be checked before any connection is made.
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return deny("resolution failed")
	}
	for _, ip := range ips {
		if err := s.Allow.CheckHostAddr(host, ip); err != nil {
			return deny(err.Error())
		}
	}

	if permitted {
		s.logf("ALLOW %s:%s%s", host, port, note)
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Allow, Host: host, Port: port})
	} else {
		s.logf("OBSERVE %s:%s  (would be DENIED when enforcing)%s", host, port, note)
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Observe, Host: host, Port: port,
			Reason: "not in allow-list"})
	}
	// Every resolved address passed the guard; return them all so the dialer
	// can fall back (IPv6 first on a host without IPv6 routing, say).
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = net.JoinHostPort(ip.String(), port)
	}
	return strings.Join(addrs, ","), true
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
	if s.scanVisible(req, host, port, client) {
		s.count(host, port, func(st *Stat) { st.Conns++ })
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: "canary credential"})
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
			s.finish(host, port, atomic.LoadInt64(&cr.n), 0)
			return
		}
		s.count(host, port, func(st *Stat) { st.Methods[req.Method]++ })
		if s.scanVisible(req, host, port, tlsClient) {
			s.event(events.Event{Kind: events.KindRequest, Decision: events.Deny, Host: host, Port: port,
				Method: req.Method, Reason: "canary credential"})
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
			s.finish(host, port, atomic.LoadInt64(&cr.n), 0)
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

	if s.scanVisible(req, host, port, client) {
		s.count(host, port, func(st *Stat) { st.Conns++; st.Methods[req.Method]++ })
		s.event(events.Event{Kind: events.KindConnect, Decision: events.Deny, Host: host, Port: port, Reason: "canary credential"})
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
		if err != nil || !changed {
			continue
		}
		entries, invalid := s.Deny.Entries()
		s.logf("DENYFILE reloaded: %d hosts%s", len(entries), map[bool]string{true: fmt.Sprintf(", %d invalid lines ignored", invalid)}[invalid > 0])
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

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	atomic.AddInt64(&c.n, int64(n))
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
