// Package bridge forwards a loopback TCP port to a unix socket.
//
// It exists for sandboxes with their own network namespace. Inside such a
// sandbox 127.0.0.1 is a private loopback with nothing listening on it, so a
// program configured with HTTP_PROXY=http://127.0.0.1:PORT has nowhere to go.
// The bridge runs inside the sandbox, under the same restrictions as the
// program, listens on that private loopback, and relays each connection to the
// allow-listing proxy's unix socket — which is bind-mounted in from the host.
// It adds no route of its own: the only thing it can reach is the proxy.
//
// The bridge also binds the ports the policy permits (allow-port) on the
// sandbox's loopback. Tools that bypass HTTP proxies for localhost — by
// setting NO_PROXY to loopback, for example — connect directly; each such
// connection is tunnelled through the proxy with a synthesized CONNECT, so the
// policy, its decisions and its event log still apply. A program that wants to
// SERVE on a permitted port cannot: the bridge binds it first.
package bridge

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// boundListener pairs a listener with the destination it fronts: empty for
// the proxy port itself, the bound address for a permitted port.
type boundListener struct {
	ln   net.Listener
	addr string
}

// Serve accepts on listen — the port the sandbox's proxy environment points
// at — and relays every connection to the unix socket at to, until ctx is
// cancelled. ready is closed once the listener is bound.
func Serve(ctx context.Context, listen, to string, ready chan<- struct{}) error {
	return ServeAll(ctx, listen, nil, to, nil, ready)
}

// ServeAll is Serve plus binds: addresses such as 127.0.0.1:8000 that are also
// bound on the sandbox's loopback, each relayed through the proxy as a
// synthesized CONNECT to that address. The main listener is bound first; a
// bind that fails is reported through onBindError (which may be nil) and
// skipped, so one blocked port never takes down the run. ready is closed once
// every listener has been set up.
func ServeAll(ctx context.Context, listen string, binds []string, to string, onBindError func(addr string, err error), ready chan<- struct{}) error {
	var listeners []boundListener
	closeAll := func() {
		for _, l := range listeners {
			_ = l.ln.Close()
		}
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	listeners = append(listeners, boundListener{ln: ln})
	for _, addr := range binds {
		bl, err := net.Listen("tcp", addr)
		if err != nil {
			if onBindError != nil {
				onBindError(addr, err)
			}
			continue
		}
		listeners = append(listeners, boundListener{ln: bl, addr: addr})
	}
	if ready != nil {
		close(ready)
	}
	go func() { <-ctx.Done(); closeAll() }()
	for _, l := range listeners {
		// A listener without an address is the proxy port itself: its clients
		// speak the HTTP proxy protocol. Every other one fronts a permitted
		// port, so the bridge speaks that protocol on the client's behalf.
		forward := func(c net.Conn) { relay(ctx, c, to) }
		if l.addr != "" {
			dest := l.addr
			forward = func(c net.Conn) { relayTunneled(ctx, c, to, dest) }
		}
		go acceptLoop(ctx, l.ln, forward)
	}
	return nil
}

// maxConns bounds how many connections one listener is relaying at once, the
// same shape as the DNS relay's semaphore: each relay dials the proxy, so an
// unbounded fan-out lets a single client exhaust the bridge instead of itself.
const maxConns = 64

// maxAcceptFailures is how many consecutive accept errors the loop tolerates
// before giving up. Isolated ones are just EMFILE under load and back off, but
// a listener that cannot accept a hundred times running is broken, and a retry
// loop that never returns burns a core inside a sandbox that should be
// quiescent.
const maxAcceptFailures = 100

func acceptLoop(ctx context.Context, ln net.Listener, forward func(net.Conn)) {
	sem := make(chan struct{}, maxConns)
	failures := 0
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if failures++; failures >= maxAcceptFailures {
				return
			}
			// A transient accept error (EMFILE under load) must not kill the
			// listener: back off briefly and continue.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		failures = 0
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = c.Close()
			return
		}
		go func() {
			defer func() { <-sem }()
			forward(c)
		}()
	}
}

// relay pipes a connection from the main listener straight to the proxy: the
// client speaks the HTTP proxy protocol itself, so the proxy reads the
// destination from its request.
func relay(ctx context.Context, c net.Conn, to string) {
	defer c.Close()
	u, err := net.DialTimeout("unix", to, 5*time.Second)
	if err != nil {
		return
	}
	defer u.Close()
	pipeBoth(ctx, c, u)
}

// ServeDNS relays DNS queries from the sandbox's loopback to the proxy's DNS
// socket. It binds listen (127.0.0.1:53, the address the sandbox's resolv.conf
// points at) on both UDP and TCP and answers each query by exchanging a framed
// message with the proxy, which gates the name and resolves host-side. TCP is
// not optional: glibc and musl retry over TCP whenever an answer comes back
// with TC=1, routine for DNSSEC-signed answers and large A or AAAA sets, so a
// UDP-only relay makes those lookups hard-fail. A query that cannot be relayed
// is dropped: the client retries, and an unreachable resolver is exactly what
// the sandbox looks like when the proxy is gone. The bind can fail when the
// policy permits port 53 for tunnelling; each transport that fails is reported
// and resolution over it is simply unavailable.
func ServeDNS(ctx context.Context, listen, sock string, onBindError func(err error)) {
	pc, udpErr := BindDNS(listen)
	if udpErr != nil && onBindError != nil {
		onBindError(udpErr)
	}
	ln, tcpErr := BindDNSTCP(listen)
	if tcpErr != nil && onBindError != nil {
		onBindError(tcpErr)
	}
	if udpErr != nil && tcpErr != nil {
		return
	}
	if ln != nil {
		// One handler, one semaphore, one retry policy for both transports:
		// the only difference is the length prefix a datagram boundary already
		// carries for UDP.
		go acceptLoop(ctx, ln, func(c net.Conn) { serveDNSQuery(c, sock) })
	}
	if pc != nil {
		ServeDNSConn(ctx, pc, sock)
	}
}

// BindDNS binds the UDP relay socket.
func BindDNS(listen string) (net.PacketConn, error) {
	return net.ListenPacket("udp", listen)
}

// BindDNSTCP binds the TCP relay socket, which carries the same queries with
// the two-byte length prefix RFC 1035 puts on a message sent over a stream.
func BindDNSTCP(listen string) (net.Listener, error) {
	return net.Listen("tcp", listen)
}

// serveDNSQuery answers one TCP query: a length-prefixed message in, a
// length-prefixed answer out, then the connection is done. Resolvers retry
// over a fresh connection, so one query per connection is all a client needs.
func serveDNSQuery(c net.Conn, sock string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, query); err != nil {
		return
	}
	resp, err := exchange(sock, query)
	if err != nil || len(resp) > maxDNSFrame {
		// A reply too long to carry its own prefix is no reply at all; drop it
		// and let the resolver's own timeout answer.
		return
	}
	out := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(out, uint16(len(resp)))
	copy(out[2:], resp)
	_, _ = c.Write(out)
}

// ServeDNSConn relays DNS queries on an already bound socket until the
// context is cancelled.
func ServeDNSConn(ctx context.Context, pc net.PacketConn, sock string) {
	go func() { <-ctx.Done(); _ = pc.Close() }()
	buf := make([]byte, 64*1024)
	sem := make(chan struct{}, 64)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		go func() {
			defer func() { <-sem }()
			resp, err := exchange(sock, query)
			if err == nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}

// maxDNSFrame is the largest message the framed protocol carries: the 65535
// byte cap RFC 1035 puts on a DNS message, and the bound the proxy's own
// reader applies (internal/proxy handleDNS). The two ends of one framing
// protocol have to agree on it, or a peer on either side can ask the other for
// a 4 GiB allocation from a length field it chose itself.
const maxDNSFrame = 65535

// exchange performs one framed query against the proxy's DNS socket: a 4-byte
// big-endian length plus the raw DNS message, response the same way.
func exchange(sock string, query []byte) ([]byte, error) {
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(query)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxDNSFrame {
		return nil, fmt.Errorf("dns frame length %d out of range", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// relayTunneled serves a connection to a bound permitted port: the client
// speaks to its destination directly, so the bridge asks the proxy for the
// tunnel itself and pipes raw bytes after the proxy agrees.
func relayTunneled(ctx context.Context, c net.Conn, to, dest string) {
	defer c.Close()
	u, err := net.DialTimeout("unix", to, 5*time.Second)
	if err != nil {
		return
	}
	defer u.Close()
	fmt.Fprintf(u, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest)
	br := bufio.NewReader(u)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	// The proxy tunnels byte-for-byte after the 200; bufio may have read
	// ahead, so deliver anything it buffered before piping.
	if n := br.Buffered(); n > 0 {
		head := make([]byte, n)
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		if _, err := c.Write(head); err != nil {
			return
		}
	}
	pipeBoth(ctx, c, u)
}

// tunnelIdle is how long a bridged connection may carry nothing in either
// direction before the bridge drops it. Cancelling the context closes the
// listeners, not the established tunnels, and a peer that stops talking
// without ever sending a FIN would otherwise hold two goroutines and two
// sockets for the rest of the run. The value is generous enough for a keep
// alive or a dev server fronted by a permitted port.
const tunnelIdle = 30 * time.Minute

// pipeDrainWait bounds the wait for the second direction after the first has
// reached end of stream, so a peer that never finishes its response cannot
// hold the connection open forever.
const pipeDrainWait = 5 * time.Second

// pipe copies src to dst until either end reports an error. It sets the
// deadlines itself, before every read, so what is bounded is the gap between
// bytes rather than the life of the connection.
func pipe(dst, src net.Conn, done chan<- net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(tunnelIdle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(tunnelIdle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				err = werr
				break
			}
		}
		if err != nil {
			break
		}
	}
	done <- dst
}

// halfCloseWrite signals end of stream to one end of a tunnel. A stream socket
// has a write half to close; on a unix socket there is nothing to do.
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func pipeBoth(ctx context.Context, a, b net.Conn) {
	done := make(chan net.Conn, 2)
	go pipe(b, a, done)
	go pipe(a, b, done)
	// The copy that finished first reached its source's end of stream, usually
	// the client half-closing its write side after sending the request.
	// Closing both halves here truncates the response still in flight on the
	// other one, so signal end of stream the same way instead and let that
	// copy run out.
	fin := <-done
	halfCloseWrite(fin)
	select {
	case <-done:
	case <-time.After(pipeDrainWait):
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
}
