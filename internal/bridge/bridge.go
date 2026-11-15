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
		forward := func(c net.Conn) { relay(c, to) }
		if l.addr != "" {
			dest := l.addr
			forward = func(c net.Conn) { relayTunneled(c, to, dest) }
		}
		go acceptLoop(ctx, l.ln, forward)
	}
	return nil
}

func acceptLoop(ctx context.Context, ln net.Listener, forward func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// A transient accept error (EMFILE under load) must not kill the
			// listener: back off briefly and continue.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go forward(c)
	}
}

// relay pipes a connection from the main listener straight to the proxy: the
// client speaks the HTTP proxy protocol itself, so the proxy reads the
// destination from its request.
func relay(c net.Conn, to string) {
	defer c.Close()
	u, err := net.DialTimeout("unix", to, 5*time.Second)
	if err != nil {
		return
	}
	defer u.Close()
	pipeBoth(c, u)
}

// ServeDNS relays DNS queries from the sandbox's loopback to the proxy's DNS
// socket. It binds listen — 127.0.0.1:53053, the address the sandbox's
// resolv.conf points at — and answers each datagram by exchanging a framed
// query with the proxy, which gates the name and resolves host-side. A query
// that cannot be relayed is dropped: the client retries, and an unreachable
// resolver is exactly what the sandbox looks like when the proxy is gone.
// The bind can fail when the policy permits port 53 for tunnelling; the
// failure is reported and resolution is simply unavailable.
func ServeDNS(ctx context.Context, listen, sock string, onBindError func(err error)) {
	pc, err := BindDNS(listen)
	if err != nil {
		if onBindError != nil {
			onBindError(err)
		}
		return
	}
	ServeDNSConn(ctx, pc, sock)
}

// BindDNS binds the UDP relay socket.
func BindDNS(listen string) (net.PacketConn, error) {
	return net.ListenPacket("udp", listen)
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
	resp := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// relayTunneled serves a connection to a bound permitted port: the client
// speaks to its destination directly, so the bridge asks the proxy for the
// tunnel itself and pipes raw bytes after the proxy agrees.
func relayTunneled(c net.Conn, to, dest string) {
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
	pipeBoth(c, u)
}

func pipeBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
}
