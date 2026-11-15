package bridge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeProxy stands in for the allow-listing proxy: it answers CONNECT with
// 200 (or 403 when deny is set) and then echoes everything it receives, so a
// test can assert both the tunnel request and the byte path.
type fakeProxy struct {
	ln       net.Listener
	seen     chan string
	deny     bool
	mainAddr string // the bridge's proxy-port listener, set by startBridge
	lastBind string // the bound permitted port, set by startBridge
}

// sockPath returns a unix socket path short enough for macOS, whose per-user
// temp directories push the usual t.TempDir() paths past the kernel's
// 104-character sun_path limit and make bind fail with EINVAL.
func sockPath(t *testing.T, name string) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "scheckr")
	if err != nil {
		// No /tmp to write to: fall back and rely on a longer sun_path.
		return filepath.Join(t.TempDir(), name)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, name)
}

func startFakeProxy(t *testing.T, deny bool) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("unix", sockPath(t, "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProxy{ln: ln, seen: make(chan string, 4), deny: deny}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fp.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return fp
}

func (fp *fakeProxy) handle(c net.Conn) {
	defer c.Close()
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return
	}
	fp.seen <- req.Host
	if fp.deny {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	io.Copy(c, c)
}

// waitHost returns the next CONNECT destination the fake proxy observed.
func (fp *fakeProxy) waitHost(t *testing.T) string {
	t.Helper()
	select {
	case host := <-fp.seen:
		return host
	case <-time.After(5 * time.Second):
		t.Fatal("proxy never saw a CONNECT")
		return ""
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func startBridge(t *testing.T, binds []string, fp *fakeProxy) context.CancelFunc {
	t.Helper()
	listen := freeAddr(t)
	fp.mainAddr = listen
	if len(binds) > 0 {
		fp.lastBind = binds[len(binds)-1]
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- ServeAll(ctx, listen, binds, fp.ln.Addr().String(), nil, ready) }()
	select {
	case <-ready:
	case err := <-errc:
		t.Fatalf("bridge failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("bridge never became ready")
	}
	return cancel
}

// A direct connection to a bound permitted port must reach the proxy as a
// CONNECT to that destination and carry the client's bytes both ways.
func TestBridgeTunnelsDirectConnectThroughProxy(t *testing.T) {
	fp := startFakeProxy(t, false)
	defer startBridge(t, []string{freeAddr(t)}, fp)()

	c, err := net.Dial("tcp", fp.lastBind)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo through the proxy = %q, want %q", got, "ping")
	}
	if host := fp.waitHost(t); host != fp.lastBind {
		t.Fatalf("CONNECT destination = %q, want %q", host, fp.lastBind)
	}
}

// The main listener keeps speaking the HTTP proxy protocol: the client's own
// request reaches the proxy untouched, and the proxy's answer flows back.
func TestBridgeProxyPortPassesClientRequestThrough(t *testing.T) {
	fp := startFakeProxy(t, false)
	defer startBridge(t, nil, fp)()

	c, err := net.Dial("tcp", fp.mainAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("HTTP/1.1 200 Connection established"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 200 Connection established") {
		t.Fatalf("proxy answer = %q, want the 200 the client's own CONNECT earned", got)
	}
	if host := fp.waitHost(t); host != "example.com:443" {
		t.Fatalf("CONNECT destination = %q, want the client's own example.com:443", host)
	}
}

// A connection the proxy refuses must not become a tunnel: it closes without
// carrying any payload.
func TestBridgeRefusedTunnelCarriesNothing(t *testing.T) {
	fp := startFakeProxy(t, true)
	defer startBridge(t, []string{freeAddr(t)}, fp)()

	c, err := net.Dial("tcp", fp.lastBind)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "secret"); err != nil {
		t.Fatal(err)
	}
	if host := fp.waitHost(t); host != fp.lastBind {
		t.Fatalf("CONNECT destination = %q, want %q", host, fp.lastBind)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err == nil {
		t.Fatal("denied tunnel stayed open; want a closed connection")
	}
}

// A bind that cannot be taken is skipped with a warning; the rest of the
// bridge keeps working.
func TestBridgeBindConflictIsReportedAndSkipped(t *testing.T) {
	fp := startFakeProxy(t, false)
	taken := freeAddr(t)
	hold, err := net.Listen("tcp", taken)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()

	var warned []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		errc <- ServeAll(ctx, freeAddr(t), []string{taken, taken}, fp.ln.Addr().String(),
			func(addr string, _ error) { warned = append(warned, addr) }, ready)
	}()
	select {
	case <-ready:
	case err := <-errc:
		t.Fatalf("bridge failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("bridge never became ready")
	}
	// Both entries hit the held port, so both are reported and skipped.
	if len(warned) != 2 || warned[0] != taken || warned[1] != taken {
		t.Fatalf("bind warnings = %v, want [%s %s]", warned, taken, taken)
	}
}
