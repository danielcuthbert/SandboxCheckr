package proxy

import (
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

func TestParseDenyList(t *testing.T) {
	in := "# comment\nEvil.com\n  *.relay.example  # trailing\n\nevil.com\nnot a host!\nx.\n"
	got, invalid := ParseDenyList([]byte(in))
	want := []string{"evil.com", "relay.example", "x"}
	if strings.Join(got, ",") != strings.Join(want, ",") || invalid != 1 {
		t.Errorf("got %v (%d invalid), want %v (1 invalid)", got, invalid, want)
	}
}

// Subdomains and a trailing root dot must not slip past an entry: a
// kill switch that "evil.com." walks around is not one.
func TestDenyFileMatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(path, []byte("evil.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDenyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"evil.com", "EVIL.com", "a.b.evil.com", "evil.com.", "sub.evil.com."} {
		if _, hit := d.Match(h); !hit {
			t.Errorf("%s should be refused", h)
		}
	}
	for _, h := range []string{"notevil.com", "evil.com.example", "evil.co"} {
		if _, hit := d.Match(h); hit {
			t.Errorf("%s wrongly refused", h)
		}
	}
}

// A missing file is an empty list; creating, editing and deleting it take
// effect on the next lookup.
func TestDenyFileReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny.txt")
	d, err := NewDenyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, hit := d.Match("a.test"); hit {
		t.Fatal("missing file must refuse nothing")
	}
	_ = os.WriteFile(path, []byte("a.test\n"), 0o600)
	if _, hit := d.Match("a.test"); !hit {
		t.Error("new entry must apply on the next lookup")
	}
	// Same size, so only the mtime differs: push it forward to be sure the
	// change is seen on filesystems with coarse timestamps.
	_ = os.WriteFile(path, []byte("b.test\n"), 0o600)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	if _, hit := d.Match("a.test"); hit {
		t.Error("removed entry must stop applying")
	}
	_ = os.Remove(path)
	if _, hit := d.Match("b.test"); hit {
		t.Error("deleting the file must clear the list")
	}
}

// The kill switch overrides the allow-list and observe mode alike.
func TestDenyFileBeatsAllowListAndObserve(t *testing.T) {
	upstream := startUpstream(t)
	host, _, _ := net.SplitHostPort(upstream)
	path := filepath.Join(t.TempDir(), "deny.txt")
	_ = os.WriteFile(path, []byte(host+"\n"), 0o600)
	for _, observe := range []bool{false, true} {
		list, _ := NewAllowList([]string{host})
		list.AllowPrivate, list.AnyPort = true, true
		srv := NewServer(list, observe, io.Discard)
		srv.Deny, _ = NewDenyFile(path)
		addr, err := srv.Listen(0)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go srv.Serve(ctx)
		resp := proxyRequest(t, addr, "http://"+upstream+"/")
		resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("observe=%v: got %d, want 403", observe, resp.StatusCode)
		}
	}
}

// Adding a host must cut a tunnel that is already open, not only refuse new
// ones: an agent sends everything over the connection it already holds.
func TestDenyFileCutsOpenTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	path := filepath.Join(t.TempDir(), "deny.txt")
	list, _ := NewAllowList([]string{host})
	list.AllowPrivate, list.AnyPort = true, true
	srv := NewServer(list, false, io.Discard)
	srv.Deny, _ = NewDenyFile(path)
	addr, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT "+host+":"+port+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	buf := make([]byte, 256)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("tunnel not established: %q %v", buf[:n], err)
	}

	_ = os.WriteFile(path, []byte(host+"\n"), 0o600)
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected the open tunnel to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("open tunnel was not cut within the reload interval")
	}
}
