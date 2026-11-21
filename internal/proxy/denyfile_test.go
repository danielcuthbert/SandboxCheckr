package proxy

import (
	"context"
	"fmt"
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
// effect after Refresh (the watcher reloads once a second).
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
	if changed, err := d.Refresh(); err != nil || !changed {
		t.Fatalf("Refresh must report the new file (changed=%v err=%v)", changed, err)
	}
	if _, hit := d.Match("a.test"); !hit {
		t.Error("new entry must apply after Refresh")
	}
	// Same size, so only the mtime differs: push it forward to be sure the
	// change is seen on filesystems with coarse timestamps.
	_ = os.WriteFile(path, []byte("b.test\n"), 0o600)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	if changed, err := d.Refresh(); err != nil || !changed {
		t.Fatalf("Refresh must report the mtime change (changed=%v err=%v)", changed, err)
	}
	if _, hit := d.Match("a.test"); hit {
		t.Error("removed entry must stop applying after Refresh")
	}
	_ = os.Remove(path)
	if changed, err := d.Refresh(); err != nil || !changed {
		t.Fatalf("Refresh must report the deletion (changed=%v err=%v)", changed, err)
	}
	if _, hit := d.Match("b.test"); hit {
		t.Error("deleting the file must clear the list after Refresh")
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

// The file is append-mostly, so the entries lost to the size cap are the ones
// added last, which is the opposite of what a kill switch should do quietly.
func TestDenyFileReportsTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny.txt")
	var b strings.Builder
	for i := range maxDenyFileBytes/16 + 8 {
		fmt.Fprintf(&b, "h%d.denied.test\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDenyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated() {
		t.Fatal("a list past the cap should report itself truncated")
	}
	entries, invalid := d.Entries()
	if len(entries) == 0 || invalid != 0 {
		t.Fatalf("loaded %d entries with %d invalid", len(entries), invalid)
	}
	if err := os.WriteFile(path, []byte("a.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := d.Refresh(); err != nil || !changed {
		t.Fatalf("refresh of the shortened list: %v %v", changed, err)
	}
	if d.Truncated() {
		t.Error("a list within the cap must not report itself truncated")
	}
	if _, ok := d.Match("a.test"); !ok {
		t.Error("the shortened list is not in force")
	}
}
