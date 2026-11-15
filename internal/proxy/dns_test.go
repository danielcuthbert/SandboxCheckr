package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// dnsQuery builds a DNS query with one question.
func dnsQuery(name string, qtype uint16) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT
	b.Write(hdr)
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	t := make([]byte, 4)
	binary.BigEndian.PutUint16(t[0:2], qtype)
	b.Write(t)
	return b.Bytes()
}

// fakeDNSOverTCP answers every query with respond, as a resolver speaking DNS
// over TCP: two-byte length prefixes in both directions.
func fakeDNSOverTCP(t *testing.T, respond func(query []byte) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				r := respond(q)
				out := make([]byte, 2+len(r))
				binary.BigEndian.PutUint16(out, uint16(len(r)))
				copy(out[2:], r)
				c.Write(out)
			}(c)
		}
	}()
	return ln.Addr().String()
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

// startDNSProxy starts a server with a DNS relay socket and returns a client
// connection to it.
func startDNSProxy(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	if _, err := srv.Listen(0); err != nil {
		t.Fatal(err)
	}
	sock := sockPath(t, "dns.sock")
	if err := srv.ListenDNS(sock); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// exchangeDNS writes one framed query and reads one framed response.
func exchangeDNS(t *testing.T, c net.Conn, query []byte) []byte {
	t.Helper()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(query)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func newDNSServer(t *testing.T, allow []string, observe bool, logBuf *syncBuffer, resolver string) *Server {
	t.Helper()
	list, err := NewAllowList(allow)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(list, observe, logBuf)
	srv.Resolver = resolver
	return srv
}

func TestDNSRelayRelaysAllowedNames(t *testing.T) {
	// The fake resolver echoes the query back with QR set and RCODE 0.
	fake := fakeDNSOverTCP(t, func(q []byte) []byte {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		return r
	})
	logBuf := &syncBuffer{}
	eventsBuf := &syncBuffer{}
	srv := newDNSServer(t, []string{"allowed.test"}, false, logBuf, fake)
	srv.Events = events.NewWriter(eventsBuf, "test")
	c := startDNSProxy(t, srv)

	query := dnsQuery("allowed.test", 1)
	resp := exchangeDNS(t, c, query)
	if got := resp[3] & 0x0F; got != 0 {
		t.Fatalf("allowed.test: RCODE = %d, want 0", got)
	}
	if !bytes.Equal(resp[12:], query[12:]) {
		t.Fatalf("response question does not match the query")
	}
}

func TestDNSRelayRefusesUnlistedNames(t *testing.T) {
	fake := fakeDNSOverTCP(t, func(q []byte) []byte { t.Fatal("resolver should not be reached"); return nil })
	logBuf := &syncBuffer{}
	eventsBuf := &syncBuffer{}
	srv := newDNSServer(t, []string{"allowed.test"}, false, logBuf, fake)
	srv.Events = events.NewWriter(eventsBuf, "test")
	c := startDNSProxy(t, srv)

	resp := exchangeDNS(t, c, dnsQuery("denied.test", 1))
	if got := resp[3] & 0x0F; got != 5 {
		t.Fatalf("denied.test: RCODE = %d, want 5 (REFUSED)", got)
	}
	if !strings.Contains(eventsBuf.String(), `"kind":"dns"`) {
		t.Fatalf("no dns event logged:\n%s", eventsBuf.String())
	}
	if !strings.Contains(eventsBuf.String(), `"decision":"deny"`) || !strings.Contains(eventsBuf.String(), `"reason":"not in allow-list"`) {
		t.Fatalf("deny event missing or wrong:\n%s", eventsBuf.String())
	}
}

func TestDNSRelayRefusesDenyFileNames(t *testing.T) {
	fake := fakeDNSOverTCP(t, func(q []byte) []byte { t.Fatal("resolver should not be reached"); return nil })
	denyPath := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(denyPath, []byte("blockme.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deny, err := NewDenyFile(denyPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := newDNSServer(t, []string{"blockme.test"}, false, &syncBuffer{}, fake)
	srv.Deny = deny
	c := startDNSProxy(t, srv)

	resp := exchangeDNS(t, c, dnsQuery("blockme.test", 1))
	if got := resp[3] & 0x0F; got != 5 {
		t.Fatalf("blockme.test: RCODE = %d, want 5 (REFUSED)", got)
	}
}

func TestDNSRelayServFailsWhenResolverUnreachable(t *testing.T) {
	// Port 1 is closed on loopback.
	srv := newDNSServer(t, []string{"allowed.test"}, false, &syncBuffer{}, "127.0.0.1:1")
	c := startDNSProxy(t, srv)

	resp := exchangeDNS(t, c, dnsQuery("allowed.test", 1))
	if got := resp[3] & 0x0F; got != 2 {
		t.Fatalf("RCODE = %d, want 2 (SERVFAIL)", got)
	}
}

func TestDNSRelayObserveResolvesAndLogs(t *testing.T) {
	fake := fakeDNSOverTCP(t, func(q []byte) []byte {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		return r
	})
	eventsBuf := &syncBuffer{}
	srv := newDNSServer(t, []string{"allowed.test"}, true, &syncBuffer{}, fake)
	srv.Events = events.NewWriter(eventsBuf, "test")
	c := startDNSProxy(t, srv)

	resp := exchangeDNS(t, c, dnsQuery("other.test", 1))
	if got := resp[3] & 0x0F; got != 0 {
		t.Fatalf("observe mode: RCODE = %d, want 0", got)
	}
	if !strings.Contains(eventsBuf.String(), `"decision":"observe"`) {
		t.Fatalf("no observe dns event:\n%s", eventsBuf.String())
	}
}

func TestDNSQuestion(t *testing.T) {
	cases := []struct {
		name  string
		query []byte
		want  string
		qtype string
		ok    bool
	}{
		{"normal A", dnsQuery("example.com", 1), "example.com", "A", true},
		{"normal AAAA", dnsQuery("example.com", 28), "example.com", "AAAA", true},
		{"unknown qtype", dnsQuery("example.com", 16), "example.com", "type16", true},
		{"subdomain", dnsQuery("a.b.example.com", 1), "a.b.example.com", "A", true},
		{"too short", []byte{0, 0, 0, 0}, "", "", false},
		{"two questions", func() []byte {
			q := dnsQuery("example.com", 1)
			binary.BigEndian.PutUint16(q[4:6], 2) // QDCOUNT = 2
			return q
		}(), "", "", false},
		{"label over 63", append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, append([]byte{64}, make([]byte, 64)...)...), "", "", false},
		{"truncated question", dnsQuery("example.com", 1)[:len(dnsQuery("example.com", 1))-2], "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, qtype, ok := dnsQuestion(tc.query)
			if name != tc.want || qtype != tc.qtype || ok != tc.ok {
				t.Fatalf("dnsQuestion = (%q, %q, %v), want (%q, %q, %v)", name, qtype, ok, tc.want, tc.qtype, tc.ok)
			}
		})
	}
}

func TestDNSErrorEchoesQuestionAndSetsRCODE(t *testing.T) {
	query := dnsQuery("example.com", 1)
	resp := dnsError(query, dnsRCODERefused)
	if got := resp[3] & 0x0F; got != 5 {
		t.Fatalf("RCODE = %d, want 5", got)
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("QR not set")
	}
	if !bytes.Equal(resp[12:], query[12:]) {
		t.Fatalf("question not echoed")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 || binary.BigEndian.Uint16(resp[8:10]) != 0 || binary.BigEndian.Uint16(resp[10:12]) != 0 {
		t.Fatal("answer counts not zeroed")
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		t.Fatal("QDCOUNT not preserved")
	}
}

func TestDNSRelayIgnoresGarbage(t *testing.T) {
	fake := fakeDNSOverTCP(t, func(q []byte) []byte { return q })
	srv := newDNSServer(t, []string{"allowed.test"}, false, &syncBuffer{}, fake)
	c := startDNSProxy(t, srv)

	// A malformed query gets a SERVFAIL rather than a crash or a relay.
	resp := exchangeDNS(t, c, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0})
	if len(resp) == 0 || resp[3]&0x0F != 2 {
		t.Fatalf("malformed query: want SERVFAIL, got %v", resp)
	}
	// A query shorter than a header gets no response at all: the framing
	// cannot carry an echo of something that has none.
	if resp := exchangeDNS(t, c, []byte{0, 0, 0, 0}); len(resp) != 0 {
		t.Fatalf("short query: want no response, got %v", resp)
	}
}

func TestRelayResolverOverride(t *testing.T) {
	srv := NewServer(nil, false, nil)
	srv.Resolver = "192.0.2.53:53"
	addr, err := srv.relayResolver()
	if err != nil || addr != "192.0.2.53:53" {
		t.Fatalf("override = (%q, %v), want (192.0.2.53:53, nil)", addr, err)
	}
}
