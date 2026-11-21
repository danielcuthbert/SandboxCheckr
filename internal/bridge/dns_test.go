package bridge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// startFakeDNSProxy stands in for the proxy's DNS socket: one framed query in,
// one framed response out, marked with "r:" so a test can tell the answer from
// the query.
func startFakeDNSProxy(t *testing.T) string {
	t.Helper()
	sock := sockPath(t, "dns.sock")
	ln, err := net.Listen("unix", sock)
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
				var lb [4]byte
				for {
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(lb[:])
					if n == 0 || n > 65535 {
						return
					}
					q := make([]byte, n)
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					resp := append([]byte("r:"), q...)
					binary.BigEndian.PutUint32(lb[:], uint32(len(resp)))
					if _, err := c.Write(lb[:]); err != nil {
						return
					}
					if _, err := c.Write(resp); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return sock
}

// TestDNSRelayForwardsQueriesToProxy sends a query through the UDP relay to a
// fake proxy that echoes framed queries back, and expects the reply.
func TestDNSRelayForwardsQueriesToProxy(t *testing.T) {
	sock := startFakeDNSProxy(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc, err := BindDNS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ServeDNSConn(ctx, pc, sock)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	query := dnsQuery("allowed.test")
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 4096)
	n, err := c.Read(resp)
	if err != nil {
		t.Fatalf("no reply from the relay: %v", err)
	}
	resp = resp[:n]
	if string(resp[:2]) != "r:" || string(resp[2:]) != string(query) {
		t.Fatalf("reply = %q, want r:%q", resp, query)
	}
}

// TestDNSRelayServesTCPQueries covers the transport resolvers fall back to:
// glibc and musl retry over TCP whenever an answer has TC=1, so a query that
// only fits a larger message reaches the proxy framed with the two-byte RFC
// 1035 prefix and the answer comes back the same way.
func TestDNSRelayServesTCPQueries(t *testing.T) {
	sock := startFakeDNSProxy(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := BindDNSTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go acceptLoop(ctx, ln, func(c net.Conn) { serveDNSQuery(c, sock) })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	query := dnsQuery("allowed.test")
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := c.Write(framed); err != nil {
		t.Fatal(err)
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatalf("no reply from the relay: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("short reply from the relay: %v", err)
	}
	if string(resp[:2]) != "r:" || string(resp[2:]) != string(query) {
		t.Fatalf("reply = %q, want r:%q", resp, query)
	}
}

// TestDNSRelayTCPDropsQueriesWhenProxyGone checks the TCP path fails the way
// the UDP one does: no answer, and the listener still standing for the next
// query.
func TestDNSRelayTCPDropsQueriesWhenProxyGone(t *testing.T) {
	sock := sockPath(t, "dns.sock") // nothing listens here
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := BindDNSTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go acceptLoop(ctx, ln, func(c net.Conn) { serveDNSQuery(c, sock) })

	for range 2 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		query := dnsQuery("allowed.test")
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		copy(framed[2:], query)
		if _, err := c.Write(framed); err != nil {
			t.Fatal(err)
		}
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err == nil {
			t.Fatal("got a reply with no proxy behind the relay")
		}
		c.Close()
	}
}

// TestExchangeRejectsOversizedFrame checks the length bound the proxy applies
// to the same framing is applied here too: a peer that names a 4 GiB response
// gets an error, not an allocation, and a zero-length frame is refused rather
// than answered with an empty message.
func TestExchangeRejectsOversizedFrame(t *testing.T) {
	for _, name := range []uint32{0, 65536, 1<<32 - 1} {
		sock := sockPath(t, "dns.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			var lb [4]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(lb[:])
			if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
				return
			}
			binary.BigEndian.PutUint32(lb[:], name)
			_, _ = c.Write(lb[:])
		}()
		if _, err := exchange(sock, dnsQuery("allowed.test")); err == nil {
			t.Errorf("frame length %d accepted", name)
		}
		ln.Close()
	}
}

// TestDNSRelayDropsQueriesWhenProxyGone checks that a dead proxy is a dropped
// datagram, not a crash: the relay keeps serving.
func TestDNSRelayDropsQueriesWhenProxyGone(t *testing.T) {
	sock := sockPath(t, "dns.sock") // nothing listens here
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc, err := BindDNS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ServeDNSConn(ctx, pc, sock)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(dnsQuery("allowed.test")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("got a reply with no proxy behind the relay")
	}
}

func dnsQuery(name string) []byte {
	var q []byte
	hdr := make([]byte, 12)
	hdr[10], hdr[11] = 0, 1 // QDCOUNT
	q = append(q, hdr...)
	for i := 0; i < len(name); {
		end := i
		for end < len(name) && name[end] != '.' {
			end++
		}
		q = append(q, byte(end-i))
		q = append(q, name[i:end]...)
		i = end + 1
	}
	q = append(q, 0, 0, 1, 0, 1) // root, A, IN
	return q
}
