package bridge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestDNSRelayForwardsQueriesToProxy sends a query through the UDP relay to a
// fake proxy that echoes framed queries back, and expects the reply.
func TestDNSRelayForwardsQueriesToProxy(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dns.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Fake proxy: one framed query in, one framed response out (marked).
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

// TestDNSRelayDropsQueriesWhenProxyGone checks that a dead proxy is a dropped
// datagram, not a crash: the relay keeps serving.
func TestDNSRelayDropsQueriesWhenProxyGone(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dns.sock") // nothing listens here
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
