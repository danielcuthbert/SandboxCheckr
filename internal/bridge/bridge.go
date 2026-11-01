// Package bridge forwards a loopback TCP port to a unix socket.
//
// It exists for sandboxes with their own network namespace. Inside such a
// sandbox 127.0.0.1 is a private loopback with nothing listening on it, so a
// program configured with HTTP_PROXY=http://127.0.0.1:PORT has nowhere to go.
// The bridge runs inside the sandbox, under the same restrictions as the
// program, listens on that private loopback, and relays each connection to the
// allow-listing proxy's unix socket — which is bind-mounted in from the host.
// It adds no route of its own: the only thing it can reach is the proxy.
package bridge

import (
	"context"
	"io"
	"net"
	"time"
)

// Serve accepts on listen and relays every connection to the unix socket at
// to, until ctx is cancelled. ready is closed once the listener is bound.
func Serve(ctx context.Context, listen, to string, ready chan<- struct{}) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if ready != nil {
		close(ready)
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go relay(c, to)
	}
}

func relay(c net.Conn, to string) {
	defer c.Close()
	u, err := net.DialTimeout("unix", to, 5*time.Second)
	if err != nil {
		return
	}
	defer u.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(u, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, u); done <- struct{}{} }()
	<-done
}
