package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/danielcuthbert/sandboxcheckr/internal/bridge"
)

// parseBindPorts turns a comma-separated port list into the loopback
// addresses the bridge binds. Both 127.0.0.1 and [::1] are bound; a bind that
// fails is skipped with a warning by ServeAll.
func parseBindPorts(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var binds []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid bind port %q", part)
		}
		binds = append(binds, fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port))
	}
	return binds, nil
}

// runBridge is the hidden __bridge subcommand: it starts the loopback-to-unix
// forwarder, then runs the given command and exits with its status. It runs
// inside the sandbox, so it is confined exactly as the command is.
func runBridge(args []string) int {
	fs := flag.NewFlagSet("__bridge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8899", "loopback address to listen on inside the sandbox")
	to := fs.String("to", "", "unix socket of the allow-listing proxy")
	bindPorts := fs.String("bind-ports", "", "comma-separated permitted ports to also bind on the sandbox loopback, tunnelling direct connections through the proxy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if *to == "" || len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: __bridge --to <socket> [--bind-ports 8000,8080] -- <command> [args...]")
		return 2
	}
	binds, err := parseBindPorts(*bindPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bridge: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		errc <- bridge.ServeAll(ctx, *listen, binds, *to, func(addr string, err error) {
			fmt.Fprintf(os.Stderr, "bridge: not binding loopback %s: %v\n", addr, err)
		}, ready)
	}()
	select {
	case <-ready:
	case err := <-errc:
		fmt.Fprintln(os.Stderr, "bridge:", err)
		return 1
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge: starting command:", err)
		return 127
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}
