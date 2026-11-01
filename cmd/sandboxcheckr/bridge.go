package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/danielcuthbert/sandboxcheckr/internal/bridge"
)

// runBridge is the hidden __bridge subcommand: it starts the loopback-to-unix
// forwarder, then runs the given command and exits with its status. It runs
// inside the sandbox, so it is confined exactly as the command is.
func runBridge(args []string) int {
	fs := flag.NewFlagSet("__bridge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8899", "loopback address to listen on inside the sandbox")
	to := fs.String("to", "", "unix socket of the allow-listing proxy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if *to == "" || len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: __bridge --to <socket> -- <command> [args...]")
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- bridge.Serve(ctx, *listen, *to, ready) }()
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
