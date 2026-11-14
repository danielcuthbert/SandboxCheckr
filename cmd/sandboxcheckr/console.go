package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/console"
	"github.com/danielcuthbert/sandboxcheckr/internal/tty"
)

const consoleUsage = `sandboxcheckr console — query the proxy's event log: where each agent went, what it tried

USAGE
  sandboxcheckr console [flags] [command [filters]]

With no command it shows the state of the nation — every agent's state, relay
activity by kind, and what to look at first — then opens an interactive prompt.
With a command, it runs it and exits, so it can be scripted:

  sandboxcheckr console summary
  sandboxcheckr console agents
  sandboxcheckr console relays
  sandboxcheckr console canaries
  sandboxcheckr console agent claude-4242
  sandboxcheckr console denied since=1h
  sandboxcheckr console tail relay
  sandboxcheckr console block is.gd     # kill switch: cut a host off in every running proxy

"sandboxcheckr run" appends to the current project's own log (under
~/.local/state/sandboxcheckr/projects/), so agents in different projects do
not interleave; "sandboxcheckr console" in the same directory reads that log
back. Emitted *-proxy runners append to the shared default log. Use --events
on either to choose another file, and --agent to choose the name.

`

// defaultDenyPath matches the runners' DENY_FILE default.
func defaultDenyPath() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "sandboxcheckr", "deny.txt")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sandboxcheckr", "deny.txt")
}

// defaultEventsPath matches the runners' EVENTS default (used by standalone
// proxies and as the console's fallback).
func defaultEventsPath() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "sandboxcheckr", "events.jsonl")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "sandboxcheckr", "events.jsonl")
}

// consoleEventsPath resolves the log console reads when --events is not
// given: the current directory's project log when it exists, otherwise the
// shared default. run writes to the project log of its --workdir, so running
// the console in that project reads that project's history back.
func consoleEventsPath() string {
	if wd, err := os.Getwd(); err == nil {
		if project, err := filepath.EvalSymlinks(wd); err == nil {
			p := projectEventsPath(project)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return defaultEventsPath()
}

func runConsole(args []string) int {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), consoleUsage)
		fmt.Fprint(fs.Output(), console.Help)
		fmt.Fprint(fs.Output(), "\nFLAGS\n")
		fs.PrintDefaults()
	}
	path := fs.String("events", "", "event log `file` to read (default: this project's log, else the shared log)")
	noColor := fs.Bool("no-color", false, "force ANSI colour off")
	denyPath := fs.String("deny-file", defaultDenyPath(), "kill-switch `file` that block / unblock edit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *path == "" {
		*path = consoleEventsPath()
	}

	isTTY := tty.IsTerminal(os.Stdout)
	c := &console.Console{
		Path:     *path,
		DenyPath: *denyPath,
		Out: console.Printer{
			W:     os.Stdout,
			Color: colorEnabled(*noColor, isTTY, os.Getenv("TERM")),
			Width: tty.Width(os.Stdout),
			ASCII: os.Getenv("TERM") == "dumb" || !utf8Locale(),
		},
	}
	if err := c.Load(); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "no event log at %s yet. Run an agent with sandboxcheckr run, "+
				"or the proxy with --events, then try again.\n", *path)
		} else {
			fmt.Fprintln(os.Stderr, "reading event log:", err)
		}
		return 1
	}

	intr := make(chan os.Signal, 1)
	if rest := fs.Args(); len(rest) > 0 {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := c.Run(ctx, strings.Join(rest, " ")); err != nil && err != io.EOF {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}

	signal.Notify(intr, os.Interrupt)
	defer signal.Stop(intr)
	interactive := tty.IsTerminal(os.Stdin)
	if interactive {
		c.Banner()
		_ = c.Run(context.Background(), "summary")
		fmt.Fprintln(os.Stdout, `
type "help" for commands, or run one of the → lines above`)
	}
	c.REPL(os.Stdin, interactive, intr)
	return 0
}
