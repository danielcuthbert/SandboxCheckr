package console

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
)

// Help is the console's command reference.
const Help = `COMMANDS
  summary  [filters]         state of the nation: overview, agents, relays, what to look at
                             (shown when the console opens; alias: status)
  agents                     one row per agent: hosts, refusals, relays, signals
  agent <name>               everything one agent did, in order
  hosts    [filters]         one row per destination, with the agents that used it
  relays   [filters]         store-or-forward hosts only (shorteners, fetchers, pastes, tunnels)
  canaries [filters]         canary trips, with agent and confidence
  shared   [filters]         hosts more than one agent reached — candidate message boards
  denied   [filters]         every refusal, in order
  events   [filters]         raw events, in order (alias: log)
  tail     [filters]         follow new events as they are written; Ctrl-C stops
  block <host> [host…]       cut a host off now, in every running proxy (kill switch)
  unblock <host> [host…]     remove it from the kill switch
  blocked                    list what the kill switch refuses
  reload                     re-read the log
  help                       this text
  quit                       leave (also: exit, Ctrl-D)

FILTERS (combine freely)
  agent=<name>  agent=claude-*   one agent, or a prefix
  host=<text>                    host contains text
  decision=allow|deny|observe
  kind=connect|request|write|upload|close|canary
  since=15m  since=2026-10-12T09:00:00Z
  relay                          store-or-forward hosts only

  "!" marks a host that relays on a plain GET (shortener, fetcher, CORS proxy,
  tunnel): no --rule contains it.
`

// Console holds a loaded event log.
type Console struct {
	Path string
	// DenyPath is the kill-switch file block and unblock edit. Empty disables
	// them.
	DenyPath string
	Out      Printer
	Now      func() time.Time
	evs      []events.Event
	skipped  int
}

// Load reads the log at c.Path.
func (c *Console) Load() error {
	f, err := os.Open(c.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	c.evs, c.skipped = events.Read(f)
	return nil
}

// SetEvents replaces the loaded events (tests, and callers that read the log
// themselves).
func (c *Console) SetEvents(evs []events.Event) { c.evs = evs }

func (c *Console) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Banner describes what is loaded.
func (c *Console) Banner() {
	agents := map[string]bool{}
	for _, e := range c.evs {
		agents[e.Agent] = true
	}
	fmt.Fprintf(c.Out.W, "%s: %d events from %d agents", events.Clean(c.Path, 120), len(c.evs), len(agents))
	if c.skipped > 0 {
		fmt.Fprintf(c.Out.W, " (%d unreadable lines skipped)", c.skipped)
	}
	fmt.Fprintln(c.Out.W)
}

// Run executes one command line. It returns io.EOF for quit.
func (c *Console) Run(ctx context.Context, line string) error {
	fields := strings.Fields(strings.TrimRight(strings.TrimSpace(line), ";"))
	if len(fields) == 0 {
		return nil
	}
	// Accept the command styles people type from habit in other consoles:
	// /exit (chat tools), \q (psql), :q (vim).
	cmd, args := strings.ToLower(strings.TrimLeft(fields[0], `/\:`)), fields[1:]
	filter := func(extra ...string) (Filter, error) {
		return ParseFilter(append(args, extra...), c.now())
	}
	switch cmd {
	case "quit", "exit", "q", "bye":
		return io.EOF
	case "help", "?", "h":
		fmt.Fprint(c.Out.W, Help)
	case "reload":
		if err := c.Load(); err != nil {
			return err
		}
		c.Banner()
	case "summary", "status", "overview":
		f, err := filter()
		if err != nil {
			return err
		}
		c.Out.PrintSummary(Summarise(Select(c.evs, f)))
	case "agents":
		f, err := filter()
		if err != nil {
			return err
		}
		c.Out.PrintAgents(Agents(Select(c.evs, f)))
	case "agent":
		if len(args) == 0 {
			return fmt.Errorf("usage: agent <name> [filters]")
		}
		name := args[0]
		args = args[1:]
		f, err := filter("agent=" + name)
		if err != nil {
			return err
		}
		sel := Select(c.evs, f)
		if len(sel) == 0 {
			return fmt.Errorf("no events for agent %q; try: agents", events.Clean(name, 40))
		}
		c.Out.PrintAgents(Agents(sel))
		fmt.Fprintln(c.Out.W)
		c.Out.PrintEvents(dropClose(sel), false)
	case "hosts":
		f, err := filter()
		if err != nil {
			return err
		}
		c.Out.PrintHosts(Hosts(Select(c.evs, f)))
	case "relays", "relay":
		f, err := filter("relay")
		if err != nil {
			return err
		}
		c.Out.PrintHosts(Hosts(Select(c.evs, f)))
	case "canaries", "canary":
		f, err := filter("kind=canary")
		if err != nil {
			return err
		}
		c.Out.PrintEvents(Select(c.evs, f), true)
	case "shared":
		f, err := filter()
		if err != nil {
			return err
		}
		rows := Shared(Select(c.evs, f))
		if len(rows) == 0 {
			fmt.Fprintln(c.Out.W, "no host was reached by more than one agent")
			return nil
		}
		c.Out.PrintHosts(rows)
	case "denied", "deny":
		f, err := filter("decision=deny")
		if err != nil {
			return err
		}
		c.Out.PrintEvents(Select(c.evs, f), true)
	case "events", "log":
		f, err := filter()
		if err != nil {
			return err
		}
		c.Out.PrintEvents(Select(c.evs, f), true)
	case "block":
		if len(args) == 0 {
			return fmt.Errorf("usage: block <host> [host…]")
		}
		return c.editDeny(args, true)
	case "unblock":
		if len(args) == 0 {
			return fmt.Errorf("usage: unblock <host> [host…]")
		}
		return c.editDeny(args, false)
	case "blocked":
		return c.showDeny()
	case "tail", "follow":
		f, err := filter()
		if err != nil {
			return err
		}
		return c.Tail(ctx, f)
	default:
		return fmt.Errorf("unknown command %q; type help", events.Clean(cmd, 40))
	}
	return nil
}

// dropClose removes byte-count events, which clutter a per-agent timeline.
func dropClose(evs []events.Event) []events.Event {
	var out []events.Event
	for _, e := range evs {
		if e.Kind != events.KindClose {
			out = append(out, e)
		}
	}
	return out
}

// Tail prints events matching f as they are appended, until ctx is done.
func (c *Console) Tail(ctx context.Context, f Filter) error {
	fh, err := os.Open(c.Path)
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	off, err := fh.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out.W, "following new events — Ctrl-C to stop")
	var partial []byte
	buf := make([]byte, 64*1024)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(c.Out.W, "\nstopped following")
			return nil
		case <-tick.C:
		}
		if fi, err := os.Stat(c.Path); err == nil && fi.Size() < off {
			// Truncated or replaced: start again from the top.
			_ = fh.Close()
			if fh, err = os.Open(c.Path); err != nil {
				return err
			}
			off, partial = 0, nil
		}
		for {
			n, err := fh.ReadAt(buf, off)
			if n > 0 {
				off += int64(n)
				partial = append(partial, buf[:n]...)
				for {
					i := strings.IndexByte(string(partial), '\n')
					if i < 0 {
						break
					}
					line := partial[:i+1]
					partial = partial[i+1:]
					evs, _ := events.Read(strings.NewReader(string(line)))
					for _, e := range evs {
						c.evs = append(c.evs, e)
						if f.Match(e) && e.Kind != events.KindClose {
							c.Out.PrintEvent(e, true)
						}
					}
				}
			}
			if err != nil || n < len(buf) {
				break
			}
		}
	}
}

// REPL reads commands from in until quit or end of input (Ctrl-D).
//
// Ctrl-C (delivered on intr) stops a running command such as tail and returns
// to the prompt. At an idle prompt it prints how to leave; pressed twice in a
// row there, it leaves. A Ctrl-C at the prompt must never carry over and
// cancel the next command.
func (c *Console) REPL(in io.Reader, interactive bool, intr <-chan os.Signal) {
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	prompt := func() {
		if interactive {
			fmt.Fprint(c.Out.W, c.Out.c("1", "sandboxcheckr> "))
		}
	}
	prompt()
	armed := false // a Ctrl-C at the idle prompt was just pressed
	for {
		select {
		case <-intr:
			if armed {
				fmt.Fprintln(c.Out.W)
				return
			}
			armed = true
			fmt.Fprintln(c.Out.W, "\n(type quit, press Ctrl-D, or Ctrl-C again to leave)")
			prompt()
			continue
		case line, ok := <-lines:
			if !ok {
				if interactive {
					fmt.Fprintln(c.Out.W)
				}
				return
			}
			armed = false
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				select {
				case <-intr:
					cancel()
				case <-done:
				}
			}()
			err := c.Run(ctx, line)
			close(done)
			cancel()
			if err == io.EOF {
				return
			}
			if err != nil {
				fmt.Fprintln(c.Out.W, "error:", err)
			}
			prompt()
		}
	}
}
