// Command sandboxcheckr reports what confinement mechanisms exist on this
// machine, which of them actually hold when tested, and what running untrusted
// code here would still expose.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/emit"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms"
	"github.com/danielcuthbert/sandboxcheckr/internal/probe"
	"github.com/danielcuthbert/sandboxcheckr/internal/run"
	"github.com/danielcuthbert/sandboxcheckr/internal/tty"
)

func main() {
	// The probe subcommand is checked before flag parsing: it is an internal
	// re-exec of this binary inside a candidate sandbox, not a user-facing
	// interface, and it must not be affected by the parent's flags.
	if len(os.Args) > 1 && os.Args[1] == probe.ProbeSubcommand {
		os.Exit(runProbeChild(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == probe.PeerSubcommand {
		os.Exit(runPeerChild(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "__bridge" {
		os.Exit(runBridge(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "proxy" {
		os.Exit(runProxy(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "canary" {
		os.Exit(runCanary(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(runSandbox(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "console" {
		os.Exit(runConsole(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "adopt" {
		os.Exit(runAdopt(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "lint" {
		os.Exit(runLint(os.Args[2:]))
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Printf("sandboxcheckr %s\n", run.Version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "help" {
		if len(os.Args) > 2 {
			// "sandboxcheckr help proxy" behaves like "sandboxcheckr proxy -h".
			os.Args = []string{os.Args[0], os.Args[2], "-h"}
			main()
			return
		}
		usage()
		return
	}

	var (
		asJSON     = flag.Bool("json", false, "emit the full report as JSON")
		gapsOnly   = flag.Bool("gaps", false, "print only what remains unprotected")
		noProbes   = flag.Bool("no-probes", false, "passive detection only; do not spawn confined children")
		peers      = flag.Bool("peers", false, "additionally test whether two separately-sandboxed processes can signal each other")
		noColor    = flag.Bool("no-color", false, "force ANSI colour off (otherwise auto: on for a terminal, off when piped)")
		noBanner   = flag.Bool("no-banner", false, "suppress the sandcastle banner (otherwise shown only on an interactive terminal)")
		asciiFlag  = flag.Bool("ascii", false, "force ASCII-only glyphs (otherwise auto for dumb terminals / non-UTF-8 locales)")
		widthFlag  = flag.Int("width", 0, "output width in `columns` (0 = auto-detect the terminal, else 74)")
		verbose    = flag.Bool("verbose", false, "expand findings that are fine, and show raw observed values")
		emitMech   = flag.String("emit", "", "write a ready-to-run sandbox wrapper for `mechanism` (see MECHANISMS above)")
		proxyPort  = flag.Int("proxy-port", 0, "fix the loopback `port` proxied mechanisms use (default: probing uses 8899; emitted runners pick a free port each run)")
		workdirArg = flag.String("workdir", "", "project `dir`ectory the sandbox may write to (required with --emit)")
		noBaseline = flag.Bool("no-baseline", false, "skip the unsandboxed baseline run")
		tccFlag    = flag.Bool("tcc", false, "macOS: also probe Desktop/Documents/Downloads (may show a consent prompt — click Don't Allow)")
	)
	flag.Usage = usage
	flag.Parse()

	ctx := context.Background()

	if *emitMech != "" {
		os.Exit(emitWrapper(*emitMech, *workdirArg, *proxyPort))
	}

	// Adapt to the environment rather than assuming an 80-column colour terminal.
	// A good CLI looks right whether it is on a wide iTerm, a narrow split pane,
	// a pipe into grep, or a CI log — and never writes escape sequences into a
	// file. The flags are overrides of this auto-detection, not the only control.
	isTTY := tty.IsTerminal(os.Stdout)
	term := os.Getenv("TERM")
	color := colorEnabled(*noColor, isTTY, term)
	banner := !*noBanner && isTTY
	ascii := *asciiFlag || term == "dumb" || !utf8Locale()
	width := *widthFlag
	if width == 0 && isTTY {
		width = tty.Width(os.Stdout)
	}

	if *tccFlag {
		fmt.Fprintln(os.Stderr, "Probing Desktop, Documents and Downloads. If macOS asks whether this app may access "+
			"a folder, click \"Don't Allow\" unless you really want every program started from this terminal to have it.")
	}
	rep := run.Execute(ctx, run.Options{
		SkipProbes:   *noProbes,
		PeerProbes:   *peers,
		SkipBaseline: *noBaseline,
		TCC:          *tccFlag,
		ProxyPort:    *proxyPort,
	})

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "encoding report:", err)
			os.Exit(1)
		}
	case *gapsOnly:
		emit.Gaps(os.Stdout, rep, color)
	default:
		emit.Terminal(os.Stdout, rep, emit.Options{
			Color:   color,
			Banner:  banner,
			Verbose: *verbose,
			Width:   width,
			ASCII:   ascii,
		})
	}

	// Exit non-zero when we could not recommend anything, so the tool is usable
	// as a CI gate. A confined self-check also fails, because an indeterminate
	// answer must not read as a pass.
	if rep.Recommended == "" || rep.SelfCheck.Confined {
		os.Exit(2)
	}
}

// colorEnabled decides whether to emit ANSI colour, honouring the widely-adopted
// conventions so the tool behaves the way people expect:
//   - --no-color / NO_COLOR (any value) force it off;
//   - FORCE_COLOR / CLICOLOR_FORCE=1 force it on (e.g. when piping into `less -R`);
//   - otherwise: on for an interactive terminal, off when piped or TERM=dumb.
//
// The default-off-when-piped behaviour is the important one: it stops escape
// sequences ending up in redirected files and CI logs.
func colorEnabled(noColorFlag, isTTY bool, term string) bool {
	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	return isTTY && term != "dumb"
}

// utf8Locale reports whether the environment claims a UTF-8 locale. When unset
// it assumes UTF-8, since that is the modern default and most terminals render
// it; the goal is to fall back to ASCII only when there is positive evidence the
// terminal cannot cope, not to punish a correctly-configured one.
func utf8Locale() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			u := strings.ToUpper(v)
			return strings.Contains(u, "UTF-8") || strings.Contains(u, "UTF8")
		}
	}
	return true
}

// runProbeChild is the payload executed inside a candidate sandbox. It writes
// the battery results to stdout as JSON and always exits zero: a non-zero exit
// would be indistinguishable from the sandbox killing us, and the parent needs
// the results regardless of what was blocked.
func runProbeChild(args []string) int {
	fs := flag.NewFlagSet(probe.ProbeSubcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workdir := fs.String("workdir", "", "scratch directory the sandbox should permit")
	home := fs.String("home", "", "the real home directory on the host")
	homeID := fs.String("home-id", "", "device:inode of the home directory on the host")
	online := fs.Bool("online", false, "the parent observed working DNS outside the sandbox")
	tcc := fs.Bool("tcc", false, "probe TCC-gated user folders")
	var socks multiFlag
	fs.Var(&socks, "agent-socket", "credential agent socket on the host; repeatable")
	expectProxy := fs.String("expect-proxy", "", "egress proxy a proxied sandbox must reach")
	canaryHost := fs.String("canary-host", "", "canary hostname for proxy self-verification")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	results := probe.RunBattery(probe.Options{
		Workdir: *workdir, Home: *home, HomeID: *homeID, Online: *online, TCC: *tcc,
		AgentSockets: socks, ExpectProxy: *expectProxy, CanaryHost: *canaryHost,
	})
	if err := probe.WriteResults(os.Stdout, results); err != nil {
		fmt.Fprintln(os.Stderr, "writing probe results:", err)
		return 1
	}
	return 0
}

// runPeerChild performs one half of the peer-visibility exchange inside a
// sandbox. Like the probe child it always exits zero, because a non-zero exit
// would be indistinguishable from the sandbox killing it.
func runPeerChild(args []string) int {
	fs := flag.NewFlagSet(probe.PeerSubcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	role := fs.String("role", "", "signal or observe")
	token := fs.String("token", "", "exchange token")
	hold := fs.Duration("hold", 0, "how long the signalling peer stays alive")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if err := probe.RunPeerRole(os.Stdout, probe.PeerRole(*role), *token, *hold); err != nil {
		fmt.Fprintln(os.Stderr, "peer role:", err)
		return 1
	}
	return 0
}

// emitWrapper writes the artifact for one mechanism, generated from the same
// profile the probes exercise.
func emitWrapper(id, workdir string, proxyPort int) int {
	if workdir == "" {
		fmt.Fprintln(os.Stderr, "--emit requires --workdir naming the directory the sandbox may write to")
		return 1
	}
	abs, err := filepath.Abs(workdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolving workdir:", err)
		return 1
	}
	// Resolve symlinks: on macOS a profile written against an unresolved path
	// will not match the path the kernel checks against.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	// The emitted runner is trusted code (it carries the bwrap arguments). If
	// it lands inside the sandboxed workdir, the sandboxed program can rewrite
	// it (e.g. swap --tmpfs /home for --bind) and the next invocation runs the
	// tampered wrapper.
	if cwd, err := os.Getwd(); err == nil {
		if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
			cwd = resolved
		}
		if cwd == abs || strings.HasPrefix(cwd, abs+string(filepath.Separator)) {
			fmt.Fprintf(os.Stderr, "--emit refuses to write the runner inside the sandboxed workdir (%s): a sandboxed program could edit it; run --emit from a directory outside the workdir\n", abs)
			return 1
		}
	}

	var known []string
	for _, m := range mechanisms.All(proxyPort) {
		known = append(known, m.ID())
		if m.ID() != id {
			continue
		}
		art, err := m.Wrapper(mechanism.Workdir{Path: abs})
		if err != nil {
			fmt.Fprintln(os.Stderr, "generating wrapper:", err)
			return 1
		}
		if art.FileName != "" {
			// 0o700: the runner is meant to be executed. The profile beside it
			// stays 0o600.
			if err := os.WriteFile(art.FileName, []byte(art.FileBody), 0o700); err != nil {
				fmt.Fprintln(os.Stderr, "writing profile:", err)
				return 1
			}
			fmt.Printf("Wrote %s (scoped to %s)\n", art.FileName, abs)
		}
		for name, body := range art.ExtraFiles {
			if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "writing", name+":", err)
				return 1
			}
			fmt.Printf("Wrote %s\n", name)
		}
		fmt.Println()
		fmt.Printf("Run your command with:\n  %s\n", art.Command)
		if len(art.Notes) > 0 {
			fmt.Println("\nBefore you rely on this:")
			for _, n := range art.Notes {
				fmt.Printf("  · %s\n", n)
			}
		}
		return 0
	}

	if len(known) == 0 {
		fmt.Fprintf(os.Stderr, "no sandbox mechanism is implemented for %s yet\n", runtime.GOOS)
		return 1
	}
	fmt.Fprintf(os.Stderr, "unknown mechanism %q (available: %s)\n", id, strings.Join(known, ", "))
	return 1
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, `sandboxcheckr %s — what can untrusted code do on this machine, and what would contain it?

USAGE
  sandboxcheckr [flags]                              report: what leaks today, and what each sandbox stops
  sandboxcheckr run [flags] <command> [args...]      run it now in a proxied sandbox with canaries
  sandboxcheckr --emit <mechanism> --workdir <dir>   write a runner script for one sandbox, scoped to <dir>
  sandboxcheckr proxy [flags]                        run the allow-listing egress proxy
  sandboxcheckr canary new|env [flags]               create/read a per-run canary set (used by runners)
  sandboxcheckr console [command]                    query the proxy event log: where each agent went
  sandboxcheckr adopt [--write]                      turn an observe or denied run's log into sandboxcheckr.toml
  sandboxcheckr lint <profile.sb>                    statically audit a Seatbelt profile
  sandboxcheckr version
  sandboxcheckr help [run|proxy|console|lint|canary] this help, or help for a subcommand

`, run.Version)
	writeMechanismHelp(out)
	fmt.Fprint(out, proxyHelpSummary)
	fmt.Fprint(out, canaryHelpSummary)
	fmt.Fprint(out, "\nFLAGS\n")
	flag.PrintDefaults()
	fmt.Fprint(out, `
EXAMPLES
  sandboxcheckr                                           full report
  sandboxcheckr run claude                                run Claude in the current project
  sandboxcheckr run --observe claude                      discover hosts before enforcing an allow-list
  sandboxcheckr adopt --write                             then turn what it saw into sandboxcheckr.toml
  sandboxcheckr run --allow registry.npmjs.org -- npm install
  sandboxcheckr --tcc                                     also check Desktop/Documents/Downloads (macOS)
  sandboxcheckr run --canary-kill claude                  stop on a high-confidence trip
  sandboxcheckr console canaries                          review trips across agents

EMITTED RUNNERS (ADVANCED)
  sandboxcheckr --emit seatbelt-proxy --workdir ~/code/app
  sh seatbelt-proxy.sh claude
  ALLOW="--observe" sh seatbelt-proxy.sh claude

ENVIRONMENT (read by emitted runner scripts)
  PASS_ENV   names of variables to pass into the sandbox (default: none — the environment is cleared)
  EXTRA_RO   extra paths the program may read
  EXTRA_RW   extra paths the program may read and write, e.g. "$HOME/.claude $HOME/.claude.json"
  ALLOW_DOTENV=1       let the program read .env files in the workdir (denied by default)
  ALLOW_EXEC_CONFIG=1  let it write git hooks and config, CI workflows, editor tasks (.vscode,
                       .idea), .husky, .envrc — files another program runs later, outside the
                       sandbox (denied by default)
  ALLOW      flags for the runner's proxy (default: --allow api.anthropic.com). Any proxy flag
             works here: --observe, --allow, --allow-port, --allow-private-host, --rule.
             See: sandboxcheckr help proxy
  PORT       fix the runner's proxy port (default: a free port each run, so sandboxes
             started together never share a proxy)
  PROXY_LOG  where the runner's proxy writes its decisions (default: a private per-run
             directory outside the workdir, which the sandboxed program cannot edit;
             the summary is printed when the program exits)
  CANARY=0  disable canaries in an emitted proxied runner (run: --no-canary)
  CANARY_KILL=1  stop its sandbox process on a high-confidence trip (run: --canary-kill)

EXIT STATUS (report command)
  0  a usable sandbox was found and measured
  1  usage or I/O error
  2  nothing usable could be recommended, or SandboxCheckr was itself sandboxed (results unreliable)

RUN EXIT STATUS
  3  a canary tripped; otherwise the sandboxed command's exit status

Docs: https://github.com/danielcuthbert/sandboxcheckr
`)
}

// writeMechanismHelp lists the mechanisms --emit accepts on THIS platform,
// generated from the same registry --emit uses, so the help text cannot drift
// from what the binary actually supports.
func writeMechanismHelp(out io.Writer) {
	ms := mechanisms.All(0)
	fmt.Fprintf(out, "MECHANISMS (for --emit, on %s)\n", runtime.GOOS)
	if len(ms) == 0 {
		fmt.Fprintf(out, "  none yet on %s — the report still shows host posture and what an unsandboxed program can do\n", runtime.GOOS)
		return
	}
	w := 0
	for _, m := range ms {
		w = max(w, len(m.ID()))
	}
	for _, m := range ms {
		fmt.Fprintf(out, "  %-*s  %s\n", w, m.ID(), m.BestFor())
	}
}

// proxyHelpSummary is the egress-proxy section of the main help. It is a
// summary on purpose: what the proxy controls and the flags that change it, so
// a reader of -h knows the controls exist. Every flag's full description is in
// "sandboxcheckr help proxy", and a test checks both mention every flag.
const proxyHelpSummary = `
EGRESS PROXY (used by sandboxcheckr run and the *-proxy mechanisms)
  With "run", use --allow, --rule, --allow-port, --allow-private-host or
  --observe; other commands get no destinations at all unless you allow them.
  Emitted runners use ALLOW=.
  Each run gets its own proxy on a free port. Direct sockets and DNS are denied in
  the sandbox, so the proxy is the only way out. What it controls:
    hosts      only allowed hosts (Claude default api.anthropic.com) --allow host, --allow .domain
    ports      443 and 80                                        proxy: --allow-port N
    private    internal and metadata addresses refused           proxy: --allow-private-host host
    requests   e.g. download-only: GET/HEAD, optional paths      --rule host:GET,HEAD[:/path]
               (ruled hosts are TLS-inspected with a per-run CA trusted only in the sandbox)
    uploads    bytes sent per host counted; > 1 MiB flagged      (always on)
    writes     first data-sending request per host flagged       (plain HTTP and --rule hosts)
    code hosts suggested a path rule, not just download-only     --rule host:GET,HEAD:/your-org/
  --observe allows ordinary hosts and, on exit, prints a ready ALLOW= line;
  canary trips stay blocked.
  Full detail: sandboxcheckr help proxy
`

const canaryHelpSummary = `
CANARY CREDENTIALS (on by default in sandboxcheckr run and emitted *-proxy runners)
  Each run plants fake credentials with unique .invalid hosts in private scratch.
  The proxy denies and logs use of those hosts, even in --observe mode, and
  detects token strings in traffic it can read. Trips appear first in the exit
  summary, in sandboxcheckr console canaries, and make the runner exit 3.
  With "run", --canary-kill stops the command on a high-confidence trip;
  --no-canary disables planting. No trip does not prove the run was clean:
  token strings inside unruled HTTPS and unplanted secrets are invisible.
  Full detail: sandboxcheckr help run
`
