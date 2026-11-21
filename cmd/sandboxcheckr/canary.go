package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
)

const canaryUsage = `sandboxcheckr canary — internal per-run credential generation

Canaries are enabled automatically by sandboxcheckr run and emitted *-proxy
runners. Use sandboxcheckr help run for the flags and trip behavior. These
subcommands are used by the runners to share a canary set with their proxy.

USAGE
  sandboxcheckr canary new --file <set.json> --dir <private-dir> --mount <sandbox-path>
  sandboxcheckr canary env --file <set.json>

Use sandboxcheckr canary new -h or env -h for the internal flags.
`

func runCanary(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, canaryUsage)
		return 2
	}
	if args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, canaryUsage)
		return 0
	}
	fs := flag.NewFlagSet("canary "+args[0], flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), canaryUsage, "\nFLAGS\n"); fs.PrintDefaults() }
	file := fs.String("file", "", "canary set JSON")
	fs.StringVar(file, "out", "", "canary set JSON (alias for --file)")
	dir := fs.String("dir", "", "private planting directory")
	mount := fs.String("mount", "", "path visible inside the sandbox")
	pass := fs.String("pass-env", "", "passed environment names")
	extra := fs.String("extra", "", "extra exposed paths")
	tokens := multiFlag{}
	fs.Var(&tokens, "token", "external canary token `host`, or `name=value` to watch a string (e.g. from canarytokens.org); repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch args[0] {
	case "new":
		if *file == "" || *dir == "" || *mount == "" {
			return 2
		}
		// The rule `run` applies, applied here as well: the tokens arrive on
		// this command line from CANARY_TOKENS_FLAGS, expanded unquoted by the
		// runner, and --dir, --file and --mount write wherever they are
		// pointed. A token that reads as a flag must not reach this parser,
		// whoever assembled the list.
		for _, token := range tokens {
			if err := canary.ValidToken(token); err != nil {
				fmt.Fprintln(os.Stderr, "--token:", err)
				return 2
			}
		}
		s, err := canary.New(*pass, *extra, *mount)
		if err == nil {
			err = s.AddExternal(tokens)
		}
		if err == nil {
			err = s.Plant(*dir)
		}
		if err == nil {
			err = s.Write(*file)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return 1
		}
		if len(s.Credentials) == 0 {
			fmt.Fprintln(os.Stderr, "sandboxcheckr: all canary groups skipped because real credentials or config paths were passed")
		} else {
			fmt.Fprintln(os.Stderr, "sandboxcheckr: canaries active, run "+s.RunID)
		}
		if n := countExternal(s); n > 0 {
			fmt.Fprintf(os.Stderr, "sandboxcheckr: external canary tokens: %d (lookups of the token host and connections to it are forwarded so the token service alerts; every use trips at high confidence)\n", n)
		}
		return 0
	case "env":
		if *file == "" {
			return 2
		}
		s, err := canary.Read(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "canary:", err)
			return 1
		}
		keys := make([]string, 0, len(s.Env))
		for k := range s.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s=%s\n", k, s.Env[k])
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: sandboxcheckr canary new|env ...")
		return 2
	}
}

func countExternal(s *canary.Set) int {
	n := 0
	for _, c := range s.Credentials {
		if c.External {
			n++
		}
	}
	return n
}
