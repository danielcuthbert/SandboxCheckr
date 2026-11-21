package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/canary"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/projconfig"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

const runUsage = `sandboxcheckr run — run a command in this project's proxied sandbox

USAGE
  sandboxcheckr run [flags] <command> [args...]

The current directory is the project by default. If the project contains a
sandboxcheckr.toml policy file, it is the baseline: command-line flags are
added to it (list flags) or override it (scalar flags). Canary credentials
and the egress proxy are on by default. Canaries use unique .invalid hosts
and fake tokens in private scratch, never your project or real home. Any trip
is denied, logged, printed at exit, and returns status 3. --observe still
denies canary trips. --canary-kill stops the command on a high-confidence
trip; --no-canary disables planting. --canary-token adds a token from an
outside token service (for example a DNS token from canarytokens.org), as a
hostname or as name=value to watch a string: lookups of the token host and
connections to it are forwarded so the token service can alert you, and every
use of the token trips at high confidence. No trip does not prove the run was
clean: unruled HTTPS hides token strings.

Examples:
  sandboxcheckr run claude
  sandboxcheckr run --workdir ~/code/app -- claude -p "review this code"
  sandboxcheckr run --allow registry.npmjs.org -- npm install
  sandboxcheckr run --observe -- npm test  # discovers hosts; still blocks canary trips

A sandboxcheckr.toml beside the code removes the flags from every later run:

  # sandboxcheckr.toml
  allow = ["localhost"]
  allow-private-host = ["localhost"]
  allow-port = [8000]
  ro = ["~/tools/raptor"]

Claude keeps api.anthropic.com and Codex api.openai.com unless you change it.
Any other command starts with NO network: the proxy refuses every destination
until you name one with --allow or the policy file. A local inference endpoint
is private address space, which the proxy refuses by default, so name the
host, that fact, and its port explicitly.

For Claude or Codex, an existing API key is passed if set; otherwise existing
login files are granted. Known agents also get their state directory (omp
gets ~/.omp). No other shell credentials are passed unless you name them
with --pass-env or --rw. --no-agent-auth disables these presets.

A python virtualenv is picked up automatically: the activated VIRTUAL_ENV,
or .venv or venv in the project. It is granted read-only and put first on
PATH inside the sandbox, so the interpreter and its packages resolve.

The event log is per project by default: each project's runs append to a log
under ~/.local/state/sandboxcheckr/projects/, and "sandboxcheckr console"
run in the same project reads it back. --events chooses an explicit file.

FLAGS
`

// allowFlagsFor builds the ALLOW value the runner passes to this run's proxy.
// Claude and Codex keep their provider's endpoint; every other command gets an
// explicit deny, because falling through to the proxy's api.anthropic.com
// default handed `run -- npm install` a working route to a model API nobody
// had configured. User flags are appended to whatever baseline applies.
func allowFlagsFor(commandName string, allows, rules, ports, privHosts []string) string {
	var parts []string
	switch commandName {
	case "claude":
		parts = append(parts, "--allow api.anthropic.com")
	case "codex":
		parts = append(parts, "--allow api.openai.com")
	default:
		if len(allows) == 0 && len(rules) == 0 {
			parts = append(parts, "--deny-all")
		}
	}
	for _, host := range allows {
		parts = append(parts, "--allow "+host)
	}
	for _, rule := range rules {
		parts = append(parts, "--rule "+rule)
	}
	for _, port := range ports {
		parts = append(parts, "--allow-port "+port)
	}
	for _, host := range privHosts {
		parts = append(parts, "--allow-private-host "+host)
	}
	return strings.Join(parts, " ")
}

// pathHelp accompanies a failed command lookup: the command is found exactly
// as it would be without the sandbox, so the fix is the usual PATH work.
const pathHelp = `The command is looked up in this shell's PATH, as it would be without the sandbox. To fix:
  - install it, or run it by absolute path: sandboxcheckr run /path/to/command ...
  - if it comes from a version manager (nvm, pyenv, mise, ...), source that
    manager's init script in this shell so PATH is set
  - check the search path with: echo $PATH
`

// runOptions holds run's parsed flags. A project's sandboxcheckr.toml is
// merged into it before validation, so the rest of the pipeline sees one
// policy regardless of where each value came from.
type runOptions struct {
	allows, rules, ports, privHosts, passes, ro, rw multiFlag
	canaryTokens                                    multiFlag
	observe, canaryKill, noCanary, noAgentAuth      bool
	events, agent, denyFile                         string
}

func runSandbox(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), runUsage); fs.PrintDefaults() }
	workdir := fs.String("workdir", ".", "project `directory` (default: current directory)")
	o := &runOptions{}
	fs.Var(&o.allows, "allow", "permit this destination `host`; repeatable")
	fs.Var(&o.rules, "rule", "restrict an allowed host: `host:METHODS[:/path]`; repeatable")
	fs.Var(&o.ports, "allow-port", "destination `port` to permit for allowed hosts; repeatable (default 443 and 80)")
	fs.Var(&o.privHosts, "allow-private-host", "let this `host` resolve to a private address (a local inference server, an internal registry); repeatable. Link-local/metadata stays refused")
	fs.Var(&o.passes, "pass-env", "pass this named environment variable; repeatable")
	fs.Var(&o.rw, "rw", "grant this existing `path` read/write access; repeatable")
	fs.Var(&o.ro, "ro", "grant this existing `path` read-only access; repeatable")
	fs.BoolVar(&o.observe, "observe", false, "permit and log ordinary destinations; canary trips stay blocked")
	fs.StringVar(&o.events, "events", "", "event log `file` outside the project (default: this project's log)")
	fs.StringVar(&o.agent, "agent", "", "agent label in the event log")
	fs.StringVar(&o.denyFile, "deny-file", "", "live kill-switch `file`: hosts listed here are cut off mid-run")
	fs.BoolVar(&o.canaryKill, "canary-kill", false, "stop the command on a high-confidence canary trip")
	fs.BoolVar(&o.noCanary, "no-canary", false, "disable canary credentials (the proxy prints this)")
	fs.Var(&o.canaryTokens, "canary-token", "external canary token `host` (a DNS token from canarytokens.org) or `name=value` to watch a string; repeatable. Lookups of the token host and connections to it are forwarded so the token service alerts, and every use trips at high confidence")
	fs.BoolVar(&o.noAgentAuth, "no-agent-auth", false, "do not grant known agents their login credentials or state directories")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fs.Usage()
		return 2
	}
	// The runner looks the command up in this shell's PATH and would fail
	// 127 after the proxy had already started. Fail here instead, with the
	// fix, before anything is built or started.
	if _, err := exec.LookPath(argv[0]); err != nil {
		fmt.Fprintf(os.Stderr, "run: cannot find %q: %v\n%s", argv[0], err, pathHelp)
		return 127
	}
	project, err := filepath.Abs(*workdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--workdir:", err)
		return 2
	}
	if project, err = filepath.EvalSymlinks(project); err != nil {
		fmt.Fprintln(os.Stderr, "--workdir:", err)
		return 2
	}
	if fi, err := os.Stat(project); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "--workdir: %s is not a directory\n", project)
		return 2
	}
	if mechanism.TooBroadToGrant(project) {
		fmt.Fprintln(os.Stderr, "--workdir must name a project directory, not / or your home directory")
		return 2
	}
	// The proxy decision log is evidence about what the program did. Inside
	// the workdir the sandboxed program could rewrite it, so an inherited
	// PROXY_LOG pointing there is refused rather than honoured.
	if inherited := os.Getenv("PROXY_LOG"); inherited != "" {
		if _, err := resolveOutsideProject("the proxy decision log (PROXY_LOG)", inherited, project); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	// The project's sandboxcheckr.toml is the baseline policy. It is loaded
	// after the workdir resolves (the file lives in the workdir) and merged
	// before validation, so every check below applies to the merged policy.
	cfg, err := projconfig.Load(filepath.Join(project, projconfig.Name))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	mergeProjectConfig(cfg, set, o)
	if o.observe && (len(o.allows) > 0 || len(o.rules) > 0 || len(o.ports) > 0 || len(o.privHosts) > 0) {
		fmt.Fprintln(os.Stderr, "--observe (also from sandboxcheckr.toml) cannot be combined with --allow, --rule, --allow-port or --allow-private-host")
		return 2
	}
	for i, host := range o.allows {
		if strings.HasPrefix(host, "*.") {
			host = host[1:]
		}
		if !proxy.ValidHostname(strings.TrimPrefix(host, ".")) {
			fmt.Fprintf(os.Stderr, "--allow: invalid hostname %q\n", host)
			return 2
		}
		if _, err := proxy.ParseRule(host); err != nil {
			fmt.Fprintln(os.Stderr, "--allow:", err)
			return 2
		}
		o.allows[i] = host
	}
	for _, rule := range o.rules {
		if !safeProxyWord(rule) {
			fmt.Fprintf(os.Stderr, "--rule: unsupported shell characters in %q\n", rule)
			return 2
		}
		if _, err := proxy.ParseHostRule(rule); err != nil {
			fmt.Fprintln(os.Stderr, "--rule:", err)
			return 2
		}
	}
	for _, port := range o.ports {
		// Digits only, so the value cannot split into flags when the runner
		// expands $ALLOW unquoted.
		if !proxy.ValidPort(port) {
			fmt.Fprintf(os.Stderr, "--allow-port: invalid port %q\n", port)
			return 2
		}
	}
	for _, host := range o.privHosts {
		if strings.HasPrefix(host, "*.") {
			host = host[1:]
		}
		if !proxy.ValidHostname(strings.TrimPrefix(host, ".")) {
			fmt.Fprintf(os.Stderr, "--allow-private-host: invalid hostname %q\n", host)
			return 2
		}
	}
	for _, name := range o.passes {
		if !validEnvName(name) {
			fmt.Fprintf(os.Stderr, "--pass-env: invalid name %q\n", name)
			return 2
		}
	}
	// Tokens reach the runner through CANARY_TOKENS_FLAGS, which the runner
	// expands unquoted. Every other user-supplied list is checked here for the
	// same reason: a token that word-splits becomes extra argv for canary new,
	// whose --dir and --file would then name a path from the project file.
	for _, token := range o.canaryTokens {
		if err := canary.ValidToken(token); err != nil {
			fmt.Fprintf(os.Stderr, "--canary-token: %v\n", err)
			return 2
		}
	}
	for _, label := range []struct {
		paths *multiFlag
		noun  string
	}{
		{&o.rw, "--rw"},
		{&o.ro, "--ro"},
	} {
		for i, path := range *label.paths {
			abs, err := validateGrant(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", label.noun, err)
				return 2
			}
			(*label.paths)[i] = abs
		}
	}
	var selected mechanism.Mechanism
	for _, m := range mechanisms.All(0) {
		if m.Egress() == "proxy" {
			selected = m
			break
		}
	}
	if selected == nil {
		fmt.Fprintf(os.Stderr, "no proxied sandbox is implemented for %s\n", runtime.GOOS)
		return 1
	}
	checkCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	availability := selected.Detect(checkCtx)
	cancel()
	if availability.Status != model.StatusPass {
		fmt.Fprintf(os.Stderr, "cannot start %s: %s\n", selected.ID(), availability.Detail)
		return 1
	}
	selectedEvents, err := eventLogForRun(o.events, project)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--events:", err)
		return 2
	}
	o.events = selectedEvents
	art, err := selected.Wrapper(mechanism.Workdir{Path: project})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generating runner:", err)
		return 1
	}
	sweepStalePrivateDirs()
	// Absolute template: an inherited TMPDIR must not move the runner (which
	// knows the policy) somewhere the sandboxed program can read.
	private, err := os.MkdirTemp("/tmp", "sandboxcheckr-run-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "creating private runner:", err)
		return 1
	}
	defer os.RemoveAll(private)
	if err := writeRunArtifact(private, art); err != nil {
		fmt.Fprintln(os.Stderr, "writing private runner:", err)
		return 1
	}

	env := os.Environ()
	// This command takes its configuration from flags. Inherited policy
	// switches must not silently widen (or subvert) the new sandbox:
	// SANDBOXCHECKR would choose which binary the runner execs, AGENT forges
	// the event-log label, DENY_FILE/ALLOW_* change the policy, TMPDIR would
	// move private runner state somewhere the child can see. CANARY_TOKENS_FLAGS
	// and BIND_PORTS are expanded unquoted by the runner, so an inherited value
	// would reach the child's argv, and an inherited PORT would pin two runs to
	// one proxy, merging their allow-lists.
	for _, name := range []string{"PASS_ENV", "EXTRA_RW", "EXTRA_RO", "ALLOW", "CANARY", "CANARY_KILL",
		"SANDBOXCHECKR", "AGENT", "DENY_FILE", "ALLOW_DOTENV", "ALLOW_EXEC_CONFIG", "TMPDIR",
		"CANARY_TOKENS_FLAGS", "BIND_PORTS", "PORT"} {
		env = replaceEnv(env, name, "")
	}
	passNames := []string(o.passes)
	rwPaths := []string(o.rw)
	commandName := filepath.Base(argv[0])

	// A detected virtualenv becomes visible inside the sandbox: its directory
	// is bound read-only and its bin directory goes first on PATH, so the
	// interpreter, its console scripts and its site-packages all resolve
	// without the user writing a shell wrapper. A venv inside the workdir is
	// already bound with the project and needs no extra grant.
	var venvBin string
	if root, bin, ok := detectVenv(project); ok {
		venvBin = bin
		passNames = append(passNames, "PATH")
		if root != project && !strings.HasPrefix(root, project+string(filepath.Separator)) {
			abs, err := validateGrant(root)
			if err != nil {
				fmt.Fprintf(os.Stderr, "venv %s: %v\n", root, err)
				return 2
			}
			o.ro = append(o.ro, abs)
		}
		fmt.Fprintln(os.Stderr, "sandboxcheckr: using python venv", root, "(read-only, first on PATH)")
	}

	// Known agents get their state directory, without which they cannot run
	// at all. Unlike the credential grants below this carries no secrets by
	// design, but --no-agent-auth still turns it off: one flag means no
	// automatic grants.
	if !o.noAgentAuth {
		if dirs, ok := agentStateDirs[commandName]; ok {
			if home, err := os.UserHomeDir(); err == nil {
				for _, name := range dirs {
					path := filepath.Join(home, name)
					if _, err := os.Stat(path); err != nil {
						continue
					}
					if real, err := filepath.EvalSymlinks(path); err == nil {
						path = real
					}
					if mechanism.TooBroadToGrant(path) || strings.ContainsAny(path, " \t\r\n*?[]") {
						fmt.Fprintf(os.Stderr, "agent state path %q cannot be passed safely by this runner\n", path)
						return 2
					}
					rwPaths = append(rwPaths, path)
					fmt.Fprintln(os.Stderr, "sandboxcheckr: granting", commandName, "state directory", path)
				}
			}
		}
	}

	if !o.noAgentAuth {
		var key string
		var files []string
		switch commandName {
		case "claude":
			key, files = "ANTHROPIC_API_KEY", []string{".claude", ".claude.json"}
		case "codex":
			key, files = "OPENAI_API_KEY", []string{".codex"}
		}
		if key != "" {
			if os.Getenv(key) != "" {
				passNames = append(passNames, key)
				fmt.Fprintln(os.Stderr, "sandboxcheckr: passing", key, "to", commandName)
			} else if home, err := os.UserHomeDir(); err == nil {
				for _, name := range files {
					path := filepath.Join(home, name)
					if _, err := os.Stat(path); err == nil {
						if real, err := filepath.EvalSymlinks(path); err == nil {
							path = real
						}
						if mechanism.TooBroadToGrant(path) || strings.ContainsAny(path, " \t\r\n*?[]") {
							fmt.Fprintf(os.Stderr, "agent login path %q cannot be passed safely by this runner\n", path)
							return 2
						}
						rwPaths = append(rwPaths, path)
						fmt.Fprintln(os.Stderr, "sandboxcheckr: granting", commandName, "login file", path)
					}
				}
			}
		}
	}
	for _, path := range rwPaths {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real
		}
		if o.events == path || strings.HasPrefix(o.events, path+string(filepath.Separator)) {
			fmt.Fprintf(os.Stderr, "event log %s is inside a read/write grant %s; choose --events outside that grant\n", o.events, path)
			return 2
		}
	}
	if len(passNames) > 0 {
		env = replaceEnv(env, "PASS_ENV", strings.Join(unique(passNames), " "))
	}
	if len(rwPaths) > 0 {
		env = replaceEnv(env, "EXTRA_RW", strings.Join(unique(rwPaths), " "))
	}
	if len(o.ro) > 0 {
		env = replaceEnv(env, "EXTRA_RO", strings.Join(unique(o.ro), " "))
	}
	if venvBin != "" {
		// PASS_ENV=PATH passes the runner shell's PATH through --setenv, and
		// the runner's per-run --setenv lands after the baked ones, so this
		// replaces the sandbox's PATH rather than fighting it.
		if host := os.Getenv("PATH"); host != "" {
			env = replaceEnv(env, "PATH", venvBin+":"+host)
		} else {
			env = replaceEnv(env, "PATH", venvBin)
		}
	}
	env = replaceEnv(env, "EVENTS", o.events)
	if o.agent != "" {
		env = replaceEnv(env, "AGENT", o.agent)
	}
	if o.denyFile != "" {
		env = replaceEnv(env, "DENY_FILE", o.denyFile)
	}
	if o.canaryKill {
		env = replaceEnv(env, "CANARY_KILL", "1")
	}
	if o.noCanary {
		env = replaceEnv(env, "CANARY", "0")
	}
	if len(o.canaryTokens) > 0 {
		flags := make([]string, 0, 2*len(o.canaryTokens))
		for _, h := range o.canaryTokens {
			flags = append(flags, "--token", h)
		}
		env = replaceEnv(env, "CANARY_TOKENS_FLAGS", strings.Join(flags, " "))
	}
	if o.observe {
		env = replaceEnv(env, "ALLOW", "--observe")
	} else {
		env = replaceEnv(env, "ALLOW", allowFlagsFor(commandName, o.allows, o.rules, o.ports, o.privHosts))
	}
	// Permitted ports are also bound on the sandbox's loopback, so tools that
	// bypass HTTP proxies for localhost (NO_PROXY listing loopback hosts)
	// still traverse the egress proxy. The bridge's own port is excluded: it
	// is already listening there.
	if bindPorts := bindPortsFor(o.ports); len(bindPorts) > 0 {
		env = replaceEnv(env, "BIND_PORTS", strings.Join(bindPorts, ","))
	}

	cmd := exec.Command("/bin/sh", append([]string{filepath.Join(private, art.FileName)}, argv...)...)
	cmd.Dir, cmd.Env = project, env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// If run is killed outright (SIGKILL skips every deferred cleanup, so
	// stopOrphanedProxy would never fire), take the runner shell with it; the
	// proxy arms its own PDEATHSIG against that shell, so the whole chain —
	// run, runner, proxy, sandbox — dies together.
	armRunnerPdeathsig(cmd)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "starting runner:", err)
		return 1
	}
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		select {
		case sig := <-signals:
			_ = cmd.Process.Signal(sig)
		case <-done:
		}
	}()
	err = cmd.Wait()
	close(done)
	// If the runner died before its trap stopped the proxy, stop it here so
	// the exit summary is printed after the child exits on every path.
	stopOrphanedProxy(private)
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	fmt.Fprintln(os.Stderr, "runner:", err)
	return 1
}

func writeRunArtifact(dir string, art mechanism.Artifact) error {
	if art.FileName == "" || filepath.Base(art.FileName) != art.FileName {
		return fmt.Errorf("invalid runner filename")
	}
	if err := os.WriteFile(filepath.Join(dir, art.FileName), []byte(art.FileBody), 0o700); err != nil {
		return err
	}
	for name, body := range art.ExtraFiles {
		if filepath.Base(name) != name {
			return fmt.Errorf("invalid supporting filename")
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func replaceEnv(env []string, name, value string) []string {
	prefix := name + "="
	for i := 0; i < len(env); i++ {
		if strings.HasPrefix(env[i], prefix) {
			env = append(env[:i], env[i+1:]...)
			i--
		}
	}
	return append(env, prefix+value)
}

func unique(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	return out
}

// bindPortsFor picks the permitted ports to bind on the sandbox's loopback:
// every distinct port except the bridge's own, which is already listening
// there.
func bindPortsFor(ports []string) []string {
	proxy := strconv.Itoa(mechanisms.DefaultProxyPort)
	var out []string
	for _, port := range unique(ports) {
		if port == proxy {
			continue
		}
		out = append(out, port)
	}
	return out
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func safeProxyWord(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("._-:/,%+~=", c) {
			continue
		}
		return false
	}
	return true
}

// resolveOutsideProject resolves path to an absolute form with symlinked
// directories resolved, and refuses anything inside the project directory:
// logs the sandboxed program can reach, it can rewrite.
func resolveOutsideProject(label, path, project string) (string, error) {
	if real, err := filepath.EvalSymlinks(project); err == nil {
		project = real
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		if parent, err := filepath.EvalSymlinks(dir); err == nil {
			rel, _ := filepath.Rel(dir, p)
			p = filepath.Join(parent, rel)
			break
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	if p == project || strings.HasPrefix(p, project+string(filepath.Separator)) {
		return "", fmt.Errorf("%s must be outside the project so the sandboxed program cannot edit it", label)
	}
	return p, nil
}

// validateGrant applies the checks every filesystem grant goes through,
// whether it came from --rw/--ro, the policy file, venv autodetect or an
// agent preset. The runner passes grants through a shell word list, so no
// whitespace or glob characters, and nothing too broad to bind.
func validateGrant(path string) (string, error) {
	if strings.ContainsAny(path, " \t\r\n*?[]") {
		return "", fmt.Errorf("grant path %q contains whitespace or shell glob characters; emitted runners cannot pass it safely", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(abs, " \t\r\n*?[]") {
		return "", fmt.Errorf("grant path %q resolves to a path this runner cannot pass safely", abs)
	}
	if mechanism.TooBroadToGrant(abs) {
		return "", fmt.Errorf("grant path %q is too broad", abs)
	}
	return abs, nil
}

// mergeProjectConfig applies the project's sandboxcheckr.toml as the
// baseline: list keys union (config values first, then the command line's),
// scalar keys fill in only where the user did not set the flag themselves.
// set holds the flags the user actually passed, from fs.Visit.
func mergeProjectConfig(cfg *projconfig.Config, set map[string]bool, o *runOptions) {
	if cfg == nil {
		return
	}
	o.allows = unique(append(append([]string{}, cfg.Allows...), o.allows...))
	o.rules = unique(append(append([]string{}, cfg.Rules...), o.rules...))
	o.ports = unique(append(append([]string{}, cfg.Ports...), o.ports...))
	o.privHosts = unique(append(append([]string{}, cfg.PrivHosts...), o.privHosts...))
	o.passes = unique(append(append([]string{}, cfg.PassEnv...), o.passes...))
	o.canaryTokens = unique(append(append([]string{}, cfg.CanaryTokens...), o.canaryTokens...))
	o.ro = unique(append(append([]string{}, cfg.RO...), o.ro...))
	o.rw = unique(append(append([]string{}, cfg.RW...), o.rw...))
	if !set["observe"] {
		o.observe = cfg.Observe
	}
	if !set["no-canary"] {
		o.noCanary = cfg.NoCanary
	}
	if !set["canary-kill"] {
		o.canaryKill = cfg.CanaryKill
	}
	if !set["no-agent-auth"] {
		o.noAgentAuth = cfg.NoAgentAuth
	}
	if !set["events"] && cfg.Events != "" {
		o.events = cfg.Events
	}
	if !set["agent"] && cfg.Agent != "" {
		o.agent = cfg.Agent
	}
	if !set["deny-file"] && cfg.DenyFile != "" {
		o.denyFile = cfg.DenyFile
	}
}

// agentStateDirs maps known agent commands to state directories inside the
// user's home that the agent needs to function. These are functional grants,
// not credentials; the credential presets live in runSandbox's switch.
var agentStateDirs = map[string][]string{
	"omp": {".omp"},
}

// detectVenv finds a python virtualenv to make visible inside the sandbox:
// the shell's activated VIRTUAL_ENV first, then .venv or venv in the project.
// It returns the venv root (to bind) and its bin directory (for PATH).
func detectVenv(project string) (root, bin string, ok bool) {
	if v := os.Getenv("VIRTUAL_ENV"); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			if real, err := filepath.EvalSymlinks(abs); err == nil {
				if fi, err := os.Stat(real); err == nil && fi.IsDir() && dirExists(filepath.Join(real, "bin")) {
					return real, filepath.Join(real, "bin"), true
				}
			}
		}
	}
	for _, name := range []string{".venv", "venv"} {
		root := filepath.Join(project, name)
		if dirExists(filepath.Join(root, "bin")) {
			return root, filepath.Join(root, "bin"), true
		}
	}
	return "", "", false
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// sandboxcheckrStateDir is where sandboxcheckr keeps per-run state, honouring
// XDG_STATE_HOME.
func sandboxcheckrStateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "sandboxcheckr")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "sandboxcheckr")
}

// projectEventsPath is the per-project default event log: a stable short
// hash of the project's canonical absolute path, so different projects never
// interleave and the console can find the log again from the same directory.
// The path is resolved through symlinks before hashing because callers spell
// the same directory differently: a run takes it from --workdir, the console
// from the process working directory, and on Windows resolving also expands
// 8.3 short names, so without this the two sides would hash different
// strings and the console would not find the run's log.
func projectEventsPath(project string) string {
	if real, err := filepath.EvalSymlinks(project); err == nil {
		project = real
	}
	sum := sha256.Sum256([]byte(project))
	return filepath.Join(sandboxcheckrStateDir(), "projects", hex.EncodeToString(sum[:4]), "events.jsonl")
}

// eventLogForRun resolves the event log for a run: an explicit path wins;
// otherwise the project's own log under ~/.local/state/sandboxcheckr/, with
// the shared default log as fallback (e.g. a read-only state directory).
// Whatever is chosen must sit outside the project, or the sandboxed program
// could rewrite the evidence.
func eventLogForRun(explicit, project string) (string, error) {
	resolve := func(path string) (string, error) {
		return resolveOutsideProject("event log", path, project)
	}
	if explicit != "" {
		return resolve(explicit)
	}
	candidates := []string{projectEventsPath(project), defaultEventsPath()}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".cache", "sandboxcheckr", "events.jsonl"))
	}
	for i, candidate := range candidates {
		p, err := resolve(candidate)
		if err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			continue
		}
		f, err := proxy.OpenAppendNoFollow(p, 0o600)
		if err == nil {
			_ = f.Close()
			if i > 0 {
				fmt.Fprintln(os.Stderr, "sandboxcheckr: event log in", p)
			}
			return p, nil
		}
	}
	dir, err := os.MkdirTemp("", "sandboxcheckr-events-*")
	if err != nil {
		return "", fmt.Errorf("cannot create a private event log: %w", err)
	}
	p := filepath.Join(dir, "events.jsonl")
	fmt.Fprintln(os.Stderr, "sandboxcheckr: event log in private temporary directory", p)
	return p, nil
}
