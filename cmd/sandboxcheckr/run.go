package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms"
	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

const runUsage = `sandboxcheckr run — run a command in this project's proxied sandbox

USAGE
  sandboxcheckr run [flags] <command> [args...]

The current directory is the project by default. A private temporary runner is
created and removed automatically. Canary credentials and the egress proxy are
on by default. Canaries use unique .invalid hosts and fake tokens in private
scratch, never your project or real home. Any trip is denied, logged, printed
at exit, and returns status 3. --observe still denies canary trips. --canary-kill
stops the command on a high-confidence trip; --no-canary disables planting.
No trip does not prove the run was clean: unruled HTTPS hides token strings.

Examples:
  sandboxcheckr run claude
  sandboxcheckr run --workdir ~/code/app -- claude -p "review this code"
  sandboxcheckr run --allow registry.npmjs.org -- npm install
  sandboxcheckr run --observe -- npm test  # discovers hosts; still blocks canary trips

Claude keeps api.anthropic.com and Codex api.openai.com unless you change it.
Any other command starts with NO network: the proxy refuses every destination
until you name one with --allow. A local inference endpoint is private
address space, which the proxy refuses by default, so name the host, that
fact, and its port explicitly:

  sandboxcheckr run --allow localhost --allow-private-host localhost \
      --allow-port 11434 -- my-local-agent

For Claude or Codex, an existing API key is passed if set; otherwise existing
login files are granted. No other shell credentials are passed unless you name
them with --pass-env or --rw. --no-agent-auth disables these presets.

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

func runSandbox(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), runUsage); fs.PrintDefaults() }
	workdir := fs.String("workdir", ".", "project `directory` (default: current directory)")
	var allows, rules, passes, rw, ro, ports, privHosts multiFlag
	fs.Var(&allows, "allow", "permit this destination `host`; repeatable")
	fs.Var(&rules, "rule", "restrict an allowed host: `host:METHODS[:/path]`; repeatable")
	fs.Var(&ports, "allow-port", "destination `port` to permit for allowed hosts; repeatable (default 443 and 80)")
	fs.Var(&privHosts, "allow-private-host", "let this `host` resolve to a private address (a local inference server, an internal registry); repeatable. Link-local/metadata stays refused")
	fs.Var(&passes, "pass-env", "pass this named environment variable; repeatable")
	fs.Var(&rw, "rw", "grant this existing `path` read/write access; repeatable")
	fs.Var(&ro, "ro", "grant this existing `path` read-only access; repeatable")
	observe := fs.Bool("observe", false, "permit and log ordinary destinations; canary trips stay blocked")
	eventsPath := fs.String("events", "", "shared event log `file` outside the project")
	agent := fs.String("agent", "", "agent label in the event log")
	denyFile := fs.String("deny-file", "", "live kill-switch `file`: hosts listed here are cut off mid-run")
	canaryKill := fs.Bool("canary-kill", false, "stop the command on a high-confidence canary trip")
	noCanary := fs.Bool("no-canary", false, "disable canary credentials (the proxy prints this)")
	noAgentAuth := fs.Bool("no-agent-auth", false, "do not grant known agents their existing login credentials")
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
	if *observe && (len(allows) > 0 || len(rules) > 0 || len(ports) > 0 || len(privHosts) > 0) {
		fmt.Fprintln(os.Stderr, "--observe cannot be combined with --allow, --rule, --allow-port or --allow-private-host")
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
	for i, host := range allows {
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
		allows[i] = host
	}
	for _, rule := range rules {
		if !safeProxyWord(rule) {
			fmt.Fprintf(os.Stderr, "--rule: unsupported shell characters in %q\n", rule)
			return 2
		}
		if _, err := proxy.ParseHostRule(rule); err != nil {
			fmt.Fprintln(os.Stderr, "--rule:", err)
			return 2
		}
	}
	for _, port := range ports {
		// Digits only, so the value cannot split into flags when the runner
		// expands $ALLOW unquoted.
		if !proxy.ValidPort(port) {
			fmt.Fprintf(os.Stderr, "--allow-port: invalid port %q\n", port)
			return 2
		}
	}
	for _, host := range privHosts {
		if strings.HasPrefix(host, "*.") {
			host = host[1:]
		}
		if !proxy.ValidHostname(strings.TrimPrefix(host, ".")) {
			fmt.Fprintf(os.Stderr, "--allow-private-host: invalid hostname %q\n", host)
			return 2
		}
	}
	for _, name := range passes {
		if !validEnvName(name) {
			fmt.Fprintf(os.Stderr, "--pass-env: invalid name %q\n", name)
			return 2
		}
	}
	for _, paths := range []*multiFlag{&rw, &ro} {
		for i, path := range *paths {
			if strings.ContainsAny(path, " \t\r\n*?[]") {
				fmt.Fprintf(os.Stderr, "grant path %q contains whitespace or shell glob characters; emitted runners cannot pass it safely\n", path)
				return 2
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "grant path %q: %v\n", path, err)
				return 2
			}
			abs, err = filepath.EvalSymlinks(abs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "grant path %q: %v\n", path, err)
				return 2
			}
			if strings.ContainsAny(abs, " \t\r\n*?[]") {
				fmt.Fprintf(os.Stderr, "grant path %q resolves to a path this runner cannot pass safely\n", path)
				return 2
			}
			if mechanism.TooBroadToGrant(abs) {
				fmt.Fprintf(os.Stderr, "grant path %q is too broad\n", path)
				return 2
			}
			(*paths)[i] = abs
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
	selectedEvents, err := eventLogForRun(*eventsPath, project)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--events:", err)
		return 2
	}
	*eventsPath = selectedEvents
	art, err := selected.Wrapper(mechanism.Workdir{Path: project})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generating runner:", err)
		return 1
	}
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
	// move private runner state somewhere the child can see.
	for _, name := range []string{"PASS_ENV", "EXTRA_RW", "EXTRA_RO", "ALLOW", "CANARY", "CANARY_KILL",
		"SANDBOXCHECKR", "AGENT", "DENY_FILE", "ALLOW_DOTENV", "ALLOW_EXEC_CONFIG", "TMPDIR"} {
		env = replaceEnv(env, name, "")
	}
	passNames := []string(passes)
	rwPaths := []string(rw)
	commandName := filepath.Base(argv[0])
	if !*noAgentAuth {
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
		if *eventsPath == path || strings.HasPrefix(*eventsPath, path+string(filepath.Separator)) {
			fmt.Fprintf(os.Stderr, "event log %s is inside a read/write grant %s; choose --events outside that grant\n", *eventsPath, path)
			return 2
		}
	}
	if len(passNames) > 0 {
		env = replaceEnv(env, "PASS_ENV", strings.Join(unique(passNames), " "))
	}
	if len(rwPaths) > 0 {
		env = replaceEnv(env, "EXTRA_RW", strings.Join(unique(rwPaths), " "))
	}
	if len(ro) > 0 {
		env = replaceEnv(env, "EXTRA_RO", strings.Join(unique(ro), " "))
	}
	env = replaceEnv(env, "EVENTS", *eventsPath)
	if *agent != "" {
		env = replaceEnv(env, "AGENT", *agent)
	}
	if *denyFile != "" {
		env = replaceEnv(env, "DENY_FILE", *denyFile)
	}
	if *canaryKill {
		env = replaceEnv(env, "CANARY_KILL", "1")
	}
	if *noCanary {
		env = replaceEnv(env, "CANARY", "0")
	}
	if *observe {
		env = replaceEnv(env, "ALLOW", "--observe")
	} else {
		env = replaceEnv(env, "ALLOW", allowFlagsFor(commandName, allows, rules, ports, privHosts))
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

func eventLogForRun(explicit, project string) (string, error) {
	resolve := func(path string) (string, error) {
		return resolveOutsideProject("event log", path, project)
	}
	if explicit != "" {
		return resolve(explicit)
	}
	candidates := []string{defaultEventsPath()}
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
