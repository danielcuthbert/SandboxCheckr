# SandboxCheckr

“Just use a sandbox” is usually said by someone who hasn’t had to make one work.

SandboxCheckr lets you run a binary in a sandbox and see what it can reach.
It tests the machine, runs probes inside each sandbox it can build, and reports
what was blocked or left open. It can then run your command under Seatbelt
(macOS) or bubblewrap (Linux), with a log of its network activity.

Use it for any command you want to contain and examine: a coding agent, an MCP
server, a package install script, or your own binary, hell even some random $thing you got sent and told this was cooo.... 

The command can work in your project without automatically getting your SSH keys, browser profile, or an open route to every host on the network.

## Try it (you know you want to)

Build from this checkout:

```sh
make build
./bin/sandboxcheckr run --workdir /path/to/project claude
```

If the binary is on your `PATH`, run `sandboxcheckr run claude` from a project
directory. `sandboxcheckr run codex` works the same way. For another command:

```sh
sandboxcheckr run -- npm test
```

`run` creates a temporary sandbox and a separate egress proxy for that run.
Claude and Codex can reach their respective model API hosts by default; another
command starts with no allowed hosts. The proxy logs destinations and refuses
those you have not allowed. Name resolution inside the sandbox goes through the
proxy too, under the same allow-list. It also plants fake credentials whose
attempted use it can detect. A canary trip is blocked and makes the command
exit nonzero.

To see which hosts a command needs, then allow only the ones you choose:

```sh
sandboxcheckr run --observe -- npm test
sandboxcheckr adopt --write                 # what it saw, as sandboxcheckr.toml
sandboxcheckr run -- npm test
```

`run --observe` permits and logs every destination. `adopt` reads that log
and prints the missing `allow`, `allow-port` and `allow-private-host` lines
for your review; `--write` puts them in `sandboxcheckr.toml`. It never
proposes canary hosts, and a denied enforcing run feeds it just as well.

Observe mode permits ordinary destinations while logging them. It still blocks
canary trips. You can narrow an allowed HTTP host to methods and paths with
`--rule`; see the [user guide](docs/USER_GUIDE.md#the-egress-proxy-seatbelt-proxy-bubblewrap-proxy).

Once you know what a command needs, write the policy down in the project
instead of retyping flags. A `sandboxcheckr.toml` in the project directory is
the baseline for every `run` in it; command-line flags add to its lists and
override its switches:

```toml
# sandboxcheckr.toml
allow = ["localhost", "127.0.0.1"]
allow-private-host = ["localhost", "127.0.0.1"]
allow-port = [8000]
ro = ["~/tools/raptor"]
rw = ["~/.omp"]
```

```sh
sandboxcheckr run -- omp -c        # the policy file supplies the rest
```

Python virtualenvs are picked up automatically: an activated `VIRTUAL_ENV`,
or `.venv`/`venv` in the project, is granted read-only and put first on `PATH`
inside the sandbox, so the interpreter and its packages resolve without a
shell wrapper. Event logs are per project by default; `sandboxcheckr console`
run in the same project reads that project's log back.

On Linux, ports in `allow-port` are also bound on the sandbox's own loopback,
so tools that bypass HTTP proxies for localhost (some set `NO_PROXY` to cover
local model servers) still traverse the egress proxy and its policy. A program
that itself serves on a permitted port will find it taken; drop that port from
`allow-port` if so — the sandbox's network is private, so nothing outside
could reach that server anyway.

On macOS, start SandboxCheckr from a normal terminal. If the terminal is already
inside another sandbox, Seatbelt may be unable to start a second one. On Linux,
you need `bwrap` installed and usable by your account.

## Check the machine

Run the report without starting an agent:

```sh
sandboxcheckr
sandboxcheckr --gaps
sandboxcheckr --json
```

SandboxCheckr runs the same probe battery without a sandbox and inside each
candidate sandbox it can start. The report compares access to credential files,
browser profiles, the project directory, network paths, agent sockets, and other
host resources. A candidate has to allow writes in the project directory to be
considered usable. An error or timeout earns no protection credit.

The report distinguishes the strictest sandbox from one that still gives an
agent network access. It also inventories host security settings and statically
lints some sandbox profiles installed by other agent tools. That lint result is
about the profile text; it does not claim to have tested those other tools at
runtime.

## Where the boundary is

- The project remains writable. SandboxCheckr blocks reads of `.env` files and
  writes to common deferred execution files, including git hooks and editor
  tasks, by default. It cannot protect every secret name or every project file
  your build may later execute. Review changes before running project code on
  the host.
- Claude and Codex get their existing API key or login files unless you use
  `--no-agent-auth`. Other shell credentials are omitted unless you name them
  with `--pass-env`, `--ro`, or `--rw`. Anything you grant is available to the
  command.
- An allowed destination can receive data the command can read. A host allow
  list alone cannot prevent exfiltration through that host or through the model
  API. Method and path rules reduce some routes; they do not make the request
  body safe. The proxy cannot read tokens inside HTTPS to a host without a
  `--rule`.
- The probes test specific operations on this machine. A passing score is
  evidence about those operations, not proof against every sandbox escape.
  SandboxCheckr does not inspect the live sandbox around another process.

The [threat model](docs/THREAT_MODEL.md) records known weaknesses and the tests
behind them. The [user guide](docs/USER_GUIDE.md) has the full probe list, proxy
options, console workflow, command reference, and platform status.

## More commands

```sh
sandboxcheckr run --pass-env API_KEY --rw /path/to/config -- my-agent
sandboxcheckr run --rule registry.npmjs.org:GET,HEAD --allow registry.npmjs.org -- npm install
sandboxcheckr console                  # inspect proxy events across runs
sandboxcheckr lint profile.sb          # static Seatbelt profile audit
sandboxcheckr --emit seatbelt-proxy --workdir /path/to/project
```

`--emit` writes a persistent runner and profile you can inspect or change. See
the [user guide](docs/USER_GUIDE.md#command-reference) for the Linux mechanisms
and remaining flags. The [observation guide](docs/OBSERVING_AGENTS.md) covers
several agents running at once.

## Build and status

SandboxCheckr is pure Go, with no cgo or third-party Go dependencies.

```sh
make build
make test
make cross
```

Seatbelt probes have been run on macOS 26.6; the runner scripts have only been
dry-run there. Linux has unit tests and a CI job that runs bubblewrap end to
end, but has not been verified on the author's Linux hardware. Windows builds
and reports host posture, but has no sandbox runner yet. 

Current limits and
planned work are in the [user guide](docs/USER_GUIDE.md#status) and
[roadmap](ROADMAP.md).

The source is available under the [PolyForm Noncommercial 1.0.0 license](LICENSE.txt).
For security issues, see [SECURITY.md](SECURITY.md).
