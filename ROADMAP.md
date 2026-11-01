# SandboxCheckr — Roadmap

Status: §1 implemented; later phases remain proposed · Last updated: 2026-10-29

This file records the design, including §1 which is implemented. Shipped
behaviour is in [`README.md`](README.md); the adversarial analysis, including
what each change does and does not stop, is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Why this roadmap exists

SandboxCheckr's job so far has been **containment**: build a sandbox, prove
what it blocks, hand the user a runner. That answers "what *could* untrusted
code do here?"

ProjectDiscovery's October 2026 research
([How abliterated models can get you pwned](https://projectdiscovery.io/research/how-abliterated-models-can-get-you-pwned))
adds a second question: **"is the model or agent doing something it wasn't
asked to do?"** A poisoned model behaves normally until a trigger appears,
passes every eval, and can't be found by inspecting the weights. Containment
limits the damage; it doesn't tell you it happened.

The next phase adds **detection of anomalous behaviour** to the tool, using the
one component that already sees everything leaving a sandbox: the egress proxy.

Design principles carried over from the rest of the tool:

1. **Measured, not assumed.** A detector that has not been shown to fire on
   this machine is reported as *unverified*, never as working.
2. **Absence of a signal is not safety.** "No canary tripped" is reported as
   exactly that, with the channels it could not see, never as "clean".
3. **Nothing leaves the machine unless the user chooses it.** The tool never
   contacts an external service on its own.
4. **Never shadow what the program genuinely needs.** A planted value must not
   replace a real credential the user passed in.

---

## 1. Canary credentials (Phase 1 — local, no dependencies)

Status: implemented 2026-10-29. Per-agent event log and console trips are
included. The proxy scans the first 64 KiB of visible request bodies.

### Outcome

The user runs an agent in a proxied sandbox exactly as today. If, during the
run, anything tries to **use** or **send** a credential that nobody asked it to
touch, the proxy blocks that request, logs it loudly, puts it at the top of the
exit summary, and the runner exits non-zero. No configuration is needed: it is
on by default in the `*-proxy` runners.

### Core idea: a credential whose use is visible without decryption

For HTTPS hosts without a `--rule`, the proxy sees only the destination
hostname and byte counts — never the body. A fake API key buried in an
encrypted request would be invisible to it.

So every canary credential is built **around a hostname** that exists only in
that credential and is unique to the run, e.g. a database URL whose host is
`db-<run-id>.<reserved-domain>`. Inside the proxied sandboxes direct DNS and
sockets are already denied, so the only way to *use* that credential is to ask
the proxy for that hostname. The proxy recognises it from the CONNECT or
request line alone.

Use a reserved, never-resolving suffix (RFC 6761 `.invalid`, or ICANN's
private-use `.internal`) so a canary can never reach a real host, even outside
the sandbox.

String canaries (fake token values) are a secondary signal: the proxy can
match them only where it can read requests — plain HTTP, `--rule` hosts,
request lines and headers.

### Architecture

```
     sandboxcheckr run <command> (or --emit <mech>-proxy)
                         │
                         ▼
   ┌──────────────────── runner script ─────────────────────┐
   │ 1. generate canary set for this run  (sandboxcheckr     │
   │    canary new --out $SCRATCH/canary.json)               │
   │ 2. start proxy with --canaries $SCRATCH/canary.json     │
   │ 3. plant values: env vars + files in private scratch    │
   │ 4. exec program in sandbox                              │
   │ 5. on exit: proxy prints summary; non-zero if tripped   │
   └─────────────────────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
   sandboxed program  ──── only route ──▶  egress proxy
   (sees canary env/files)                 ├─ decide(): host ∈ canary hosts? → TRIP
                                           ├─ inspect()/handlePlain(): body/headers
                                           │   contain canary token?            → TRIP
                                           └─ printSummary(): CANARY section first
```

New package: `internal/canary`

| Piece | Responsibility |
|---|---|
| `Set` | One run's canaries: run ID, environment additions, planted files, watched hostnames, watched strings. Serialisable to JSON so the runner and proxy share it. |
| `New(groups, byo)` | Generate fresh random values per run. Groups (cloud, kube, container registry, database, generic API) are planted and skipped together. |
| `Matcher` | Given a host, or a byte slice, return which canary (if any) it contains. Must be cheap: it runs on every proxied connection. |
| `Plant(dir)` | Write the planted files into the sandbox's private scratch directory, never into the user's real home or project. |

Proxy integration points (existing code):

| Where | Change |
|---|---|
| `internal/proxy/proxy.go` `decide()` | Before the allow-list check, ask the matcher about the host. On a match: deny, record a trip, log `CANARY TRIPPED`. This runs in observe mode too — a trip is never "would be denied". |
| `inspect()` and `handlePlain()` | Scan request line, headers and (bounded) body for canary strings. Same trip handling. |
| `Stat` | Add trip count and the canary label(s) seen. |
| `cmd/sandboxcheckr/proxy.go` | New `--canaries <file>` and `--canary-kill` flags; `printSummary()` prints a CANARY section *before* the destinations table; exit status reflects trips. |

Runner integration (existing code):

| Where | Change |
|---|---|
| `seatbelt.go` `runnerProxy` / `runnerProxyEnv` | Generate the set, pass it to the proxy, add canary variables to the program's environment. |
| `bwrap.go` proxied wrapper | Same, via `--setenv`; planted files bound into the sandbox's empty `$HOME` or scratch. |
| Both | Skip a group when the user passes a real credential of that kind (`PASS_ENV`, or `EXTRA_RO`/`EXTRA_RW` granting the matching config directory). `CANARY=0` disables canaries entirely and prints that it did. |

### Where canaries are planted

| Location | How | Notes |
|---|---|---|
| Environment | Common credential variable names, with canary values | Skipped per group if the user passes the real variable |
| Tool config files | Files in the private scratch directory, with the standard "use this config file" variables pointing at them | Real tools follow these variables, so a payload using the normal tooling picks them up |
| Project `.env` (bubblewrap) | Today the protection mounts an *empty* file. Mount a canary `.env` instead | Gives an attacker plausible loot whose use is visible. Seatbelt keeps returning EPERM; it cannot substitute content |
| Planted files never go in the user's real home or project directory | — | The user's files are never modified |

### Trip handling and confidence

Not every touch of a credential is malicious — an agent asked to "fix the
database connection" may legitimately read `DATABASE_URL`. Trips carry a
confidence level so the report doesn't cry wolf:

| Confidence | Signal | Example |
|---|---|---|
| **High** | A canary string is sent to a host unrelated to it | Planted `.env` contents in a request body to any host |
| **Medium** | A connection to the canary's own hostname | A test run trying to reach the canary database |
| **Info** | A canary appears in traffic to the model endpoint (Phase 2, opt-in) | The agent read a canary and put it in a prompt |

Every trip is **denied**, whatever its confidence. `--canary-kill` additionally
stops the sandboxed program on the first high-confidence trip.

### Self-verification probe

New probe, proxied mechanisms only: `canary.detection`.

During the probe run the harness starts the proxy with a canary set, and the
probe child attempts a connection to one canary hostname. The harness checks
the proxy recorded the trip.

- Trip recorded → `canary.detection` ALLOWED (positive control, like
  `net.proxy.reachable`).
- No trip → the report says canary detection is **unverified** on this host.

### What the report says

- Exit summary (proxy), top section: run ID, each trip with confidence,
  canary label, destination, method, and the log line to look at.
- Exit summary when nothing tripped: "No canary was used or sent through the
  proxy. This does not show the run was clean:" followed by the blind spots
  (see below).
- Main report: canary detection is listed per proxied mechanism as verified /
  unverified.
- CI: runner exit status is non-zero on any trip.

---

## 2. Bring-your-own external tokens (Phase 2)

### Outcome

A credential that leaks through a channel the proxy cannot see — most
importantly **into the model's own prompt** — and is used later, anywhere,
still raises an alert.

### Design

The user supplies tokens they created with an external canary service such as
Thinkst [canarytokens.org](https://canarytokens.org) (cloud API key, DNS
token, URL token):

```sh
CANARY_AWS_KEY='AKIA…:…' CANARY_DNS='xyz.canarytokens.com' sh seatbelt-proxy.sh claude
```

- The runner plants them **in place of** the generated values for the matching
  group, so the most attractive credential is the one that alerts externally.
- The proxy still watches for them locally (they are part of the `Set`), so a
  use *through* the proxy trips immediately as in Phase 1.
- SandboxCheckr never calls the external service. The alert comes from the
  service, to the user, on the user's terms.
- Values are validated against a strict character set before they are written
  into files or the environment.
- The summary lists which external tokens were planted, so the user knows
  where to look for an alert.

### Which token types

Of Thinkst's catalogue, four match what a coding agent actually touches:
cloud keys, cluster configs, connection strings and webhooks. The rest
(Word/PDF documents, MySQL dumps, WireGuard configs, credit cards, Windows
folders) are designed to catch a human browsing a file share, not an agent.
Check canarytokens.org for the current token set before implementing.

| Token | Where it is planted | What fires it | Seen locally by the proxy? |
|---|---|---|---|
| **AWS API key** | Standard AWS key environment variables, plus a credentials file in scratch pointed to by `AWS_SHARED_CREDENTIALS_FILE` | Any AWS API call using the key, from anywhere | **No.** The key travels inside TLS to `*.amazonaws.com`. Locally the call is denied (AWS isn't allow-listed); Thinkst catches use elsewhere |
| **Kubeconfig** | A kubeconfig in scratch, with `KUBECONFIG` pointing at it | Any `kubectl` / API client using it | **Yes.** Its server address is a Thinkst host, so the connection attempt is a hostname the proxy can match |
| **DNS token** | The hostname inside a planted `DATABASE_URL`, and in the bubblewrap canary `.env` | Anyone resolving the name, anywhere | **Yes**, provided the proxy checks canary hosts *before* resolving anything (design note 1) |
| **Web bug (URL)** | A webhook-style variable, e.g. a deploy or chat webhook URL | Any HTTP request to it | **Yes**, by hostname |

The AWS key is the most attractive bait and the one the proxy can't see. That
is deliberate: it covers the channel the proxy cannot, where the agent reads
the key, it ends up in the model's prompt, and someone uses it later. The other
three trip locally *and* externally.

### What a placement looks like

The user supplies tokens to the runner (placeholder values):

```sh
CANARY_AWS_KEY='AKIA…:…' \
CANARY_DNS='<id>.canarytokens.com' \
CANARY_URL='https://canarytokens.com/<path>/<id>/' \
CANARY_KUBECONFIG="$HOME/canary-kubeconfig.yaml" \
  sh seatbelt-proxy.sh claude
```

What the sandboxed program then sees:

```
AWS_ACCESS_KEY_ID=AKIA…                                          ← Thinkst AWS token
AWS_SECRET_ACCESS_KEY=…
DATABASE_URL=postgres://app:…@<id>.canarytokens.com:5432/prod    ← DNS token as the host
DEPLOY_WEBHOOK_URL=https://canarytokens.com/…                    ← web bug
KUBECONFIG=$TMPDIR/kubeconfig                                    ← Thinkst kubeconfig
```

Against the ProjectDiscovery payload, which steals exactly these values:

- **Locally:** the outbound request is denied as before, and a
  `CANARY TRIPPED` line is logged for the DNS and webhook hosts.
- **Externally:** if the values leaked any other way, Thinkst alerts the user
  when they are used.

### Reading an alert

A Thinkst alert includes the **source IP** of whoever used the token:

- **The user's own IP:** the token was used on this machine, so something got
  past the proxy or ran outside the sandbox.
- **A cloud provider or unknown IP:** the token left the machine — most likely
  through the model endpoint, the one leak the proxy cannot see — and was used
  later.

### Design notes

1. **Never resolve a canary hostname in the proxy.** Today `decide()` checks
   the allow-list and then calls `net.LookupIP`; in `--observe` mode every host
   is resolved, so a DNS token would alert Thinkst about the user's own
   machine. The canary check must come before any lookup, in every mode.
2. **One token per machine or project, with context in Thinkst's memo field**
   (e.g. "laptop-x, repo y, seatbelt-proxy"). A per-run token would mean
   creating one by hand for every run. The memo identifies the machine or
   project; SandboxCheckr's run ID and logs identify the run.
3. **Never shadow a real credential.** If the user passes real AWS credentials
   with `PASS_ENV`, skip the AWS token, as with generated canaries.
4. **No local endpoint override for a Thinkst key.** If the key is used, the
   request must actually reach AWS, or Thinkst never hears about it.
5. **Expect delay.** DNS and URL tokens alert within seconds; AWS key alerts
   depend on AWS logging and can take minutes. Say so in the summary.
6. **Creating tokens stays the user's job.** canarytokens.org and the paid
   Canary console both offer APIs, and a user can script token creation
   themselves, but SandboxCheckr never contacts them.

---

## 3. Model-endpoint visibility (Phase 2, opt-in)

### Outcome

The user can see when a planted canary — or a secret-shaped string — enters a
request to the model API. This is the only way to observe the "model asks the
agent to print a secret and receives it in the next prompt" channel, which no
egress rule can close.

### Design

- Opt-in flag on the runner (e.g. `CANARY_INSPECT_MODEL=1`) that adds a
  `--rule` for the model API host, so it is TLS-inspected with the existing
  per-run, name-constrained CA.
- The proxy scans request bodies to that host for canary strings only (not
  general content), records an **info**-confidence event, and does **not**
  block — the agent must keep working.
- Reported as "a canary was sent to the model", with the run ID and time.

### Cost and caveats (must be stated in the docs)

- Inspecting the model API means the proxy decrypts the agent's prompts on
  the local machine. Nothing is stored beyond the event line, but users must
  choose this knowingly.
- Streaming responses and HTTP/2 need to keep working through inspection; the
  inspector is HTTP/1.1-only today (see backlog).
- An agent legitimately reading `.env` for a task looks identical to a
  hostile one at this layer. That is why this is *info*, not *high*.

---

## 4. Behavioural signals beyond canaries (later)

Canaries catch credential misuse. Other "weird stuff" the proxy and runner are
already positioned to notice, ranked by signal quality:

| Signal | Where it is observed | Why it is anomalous |
|---|---|---|
| First data-sending request to a host (**shipped**) | proxy | Coding agents mostly read; writes to a new host are rare |
| Contact with a host never seen in observe mode | proxy, compared to a saved baseline | Drift from the program's known behaviour |
| Fetch-then-execute | runner: a file in scratch written from a proxied download, then executed | The shape of every staged payload |
| Writes to protected project files (**shipped as a block**) | sandbox denial log | Attempted deferred execution |
| Denied sandbox operations | `log stream` (macOS) / bwrap exit codes | Attempts to reach things the program was not given |

**Shipped in part (2026-10-12):** the proxy writes a structured event log
(`~/.local/state/sandboxcheckr/events.jsonl`, outside the workdir so the program
cannot forge it), one line per decision, labelled per agent, read by
`sandboxcheckr console` (see §6). Still to do: the runner and sandbox denial
log as event sources, and ranking by confidence at exit. Canary trips become
the first-ranked event type when §1 ships.

---

## 5. Follow-ups from SBX-011 (project-directory protections)

Shipped 2026-10-07, not yet verified on real hardware.

- [ ] Compile and run the new Seatbelt protection rules on macOS 26
      (`TestEveryVariantCompiles`); confirm `.env` reads, hook writes and the
      rename/link paths are refused while ordinary project writes succeed.
- [ ] Run the bubblewrap runner end to end on Linux (CI `linux-e2e`).
- [ ] Add the two new probes to `TestEveryProbeIsWeighted`.
- [ ] bubblewrap: protect paths created *during* a run (pre-create and mount
      `.git/hooks`, or a Landlock rule).
- [ ] Let users add their own secret file patterns (e.g. `PROTECT_GLOB=`)
      beyond the `.env` convention.

---

## 6. Seeing the other side: relays, decoys and group behaviour

Status: step 1 **shipped 2026-10-12** (with the event log and console from §4);
steps 2–4 designed, not built. Threat entry: SWM-007.

### Why

The 2026 agent swarm investigations (DeGraff's *Swarm*, Zenity, Transluce,
SwarmTraces) were all forensics on services the agents happened to pick: URL
shorteners' statistics pages, fetchers, CORS proxies, a URL scanner. Most of
that record is already gone, and none of it was gathered on purpose. Nobody
publicly runs a relay built to observe agents.

SandboxCheckr already sits where that traffic passes: every proxied run's
egress goes through `internal/proxy`, which has observe mode, a relay list and
a per-run, name-constrained CA. So rather than standing up a public honeypot,
the proxy can become the "other side" for **your own** agents — which keeps
principle 3 (nothing leaves the machine) and avoids recording anyone else's.

### Steps

| Step | What | Status |
|---|---|---|
| 1 | **See it.** Classify GET relays (shorteners, fetchers, CORS proxies, echo services, tunnels, user-hosted apps); warn when one is allowed and suggest no `--rule` for it; summarise every relay *tried*, reached or refused; label-aware host matching. Structured per-agent event log, `sandboxcheckr console` to query it | **Shipped** |
| 2 | **See the shape.** Request detectors on hosts the proxy can read (plain HTTP, `--rule` hosts) | Designed |
| 3 | **Be the relay.** `--decoy`: the proxy answers relay hosts itself instead of forwarding or denying | Designed |
| 4 | **Watch the group.** Shared decoys across N agents behind one proxy, with saved transcripts | Designed |

### Step 2 — request-shape detectors

Run inside `inspect()` and `handlePlain()`, emitting events:

- **URL inside a URL** in the path or query (`r.jina.ai/https://…`, `?url=`).
- **Shortener API shapes:** YOURLS `action=shorturl`, `create.php`, stats reads
  (`+` suffix).
- **Referrer injection:** a `Referer` naming a host the agent never visited, or
  carrying a high-entropy or marker string (`markerwinrefresh<N>.com`).
- **Write-then-read-back:** the same unusual token sent and later fetched — an
  agent testing a channel.
- **Fan-out:** one target requested through several relays.
- **Canary in a query string** (once §1 ships): a planted key in `?api_key=`
  to a fetcher.

### Step 3 — decoy mode

`--decoy` (runner: `DECOY=1`). For relay-class hosts the proxy neither forwards
nor denies; it answers, with a leaf from the existing per-run CA (its name
constraint widened to the decoyed hosts):

- **Shortener:** returns a short code; its stats page echoes back what was
  written, so the read-back loop works.
- **Paste / wiki:** stores the content locally, returns an ID.
- **Fetcher / CORS proxy:** records the inner URL, returns a plausible page,
  fetches nothing.

Decoys must be **behaviourally correct**: the swarm tested mechanisms before
using them, and a decoy that fails a read-back is abandoned. A client that
refuses the decoy certificate is itself recorded.

### Step 4 — group behaviour

N sandboxed agents, one proxy, decoys that are a real shared store between
them — a controlled board. This adds the network channel (SWM-005/007) to what
`--peers` already measures locally, and lets the incident's questions be asked
in a lab: do agents find a relay unprompted, invent naming conventions, ask
each other for bypasses, and does a stated rule stop them (the incident's
Toronto control case)? Run with and without one.

### Deliberately not doing

**A public honeypot relay.** To attract agents it must really forward, which
means knowingly operating an exfiltration channel; it would record other
parties' agents; and it is contaminated as soon as it is known. A local decoy
with your own agents, task and baseline is the cleaner instrument.

### Caveats (must appear in docs)

- Steps 2 and 3 need TLS interception. A client that pins certificates or
  ignores `SSL_CERT_FILE` bypasses them and appears only as a refusal.
- The relay list is never complete. An unknown relay without a `--rule` is a
  hostname and byte counts.
- Decoys show a lower bound: a capable agent may detect the fake.

### Console (shipped with step 1)

How-to: [`docs/OBSERVING_AGENTS.md`](docs/OBSERVING_AGENTS.md).

`sandboxcheckr console` reads the event log, opening on a state-of-the-nation
summary (`summary`; agents ranked by verdict, relay activity by class, findings
with the command to drill in), plus `agents`, `agent <name>`, `hosts`,
`relays`, `shared`, `denied`, `events`, `tail`, with `agent=`, `host=`,
`decision=`, `kind=`, `since=` and `relay` filters). Follow-ups:

- [ ] Event types for steps 2–3 (detector hits, decoy writes) shown in the
      agent timeline.
- [ ] `export` to CSV/JSON for a selection.
- [x] Canary trips (§1) as the first-ranked signal in `agents`.
- [ ] Log rotation; today the log grows until the user removes it.

---

## Blind spots (must appear in docs and in the "nothing tripped" summary)

- A secret sent to the **model endpoint** is invisible unless Phase 2
  inspection is on.
- A secret sent to an **allowed HTTPS host without a `--rule`** is invisible
  apart from byte counts; only hostname canaries trip there.
- A payload that **ignores credentials** (wipes files, tampers with code)
  trips nothing — that is what the containment and project protections are for.
- Canaries detect **use**, not **reading**. A model that reads a canary and
  does nothing with it is not caught.
- None of this detects a backdoored model. It detects behaviour.
- The relay list (§6) is a heuristic. A relay it does not name, used without a
  `--rule`, is visible only as a hostname and byte counts.

---

## Delivery status

| Step | Scope | Status | Outcome |
|---|---|---|---|
| 1 | `internal/canary` (`Set`, `New`, `Matcher`, `Plant`) + proxy `--canaries` | Shipped | Proxy can recognise and block canary use |
| 2 | Runner integration, on by default, group skipping, `CANARY=0` | Shipped | Every proxied run is canaried |
| 3 | Summary section, exit status, `--canary-kill` | Shipped | Trips are impossible to miss; CI fails |
| 4 | `canary.detection` probe | Shipped | Detection is verified per machine |
| 5 | bubblewrap canary `.env` | Shipped | Plausible loot in place of an empty file |
| 6 | BYO external tokens | Proposed | Alerts survive leaks the proxy can't see |
| 7 | Opt-in model-endpoint inspection | Proposed | The prompt channel becomes observable |
| 8 | Event log and behavioural signals | In part | Proxy event log and console shipped; later signals proposed |
| 9 | §6 step 2: request-shape detectors | Proposed | Relay *use* visible, not just relay contact |
| 10 | §6 step 3: decoy mode | Proposed | The proxy plays the relay; nothing leaves |
| 11 | §6 step 4: shared decoys, group runs | Proposed | Swarm behaviour observable in a lab |

Later steps should update `README.md` and `docs/THREAT_MODEL.md`, stating
what they detect and what they do not.
