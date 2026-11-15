# SandboxCheckr security assessment plan

Status: assessment plan, not a list of confirmed escapes · 2026-10-29

This plan tests the sandbox that `sandboxcheckr run` actually launches, plus
emitted runners and the report that recommends them. It extends the existing
[attack catalog](THREAT_MODEL.md). A passing unit test or a plausible policy
rule is not evidence that a live agent is contained. Conversely, a hypothesis
is not a finding until its preconditions and effect are reproduced.

## The claim to test

An agent may read and change its assigned project and use approved network
destinations. It must not read or change host material outside its grants,
reach another network destination or private address, alter the proxy's policy
or evidence, or gain a broader boundary through a peer. A canary trip is an
alert about specific planted credentials; absence of a trip is not a safety
claim. Files deliberately granted with `--ro` or `--rw`, content in the
project, and data sent to an approved model endpoint are within the agent's
reach. A sandbox cannot make an untrusted model or permitted service benign.

**Adversary:** a single hostile process or cooperating agents. They know the
profile and proxy code, can execute reachable programs and protocols, can
write the project, can race launch and shutdown, and can use every granted
credential. Do not assume that they honor `HTTP_PROXY`, use normal DNS, stop
when the foreground command exits, or leave readable text in logs.

**Boundaries:** CLI/parent shell → generated runner → kernel policy → agent;
agent → loopback proxy or Linux bridge → proxy parser/policy → resolver →
upstream; agent → project/granted paths; agent → OS brokers and peer agents;
agent → inherited terminal and user; proxy → event log/console. Test the direct
`run` path and emitted runners
separately, because their configuration surfaces differ.

## Test method and evidence

1. Use disposable project copies and synthetic credentials. Do not place real
   secrets in a test workdir. Keep receivers local or under our control; for
   loopback upstream tests, enable private-host access only in the test proxy
   or an explicit emitted-runner lab configuration.
2. Establish a positive control outside the sandbox: the operation and
   receiver must work. Then run the identical payload inside each applicable
   mechanism. Record *both* the child's result and the host-side observation
   (receiver bytes, file hashes, process state, proxy decisions and event log).
3. Run a negative control that should be allowed. A broken client that never
   attempted the operation does not count as a successful defense.
4. For every case record OS/build, SandboxCheckr revision, mechanism, launch
   mode, allow-list, grants, start/end time, expected boundary, observed
   result, and whether the result is **blocked**, **escaped**, **unverified**,
   or **allowed by design**. Keep a minimal reproducer and regression test for
   each confirmed issue. Recheck after OS, bwrap, Go, or agent upgrades.
5. Capture failures without trusting the child: host-side file snapshots,
   separate receiver logs, proxy events outside the workdir, and, where
   available, kernel audit/Seatbelt denial logs. Test that missing logs and
   crashed proxies fail visibly. Never score an inconclusive probe as blocked.

Run the matrix on real unconfined macOS and Linux hosts. This Chopin session
cannot launch nested Seatbelt; a build or test here does not replace the live
macOS run. Windows has no SandboxCheckr mechanism, so the only correct run
result there is an explicit refusal. Repeat the relevant cases with two
agents in separate projects and, deliberately, in one shared project.

Use a coverage grid so convenient variants do not stand in for the dangerous
ones:

| Dimension | Required cases |
|---|---|
| Launch | direct `run`; emitted proxied runner; strict and open-network variants as comparison controls |
| OS | each supported macOS release on real hardware; Linux with unprivileged and setuid bwrap where supported; root invocation as a negative case; Windows refusal |
| Proxy policy | default, explicit host, ruled host, observe mode, live deny edit, proxy crash |
| Child | small synthetic binary, shell/script interpreter, Claude/Codex with synthetic project, process tree with background children |
| Filesystem | clean project, symlinks/hard links, pre-existing and late-created protected paths, explicit `--ro`/`--rw`, same and separate workdirs |
| Swarm | one child, two concurrent children, restart while another child is active, four-child resource test |

Use pairwise combinations initially, then combine every condition needed for a
confirmed bypass. Keep the receiver and host evidence separate from the
sandboxed project.

## Attack inventory and proposed fixes

Priority is the order to investigate, **not** a claim of exploitability.
P0 means that failure could invalidate a headline boundary or the evidence
used to assert it. P1 means serious exposure under a named precondition. P2
tracks residual or lower-yield channels. Existing IDs point into the attack
catalog.

| ID | Priority | Hypothesis and probe | Fix if reproduced / acceptance condition |
|---|---|---|---|
| A01 | P0 | **Probe/runner drift:** compare the exact effective policy, environment, mounts, executable path and proxy parameters of the measured probe with `run` and emitted runners. Vary flags, inherited `ALLOW_DOTENV`, `ALLOW_EXEC_CONFIG`, `SANDBOXCHECKR`, `PORT`, `PROXY_LOG`, `DENY_FILE`, and symlinked paths. See SBX-008. | Build one launch specification for probe and production; clear or explicitly surface inherited policy switches in `run`. Refuse launch on a failed preflight. The comparison should fail CI on any unexpected difference. |
| A02 | P0 | **Transient or late grants:** replace a workdir, binary, grant path, or login-file symlink between validation, runner generation, and sandbox entry; try hard links, bind mounts where permitted, and `..`/Unicode/path aliases. | Open and pin trusted objects where possible; revalidate resolved paths immediately before launch; use kernel path rules that remain correct after rename. A swap must fail closed or remain confined. |
| A03 | P0 | **Linux protection only at launch:** create or rename `.env`, `.git`, `.github`, hooks, editor tasks and nested repos after bubblewrap's bind setup. Repeat under skipped `node_modules`, `.venv`, `vendor`, `target`, and with newline-bearing names. `ProtectedInWorkdir` and the shell runner scan only existing paths and skip trees. See SBX-011. | Replace best-effort file overlays with a policy that covers future paths (Landlock or a controlled read-only overlay), or narrow the claim and require a staged workdir. A child must not create a path that the report calls protected. |
| A04 | P0 | **Host brokers on macOS:** ask keychain/securityd, LaunchServices, Apple Events, pasteboard, XPC/Mach services, print/share/open helpers and privileged helpers to act on the child's behalf. Re-test SBX-001, SBX-007, SBX-009, SWM-006 on every supported macOS release. | Build a measured Mach service allow-list, deny high-value brokers, and include brokered capability probes. If an agent needs keychain login, state that exception as a credential grant and test its scope. |
| A05 | P0 | **Proxy destination confusion:** vary CONNECT authority, TLS SNI, certificate name, HTTP `Host`/`:authority`, absolute-form URL, redirects, IPv4/IPv6 literals and case/trailing-dot/IDNA aliases. Test both ruled and unruled HTTPS against controlled virtual hosts. | Canonicalize one destination identity. Reject mismatched inner authority for inspected traffic; consider ClientHello SNI validation for tunnels. Treat uninspected Host routing as a residual boundary until it is enforceable. Unit and live tests must show bytes never reach a disallowed tenant. |
| A06 | P0 | **Proxy parser/rule bypass:** exercise HTTP/1.1 request smuggling, conflicting length headers, chunked bodies, pipelining, `Upgrade`/WebSocket, unusual methods, encoded separators, dot segments, query/fragment tricks, HTTP/2 and CONNECT tunnels. Verify every forwarded request has a matching allow decision. | Reject ambiguous framing and unsupported protocols; check the normalized path and method the upstream receives; bound parsing. A rule must never authorize a different request than the one delivered. |
| A07 | P0 | **Allow-listed service as relay:** use controlled registry, object store, URL fetcher, redirect, shortener, code host and model endpoint to carry synthetic secret bytes in GET path/query, headers, small POST and streaming uploads. See SBX-006, SBX-011, SWM-007. | Offer policy profiles with path/query/size limits and origin-specific rules; require upstream registry controls (no anonymous writes, fixed remotes). Explain that arbitrary allowed GETs and model prompts remain exfiltration channels. |
| A08 | P0 | **Cross-run proxy access:** from agent B, try agent A's Seatbelt proxy port or Linux proxy socket; use shared and separate workdirs, fixed ports, concurrent startup and restart. Also connect from an unrelated host process. See SBX-010. | Give each proxy a private authenticated endpoint or enforce per-run access at the OS boundary. Fail if a peer can use a different allow-list or write events under another agent's label. |
| A09 | P0 | **Shared writable project/scratch:** two agents in one workdir exchange files, directory names, symlinks, FIFOs, Git metadata and `.sandboxcheckr-tmp` data. The current Seatbelt scratch path is derived from the workdir; it is not private between runs of that workdir. See SWM-001/002. | Require separate project copies for isolation claims. Create per-run scratch outside any peer-writable grant, or state and test that shared workdirs share a communication channel. Do not label same-workdir runs isolated. |
| A10 | P0 | **Fail-open lifecycle:** kill, hang, or replace the proxy during startup and a live tunnel; race readiness, port selection, bridge startup, child PID publication, signal handling and cleanup. Check whether any child continues with broader egress or exits 0 after a canary trip. | Tie child lifetime to a verified proxy instance, refuse on proxy loss, preserve trip status and host-side evidence, and reap descendants. A failed proxy must never silently turn a run into open networking. |
| A11 | P0 | **Linux boundary availability:** test root invoker, setuid bwrap, unavailable user namespaces, `--unshare-user-try` fallback, capabilities, procfs, ptrace and nested namespaces. Detect currently proves only that a simple bwrap invocation works. See SBX-003. | Require the intended user namespace and capability state for a security claim, or explicitly refuse/degrade. Add seccomp for unused high-risk syscalls and verify it on a real Linux host. |
| A12 | P0 | **Evidence tampering:** try changing proxy log, event log, deny file, ready file, CA bundle, canary set, trip marker and child PID file through workdir aliases, symlinks and same-UID peers. Race file creation and rotation. | Keep authoritative files outside child grants, create with no-follow and restrictive modes, pin file descriptors, and make tamper or logging failure visible. Test what a same-UID process outside the sandbox can do; it is outside the confinement guarantee. |
| A13 | P1 | **System and install-path reads:** enumerate `/etc`, `/opt`, `/nix/store`, tool install dirs and granted Claude/Codex auth directories for real readable secrets. Linux binds system trees read-only; Seatbelt grants executable trees. | Minimize mounts/grants per executable, inventory readable host material, and offer a disposable credential or broker instead of broad login-directory access. Do not describe read-only as secret-free. |
| A14 | P1 | **Network address policy:** test DNS rebinding/answer changes, CNAME chains, mixed public/private answers, IPv4-mapped IPv6, unusual numeric forms, link-local/metadata, loopback and Unix sockets. Verify the exact dialed IP is the validated IP. | Pin numeric checked addresses through dial and apply one canonical restricted-address check to every path. Preserve a deny result when DNS or classification is ambiguous. |
| A15 | P1 | **Canary coverage and bypass:** send a token after the first 64 KiB, inside unruled TLS, encoded/compressed/split across chunks, through a non-HTTP protocol, or into a model prompt. Test group skipping when a named real credential is empty or a config grant is partial. Race `--canary-kill` before the PID file exists. | Keep host canaries mandatory for a claimed canary group; report exact visible channels and skipped groups. Consider bounded streaming inspection and explicit opt-in model visibility, but never call a no-trip run clean. |
| A16 | P1 | **Kill-switch failure:** make the deny file unreadable, oversized, replaced, truncated or unreadable during rotation; race blocking with existing keep-alive tunnels and new connections. `DenyFile.Match` currently ignores `Refresh` errors. | Choose and document fail-closed behavior on reread error, atomically replace lists, pin the file location and verify every live tunnel closes within the promised deadline. |
| A17 | P1 | **Resource exhaustion:** fork/process storms, CPU, memory, disk and inode filling, massive host cardinality, slow headers, idle tunnels, oversized logs, many canary trips, certificate cache growth, and four-agent amplification. | Add per-run process/CPU/memory/disk/connection/time budgets where supported, proxy deadlines and bounded state/log rotation. The host and other runs must remain usable after a malicious child. |
| A18 | P1 | **Persistence after exit:** spawn grandchildren, detached sessions, background services, scheduled tasks or edited build hooks; test cancellation and terminal hangup. Compare project hashes and executable configuration before and after. | Kill/reap the whole process group or cgroup, isolate writable output, and review/mark executable diffs before they run on the host. Project source changes remain a deliberate residual. |
| A19 | P1 | **Covert peer channels:** process enumeration/signals, Mach/D-Bus/Unix sockets, shared memory, file locks, common caches, timing and externally allowed relays. Run `--peers` plus a two-agent protocol with host-observed success criteria. | Remove practical shared IPC routes, use separate workdirs and proxy identities, and report remaining timing/allowed-network channels honestly. A total ban on covert timing channels is not a feasible promise. |
| A20 | P2 | **Tool and update drift:** agent self-updates, shell interpreters, plugins, package managers and executables loaded from writable project or toolchain paths; compare direct `run` with emitted wrappers. | Pin agent/tool versions in assessment runs, test every supported interpreter path, and rerun boundary tests after updates. Treat fetched executable code as untrusted even from an allowed host. |
| A21 | P1 | **Terminal as a host broker:** send terminal control sequences through the child's stdout/stderr, including clipboard, hyperlinks, window/title changes and input or display manipulation. `run` currently wires child output directly to the parent's terminal. Test with a recording pseudo-terminal before any real-terminal trial. | Mediate untrusted output through a bounded PTY renderer or escape filter, and avoid giving the child a controlling host TTY when possible. It must not change the host clipboard or misrepresent a command the user is about to run. |
| A22 | P2 | **Kernel and hardware boundary:** assess reachable kernel interfaces, OS version, device nodes and side channels when the attacker controls native code; include resource and speculative/timing channels. | Keep OS patches current and offer VM-class isolation for code beyond the threat tolerance of same-kernel sandboxes. Do not claim a kernel exploit is prevented by namespace or Seatbelt policy alone. |
| A23 | P1 | **Human handoff:** plant instructions, links, terminal output or project changes that induce an operator or follow-on tool to run code outside the sandbox or grant broad `--rw`/`--pass-env` access. | Show the diff and requested grants at the boundary; separate agent text from SandboxCheckr's own status; require deliberate host-side review before executing generated artifacts. The sandbox cannot enforce what a person later chooses to do. |
| A24 | P1 | **DNS gate canonicalisation:** vary query-name case, trailing dot, suffix boundary (`evillocalhost` vs `.localhost`), embedded NUL and high-byte label bytes, root name, label/name length extremes, QDCOUNT 0/2, compression-pointer bytes; compare the name the gate judged with the name resolved, forwarded and logged. A bug here re-labels exfil as an allowed lookup (A24/SBX-012) or a canary as noise. | Fail closed on parse ambiguity; identical normalisation across canary, deny-file and allow-list decisions; no crash or hang on malformed input; the logged name is the judged name. See BT-8.3. |
| A25 | P1 | **Relay protocol abuse from the child:** speak the framed unix protocol directly to the relay socket; zero-length and oversize frames, garbage, slowloris partial frames, concurrent floods, fuzzed query corpus; attempt a :53 bind takeover and bridge kill from the mapped-root namespace. | Bounded state (exchange deadlines, no unbounded goroutine/queue growth), no crash or hang, tunnels unaffected during DNS floods; direct socket use gets the same decisions as the bridge path. See BT-8.9/8.10/8.11. |
| A26 | P2 | **Resolver-plane escape:** rewrite `/etc/resolv.conf` or `/etc/hosts`, query alternate loopback resolvers, dial upstream IP literals, `setns` to the host netns, fake-answer sibling agents after a :53 takeover. | Every path dead or fail-closed; spoofing cannot open egress; no resolution traffic leaves through anything but the relay. See BT-8.7/8.8/8.11/8.13. |

### Code-backed conditions to fix early

These are current code properties; their security impact still needs the live
tests above. They are useful first patches because the desired behavior is
clear even before a full adversarial run:

- `run` clears several inherited runner variables, but still inherits
  `ALLOW_DOTENV`, `ALLOW_EXEC_CONFIG`, `SANDBOXCHECKR`, `PROXY_LOG`, `DENY_FILE`
  and `PORT`. Make policy-changing inputs explicit flags and document the rest
  as advanced, trusted-parent settings (A01).
- The default proxy text log now lives in a private per-run directory outside
  the workdir, where the sandboxed program cannot edit it (`run` refuses an
  inherited `PROXY_LOG` inside the project). The Seatbelt scratch directory is
  still under the writable project; treat the log as authoritative only where
  `run` started it, and require separate workdirs for peer isolation (A09/A12).
- `DenyFile.Match` discards a refresh error. Surface the error to the proxy and
  choose an explicit refusal policy, especially when a deny file that existed
  becomes unreadable (A16).
- Child stdout and stderr go straight to the invoking terminal. Add a
  mediated output mode before claiming that OS broker denials also cover
  terminal-driven clipboard or display effects (A21).

## Execution order and release gates

**First: prove what launches.** Inventory the exact `run` and emitted policy,
mounts, env and grants (A01–A03, A11). Make the report say **unverified** when a
mechanism cannot be exercised on that host. Correct historical claims in the
attack catalog against current code before relying on them.

**Second: try the boundary.** Build local receiver and virtual-host fixtures
for A04–A10 and A14. Preserve a small corpus of hostile proxy requests and
launch races. A confirmed escape becomes an issue with a reproducer, a fix, a
regression test and a live retest on affected platforms. Prioritize a bypass
that reaches real host secrets or a disallowed destination over a logging gap.

**Third: measure residual exposure.** Run A12–A23 with one and several agents.
Separate outcomes into: kernel/proxy escape, allowed-by-design data flow,
post-run host execution, detection blind spot, and availability failure. Each
needs a different remedy; alerting alone does not close an egress path.

Do not call a release hardened until: (1) P0 escape tests pass on real macOS
and Linux hosts for the mechanisms shipped there; (2) a failed or missing
proxy, logging path, or required namespace fails visibly; (3) a child cannot
use another run's policy or alter authoritative evidence; (4) limits of
allowed endpoints, shared workdirs, granted credentials, and canaries are
shown in help and the report; and (5) the regression corpus runs in CI with
live host checks scheduled for every supported OS update. Record unsupported
platforms and untested hypotheses explicitly rather than marking them safe.
