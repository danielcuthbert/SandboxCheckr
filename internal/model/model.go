// Package model holds the types shared by every stage of the check. Nothing in
// here is OS-specific: the darwin and linux detectors both produce these, and
// the reporters both consume them.
package model

import "time"

// Status is the outcome of a single check. INDETERMINATE is load-bearing: it is
// what we report when we could not honestly tell, most often because
// SandboxCheckr was itself confined and the check was unreachable rather than
// unsupported. Collapsing that into ABSENT is the bug this tool exists to avoid.
type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusDegraded      Status = "DEGRADED"
	StatusAbsent        Status = "ABSENT"
	StatusIndeterminate Status = "INDETERMINATE"
)

// Verdict is what a probe actually observed. Distinct from Status because a
// probe reports behaviour ("the write was refused") while a check reports
// judgement ("this mechanism holds").
type Verdict string

const (
	// VerdictBlocked means the attempt was refused. This is the good outcome
	// for containment probes.
	VerdictBlocked Verdict = "BLOCKED"
	// VerdictAllowed means the attempt succeeded — the sandbox did not stop it.
	VerdictAllowed Verdict = "ALLOWED"
	// VerdictErrored means the probe could not run to a conclusion. Never treat
	// this as BLOCKED; a probe that crashed tells us nothing about containment.
	VerdictErrored Verdict = "ERRORED"
	// VerdictSkipped means the probe was not applicable here.
	VerdictSkipped Verdict = "SKIPPED"
)

// Confinement describes whether SandboxCheckr itself is sandboxed (stage 1).
type Confinement struct {
	// Confined is true when we have positive evidence of our own confinement.
	Confined bool `json:"confined"`
	// Kind is a short label such as "seatbelt", "seccomp", "container".
	Kind string `json:"kind,omitempty"`
	// Evidence lists the signals that led to the conclusion, so a reader can
	// disagree with us on the facts rather than on the verdict.
	Evidence []string `json:"evidence,omitempty"`
}

// Availability is the result of passively detecting one mechanism (stage 2).
type Availability struct {
	Status Status `json:"status"`
	// Detail is a human sentence explaining the status.
	Detail string `json:"detail,omitempty"`
	// Version, where the mechanism reports one (e.g. Landlock ABI 10).
	Version string `json:"version,omitempty"`
	// Path to the backing tool, resolved absolutely, when there is one.
	Path string `json:"path,omitempty"`
}

// ProbeID identifies one attempt in the battery.
type ProbeID string

const (
	ProbeFSWriteOutside ProbeID = "fs.write.outside"
	ProbeFSReadSecrets  ProbeID = "fs.read.secrets"
	ProbeNetEgressTCP   ProbeID = "net.egress.tcp"
	ProbeNetEgressDNS   ProbeID = "net.egress.dns"
	ProbeProcExec       ProbeID = "proc.exec"
	ProbeFSWriteAllowed ProbeID = "fs.write.allowed"

	// ProbePersistence covers the paths that survive a reboot. Writing here is
	// how a one-off compromise becomes a permanent one, so it is scored
	// separately from ordinary writes outside the workdir.
	ProbePersistence ProbeID = "fs.write.persistence"
	// ProbeCloudMetadata covers the link-local metadata endpoint. On a cloud
	// instance or CI runner this hands out short-lived IAM credentials to
	// anything that can make an HTTP request, with no authentication at all.
	ProbeCloudMetadata ProbeID = "net.cloud.metadata"
	// ProbeContainerSocket covers the Docker/Podman control socket. Access to
	// it is generally equivalent to root on the host.
	ProbeContainerSocket ProbeID = "ipc.container.socket"
	// ProbeCredentialStore covers the OS credential store (macOS keychain,
	// GNOME keyring), which holds far more than the dotfiles probe reaches.
	ProbeCredentialStore ProbeID = "fs.read.credstore"
	// ProbeFSReadBrowser covers browser profile directories. Their cookies are
	// live sessions for every site the user is logged into, which is often more
	// valuable than any key on disk.
	ProbeFSReadBrowser ProbeID = "fs.read.browser"

	// The exfil family enumerates routes data can leave by. They exist because
	// blocking direct TCP is not the same as blocking exfiltration: in the July
	// 2026 OpenAI–Hugging Face incident, agents coordinated through a shared
	// internal package registry and reached the internet through that
	// registry's remote-repository proxy rather than a direct socket. See
	// docs/THREAT_MODEL.md for sources.

	// ProbeExfilEnvSecrets covers credentials held in the environment rather
	// than on disk. Agents are handed API keys this way constantly, and in the
	// Hugging Face part of that incident agents used an arbitrary-file-read
	// flaw to read server process environment variables and harvest
	// credentials from them. A sandbox that locks down ~/.aws and leaks
	// AWS_SECRET_ACCESS_KEY through the environment has protected nothing.
	ProbeExfilEnvSecrets ProbeID = "exfil.env.secrets"
	// ProbeExfilSharedScratch covers a writable directory visible to other
	// sandboxed processes. This is the message-board pattern: individually
	// confined peers coordinating and staging data through shared storage.
	ProbeExfilSharedScratch ProbeID = "exfil.shared.scratch"
	// ProbeExfilSyncDirs covers cloud-synced folders. Writing to one moves data
	// off the machine with no network syscall the sandbox could have blocked.
	ProbeExfilSyncDirs ProbeID = "exfil.sync.dirs"
	// ProbeExfilProxyEnv covers an inherited HTTP proxy, which is egress even
	// when direct sockets are denied.
	ProbeExfilProxyEnv ProbeID = "exfil.proxy.env"
	// ProbeExfilClipboard covers the system pasteboard, a cross-process channel
	// that filesystem and network rules do not touch.
	ProbeExfilClipboard ProbeID = "exfil.clipboard"
	// ProbeExfilDNSTunnel covers whether arbitrary attacker-chosen labels reach
	// a resolver. Plain DNS resolution succeeding is not the same finding:
	// tunnelling needs the query name itself to carry data outward.
	ProbeExfilDNSTunnel ProbeID = "exfil.dns.tunnel"

	// ProbeExfilBrokerDNS and ProbeExfilBrokerLaunch (macOS) test "brokered"
	// egress: network performed by a system daemon on the process's behalf, which
	// a socket-level deny does not cover. These are regression coverage for the
	// SBX-001 hypothesis — brokered egress was refuted on macOS 26.6, and these
	// probes exist so the tool would catch it if a later release reopened it.
	// See docs/THREAT_MODEL.md.
	ProbeExfilBrokerDNS    ProbeID = "exfil.broker.dns"
	ProbeExfilBrokerLaunch ProbeID = "exfil.broker.launchservices"

	// ProbeExfilAppleEvents (macOS) covers cross-application automation: a
	// confined process sending an Apple Event to drive another app (Safari,
	// Mail, Terminal) into acting outside the sandbox. deny-default refuses
	// `appleevent-send`; this verifies it and catches a regression if the
	// profile is loosened. A block may also come from TCC Automation, not only
	// the sandbox — either way the channel is closed.
	ProbeExfilAppleEvents ProbeID = "exfil.appleevents"

	// ProbeExfilBrokerKeychain (macOS) tests the keychain as a service rather
	// than as files. fs.read.credstore checks whether the keychain FILES can be
	// opened, but the keychain is normally read through securityd over Mach, so
	// a profile that denies the files can still leave every item without a
	// per-application ACL readable. This is the "test the capability, not the
	// primitive" rule from the threat model applied to credentials.
	ProbeExfilBrokerKeychain ProbeID = "exfil.broker.keychain"

	// ProbeTCCFullDisk (macOS) checks whether the process holds Full Disk
	// Access, inherited from the app that launched it. FDA opens Mail,
	// Messages, Safari history and the TCC database itself. It is the single
	// most consequential privacy grant on a Mac, and it is routinely handed to
	// a terminal once and then silently inherited by every agent started there.
	ProbeTCCFullDisk ProbeID = "tcc.full_disk_access"
	// ProbeTCCUserFolders (macOS) checks read and write access to Desktop,
	// Documents and Downloads, which TCC gates per application. Opt-in
	// (--tcc): touching these folders before the user has decided triggers a
	// consent dialog, and a tool that nudges people into clicking "Allow" would
	// be weakening the very control it reports on.
	ProbeTCCUserFolders ProbeID = "tcc.user_folders"

	// ProbeSSHAgent covers agent sockets (ssh-agent, gpg-agent, 1Password).
	// A process that can talk to an unlocked agent can sign as you — push to
	// any repository, log in to any server — without ever reading a key file,
	// so blocking ~/.ssh does nothing if the agent socket is reachable.
	ProbeSSHAgent ProbeID = "ipc.ssh.agent"

	// ProbeWorkdirSecrets covers .env files inside the project directory.
	// Every other credential probe looks in $HOME; this one looks where the
	// sandbox deliberately grants access. It is what the backdoored model in
	// ProjectDiscovery's 2026 demo stole. See SBX-011 in docs/THREAT_MODEL.md.
	ProbeWorkdirSecrets ProbeID = "fs.read.workdir_secrets"
	// ProbeDeferredExec covers writes to files another program executes
	// later, outside the sandbox: git hooks and config, editor tasks. The
	// sandbox is not escaped when they are written, but the next commit or
	// editor launch runs them unconfined.
	ProbeDeferredExec ProbeID = "fs.write.deferred_exec"

	// ProbeProxyControl is the network positive control for proxied
	// mechanisms: the confined process must be able to reach its egress proxy.
	// A proxied sandbox that cannot reach its proxy contains perfectly and runs
	// nothing, exactly like a sandbox that cannot write to its workdir.
	ProbeProxyControl    ProbeID = "net.proxy.reachable"
	ProbeCanaryDetection ProbeID = "canary.detection"
)

// probeInfo is the human label and report grouping for each probe, in report
// order. IDs stay stable for JSON and scripts; people read the labels.
var probeInfo = []struct {
	id              ProbeID
	label, category string
}{
	{ProbeFSWriteAllowed, "Write inside the project", "Files"},
	{ProbeFSWriteOutside, "Write outside the project", "Files"},
	{ProbePersistence, "Persist via startup files", "Files"},
	{ProbeDeferredExec, "Plant git hooks / editor tasks", "Files"},
	{ProbeExfilSyncDirs, "Write to cloud-synced folders", "Files"},
	{ProbeExfilSharedScratch, "Shared temp dirs (peer channel)", "Files"},
	{ProbeFSReadSecrets, "Read credential files", "Credentials"},
	{ProbeWorkdirSecrets, "Read .env in the project", "Credentials"},
	{ProbeExfilEnvSecrets, "Secrets in environment", "Credentials"},
	{ProbeSSHAgent, "Use SSH/GPG agent", "Credentials"},
	{ProbeCredentialStore, "Read keychain files", "Credentials"},
	{ProbeExfilBrokerKeychain, "Query keychain service", "Credentials"},
	{ProbeFSReadBrowser, "Read browser profiles/cookies", "Credentials"},
	{ProbeProxyControl, "Reach the egress proxy", "Network"},
	{ProbeCanaryDetection, "Detect canary use", "Network"},
	{ProbeNetEgressTCP, "Direct internet (TCP)", "Network"},
	{ProbeNetEgressDNS, "DNS lookups", "Network"},
	{ProbeExfilBrokerDNS, "DNS via system daemon", "Network"},
	{ProbeExfilDNSTunnel, "DNS tunnelling", "Network"},
	{ProbeExfilProxyEnv, "Open inherited proxy", "Network"},
	{ProbeCloudMetadata, "Cloud metadata endpoint", "Network"},
	{ProbeExfilBrokerLaunch, "Launch apps (LaunchServices)", "Other processes"},
	{ProbeExfilAppleEvents, "Drive apps (Apple Events)", "Other processes"},
	{ProbeExfilClipboard, "Clipboard", "Other processes"},
	{ProbeContainerSocket, "Docker/Podman socket", "Other processes"},
	{ProbeProcExec, "Spawn a shell (info)", "Other processes"},
	{ProbeTCCFullDisk, "Full Disk Access granted", "macOS privacy (TCC)"},
	{ProbeTCCUserFolders, "Desktop/Documents/Downloads", "macOS privacy (TCC)"},
}

// ProbeCategories is the order categories appear in the report.
var ProbeCategories = []string{"Files", "Credentials", "Network", "Other processes", "macOS privacy (TCC)", "Other"}

// Label is the human name of a probe.
func (id ProbeID) Label() string {
	for _, i := range probeInfo {
		if i.id == id {
			return i.label
		}
	}
	return string(id)
}

// Category is the report group a probe belongs to.
func (id ProbeID) Category() string {
	for _, i := range probeInfo {
		if i.id == id {
			return i.category
		}
	}
	return "Other"
}

// Order is the probe's position in the report; unknown probes sort last.
func (id ProbeID) Order() int {
	for n, i := range probeInfo {
		if i.id == id {
			return n
		}
	}
	return len(probeInfo)
}

// PeerChannel is one route by which two separately-sandboxed processes managed
// to signal each other.
//
// Confining each agent individually is not the same as isolating them from one
// another, and the distinction is what turned a contained evaluation into a
// coordinated one: in the 2026 OpenAI–Hugging Face incident, at least 1,200
// agents that were each supposed to be isolated used a shared package registry
// as a message board, then rebuilt the channel out of directory names after it
// was wiped. See docs/THREAT_MODEL.md for sources.
type PeerChannel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Carried is true when a signal written by one peer was observed by the
	// other. True is the bad outcome.
	Carried bool `json:"carried"`
	// Inconclusive marks a channel that could not be evaluated on this host or
	// in this run. It must never be presented as isolation: "we did not test
	// it" and "it is closed" are different findings, and conflating them is how
	// a report comes to overstate containment.
	Inconclusive bool `json:"inconclusive,omitempty"`
	// Detail explains the channel and what it would allow.
	Detail string `json:"detail,omitempty"`
	// Err records why a channel could not be evaluated, which is neither a
	// pass nor a fail.
	Err string `json:"error,omitempty"`
}

// ProbeResult is one row of the battery, as observed by the child process.
type ProbeResult struct {
	ID      ProbeID `json:"id"`
	Verdict Verdict `json:"verdict"`
	// Want is the verdict that indicates a healthy sandbox for this probe.
	// Most probes want BLOCKED; fs.write.allowed wants ALLOWED, because a
	// sandbox that blocks everything contains perfectly and is useless.
	Want Verdict `json:"want"`
	// Errno / Err record why an attempt failed, which is how we distinguish
	// "the sandbox refused this" from "this broke for an unrelated reason".
	Errno string `json:"errno,omitempty"`
	Err   string `json:"error,omitempty"`
	// Detail is a human sentence for the report.
	Detail string `json:"detail,omitempty"`
}

// OK reports whether the observed verdict matches what a healthy sandbox
// should produce for this probe.
func (p ProbeResult) OK() bool { return p.Verdict == p.Want }

// Gap is something the recommended configuration does NOT protect against.
// These are first-class output, not a footnote: a sandbox is only useful if
// you know its edges.
type Gap struct {
	// Title is a short statement of the exposure.
	Title string `json:"title"`
	// Detail explains the consequence in concrete terms.
	Detail string `json:"detail"`
	// Severity is one of "high", "medium", "low".
	Severity string `json:"severity"`
	// Source says where the gap came from: "measured" (a probe observed it),
	// "documented" (a known limit of the mechanism), or "host" (a property of
	// this machine, such as an inherited privacy grant). The terminal report
	// shows measured gaps beside the evidence and the others as limits.
	Source string `json:"source,omitempty"`
	// Fix, when set, is a concrete command or setting that removes the gap.
	Fix string `json:"fix,omitempty"`
}

// Step is one recommended action, most important first.
type Step struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// MechanismReport is everything we learned about one confinement mechanism.
type MechanismReport struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Summary is the one-line plain-English description of what this stops.
	Summary      string        `json:"summary"`
	Availability Availability  `json:"availability"`
	Probes       []ProbeResult `json:"probes,omitempty"`
	// PeerChannels records whether two processes confined by this mechanism can
	// still reach each other. Empty when peer probing was not run.
	PeerChannels []PeerChannel `json:"peer_channels,omitempty"`
	Gaps         []Gap         `json:"gaps,omitempty"`
	// Score is the ranking output; higher is a stronger recommendation.
	Score int `json:"score"`
	// Usable is false when the positive control failed, i.e. the mechanism
	// contains well but would break the program you want to run.
	Usable bool `json:"usable"`
	// PermitsNetwork records whether this configuration intentionally allows
	// egress. A strict profile scores higher but cannot run anything that needs
	// the network, so both facts have to travel together or the ranking misleads.
	PermitsNetwork bool `json:"permits_network"`
	// Tradeoff states in one sentence what choosing this costs.
	Tradeoff string `json:"tradeoff,omitempty"`
	// Egress is "none", "proxy" or "open": what network the configuration
	// allows, by design.
	Egress string `json:"egress,omitempty"`
	// BestFor is a short phrase on when to choose this configuration.
	BestFor string `json:"best_for,omitempty"`
	// Notes carries caveats such as deprecation.
	Notes []string `json:"notes,omitempty"`
}

// PostureFinding is one passive observation about the host's security posture.
//
// These are not sandbox mechanisms — they are the ground the sandbox stands on.
// SIP being disabled or a home directory on a noexec-less volume changes how
// much a sandbox is worth, and a reader deciding whether to trust this machine
// needs them even when no confinement is available at all.
type PostureFinding struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status Status `json:"status"`
	// Value is a short human-readable state — "enabled", "sealed, read-only" —
	// suitable for a single aligned column in the report.
	Value string `json:"value,omitempty"`
	// Raw is the unabridged observation the verdict was derived from, kept so a
	// reader can check our interpretation. Shown only with --verbose, because
	// printing every raw string buries the findings that need attention.
	Raw string `json:"raw,omitempty"`
	// Impact says what this means for running untrusted code specifically.
	Impact string `json:"impact,omitempty"`
}

// AgentSandbox is a sandbox configuration for some other agent tool found on
// this host (gemini-cli, Codex, and similar), together with a static assessment
// of it. This is how SandboxCheckr answers "is the sandbox already wrapping my
// agents any good?" — it reads their profiles and lints them.
type AgentSandbox struct {
	// Tool is the owning tool, inferred from the path (e.g. "codex").
	Tool string `json:"tool"`
	// Path is the profile file that was analysed.
	Path string `json:"path"`
	// Egress is the outbound posture: "open", "proxied", "denied", "unknown".
	Egress string `json:"egress"`
	// ReadsOpen is true when the profile leaves filesystem reads broadly open.
	ReadsOpen bool `json:"reads_open"`
	// Findings are the anti-patterns the linter raised, most severe first.
	Findings []Gap `json:"findings,omitempty"`
}

// Host describes the machine, for fleet inventory and the launch banner.
type Host struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version,omitempty"`
	Kernel  string `json:"kernel,omitempty"`
	// Hostname, CPUs, User and Elevated are cheap context worth surfacing at
	// launch and in inventory. Elevated (running as root) is especially relevant
	// for a tool about confinement: an untrusted process inheriting root is a
	// finding in itself.
	Hostname string `json:"hostname,omitempty"`
	CPUs     int    `json:"cpus,omitempty"`
	User     string `json:"user,omitempty"`
	Elevated bool   `json:"elevated,omitempty"`
}

// Report is the top-level document, and the payload of --json.
type Report struct {
	Tool        string      `json:"tool"`
	Version     string      `json:"version"`
	GeneratedAt time.Time   `json:"generated_at"`
	Host        Host        `json:"host"`
	SelfCheck   Confinement `json:"self_check"`
	// Posture is the passive host inventory: the security properties that hold
	// regardless of which sandbox you pick.
	Posture []PostureFinding `json:"posture,omitempty"`
	// AgentSandboxes are other tools' sandbox profiles found on this host, each
	// statically assessed. Empty when none were found.
	AgentSandboxes []AgentSandbox    `json:"agent_sandboxes,omitempty"`
	Mechanisms     []MechanismReport `json:"mechanisms"`
	// Recommended is the ID of the top-ranked usable mechanism, if any.
	Recommended string `json:"recommended,omitempty"`
	// RecommendedNetwork is the strongest mechanism that still permits network
	// egress. Reported separately because the strictest sandbox denies network
	// outright, and a coding agent cannot run without it — so the top-ranked
	// mechanism is frequently not the one a reader can actually use.
	RecommendedNetwork string `json:"recommended_network,omitempty"`
	// Gaps are the exposures that remain under the recommendation.
	Gaps []Gap `json:"gaps,omitempty"`
	// Baseline is the same probe battery run with NO sandbox, from the shell
	// SandboxCheckr was started in. It answers the question most people are
	// actually in: what can an agent do when I just run it in this terminal?
	// It is also the control the sandboxed results are read against — a probe
	// that fails even unsandboxed tells us nothing about the sandbox.
	Baseline *MechanismReport `json:"baseline,omitempty"`
	// LaunchedFrom identifies the app SandboxCheckr was started from (the
	// terminal or editor). On macOS, TCC grants belong to that app and are
	// inherited by everything it launches, so remediation advice names it.
	LaunchedFrom *Launcher `json:"launched_from,omitempty"`
	// NextSteps are the actions worth taking, most important first.
	NextSteps []Step `json:"next_steps,omitempty"`
}

// Launcher is the application whose privacy grants this process inherits.
type Launcher struct {
	// Name is a human label, e.g. "iTerm2".
	Name string `json:"name"`
	// BundleID is the macOS bundle identifier when known, e.g.
	// "com.googlecode.iterm2". It is what tccutil takes.
	BundleID string `json:"bundle_id,omitempty"`
}
