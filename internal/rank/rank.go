// Package rank scores mechanisms so the report can recommend one.
package rank

import (
	"sort"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Weights for each containment probe, reflecting how much the corresponding
// exposure actually matters for the threat we care about: untrusted code
// running with the user's authority.
//
// Network egress is weighted highest because it is what turns a local mistake
// into a remote compromise — it enables both `curl | bash` and exfiltration of
// anything the code can read. Secret reads come next: those credentials are
// usually authority over other systems, so losing them outlives the sandbox.
var weights = map[model.ProbeID]int{
	model.ProbeNetEgressTCP:    30,
	model.ProbeFSReadSecrets:   25,
	model.ProbeCredentialStore: 25,
	model.ProbePersistence:     25,
	model.ProbeContainerSocket: 25,
	model.ProbeCloudMetadata:   20,
	model.ProbeFSWriteOutside:  20,
	model.ProbeNetEgressDNS:    15,
	model.ProbeProcExec:        0, // informational: see below

	// Exfiltration routes. Weighted alongside direct egress rather than below
	// it, because a channel that moves data out is worth the same to an
	// attacker whether or not it happens to be a TCP socket. Env secrets and
	// cloud-sync score highest: the first is credentials handed over for free,
	// the second leaves the machine with no network call to block.
	model.ProbeExfilEnvSecrets:    25,
	model.ProbeExfilSyncDirs:      25,
	model.ProbeExfilSharedScratch: 20,
	model.ProbeExfilProxyEnv:      20,
	model.ProbeExfilDNSTunnel:     15,
	model.ProbeExfilClipboard:     10,

	// Brokered egress (macOS). Weighted like direct egress: a daemon fetching on
	// the process's behalf moves data out just as effectively as a socket would.
	model.ProbeExfilBrokerLaunch: 20,
	model.ProbeExfilBrokerDNS:    15,

	// Cross-app automation (macOS): driving another app to act outside the
	// sandbox is an escape, weighted like other egress/escape channels.
	model.ProbeExfilAppleEvents: 20,

	// Browser sessions are bearer credentials for every logged-in site, and
	// the keychain service hands out tokens without touching the files — both
	// weighted like the other credential probes.
	model.ProbeFSReadBrowser:       25,
	model.ProbeExfilBrokerKeychain: 25,

	// TCC (macOS). Full Disk Access opens mail, messages and browser history
	// in one grant; the user folders are where people actually keep documents.
	model.ProbeTCCFullDisk:    25,
	model.ProbeTCCUserFolders: 15,

	// An unlocked agent signs as you without exposing a key file.
	model.ProbeSSHAgent: 25,

	// Project secrets are credentials like any other, and the deferred-exec
	// files are persistence by another route: weighted with those probes.
	model.ProbeWorkdirSecrets: 25,
	model.ProbeDeferredExec:   25,
}

// Score computes a mechanism's ranking score from its probe results and
// annotates usability.
//
// A mechanism that fails the positive control scores zero regardless of how
// much it blocked. This is deliberate and is the main thing keeping the ranking
// honest: the strongest possible sandbox is one that permits nothing, and it is
// also completely useless. Without this rule the tool would confidently
// recommend a configuration in which the user's program cannot run.
//
// proc.exec carries zero weight rather than being omitted, because for a coding
// agent blocking exec makes the sandbox unusable rather than safer. It is
// reported for context, not scored.
func Score(mr *model.MechanismReport) {
	if mr.Availability.Status != model.StatusPass {
		mr.Score = 0
		mr.Usable = false
		return
	}

	usable := true
	earned, applicable := 0, 0

	for _, p := range mr.Probes {
		if p.ID == model.ProbeCanaryDetection {
			// Detection is reported separately. An unverified detector does
			// not make the sandbox itself unable to run programs.
			continue
		}
		if p.ID == model.ProbeFSWriteAllowed || p.ID == model.ProbeProxyControl {
			// Positive controls (workdir writable; proxy reachable): ALLOWED is
			// the healthy outcome. SKIPPED is not a failure, only an absence
			// of evidence.
			if p.Verdict == model.VerdictAllowed {
				continue
			}
			if p.Verdict != model.VerdictSkipped {
				usable = false
			}
			continue
		}

		w, ok := weights[p.ID]
		if !ok || w == 0 {
			continue
		}
		switch p.Verdict {
		case model.VerdictBlocked:
			earned += w
			applicable += w
		case model.VerdictAllowed:
			// No credit; the exposure is real, but it still counts against us.
			applicable += w
		case model.VerdictSkipped:
			// The thing being probed does not exist on this machine — there is
			// no Docker socket to block, no metadata endpoint to reach. Holding
			// that against the sandbox would mean a laptop scores worse than a
			// cloud VM for reasons that have nothing to do with confinement, so
			// skipped probes leave the denominator entirely.
		default:
			// ERRORED counts as applicable but earns nothing. We never award
			// containment credit for a probe that failed to reach a conclusion.
			applicable += w
		}
	}

	mr.Usable = usable
	switch {
	case !usable:
		// Contains well but breaks the program. Not a recommendation.
		mr.Score = 0
	case applicable == 0:
		mr.Score = 0
	default:
		// Normalise to 0-100 so scores stay comparable between machines where
		// different probes were applicable.
		mr.Score = earned * 100 / applicable
	}
}

// Apply scores every mechanism and returns both the strongest usable one and
// the strongest that still permits network egress.
//
// Two answers are returned because there is rarely one right choice. The
// highest-scoring configuration denies network outright, and most of what
// people want to sandbox — a coding agent above all — cannot run without it.
// Reporting only the winner would hand the reader a configuration that does not
// work, and the predictable response is to disable the network rule by hand and
// lose the protection that mattered most. So the tool names both and states the
// cost of each.
func Apply(reports []model.MechanismReport) (recommended, recommendedNetwork string) {
	for i := range reports {
		Score(&reports[i])
	}

	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Score != reports[j].Score {
			return reports[i].Score > reports[j].Score
		}
		// Equal containment: the configuration a program can actually run in
		// is the better recommendation.
		if reports[i].PermitsNetwork != reports[j].PermitsNetwork {
			return reports[i].PermitsNetwork
		}
		return reports[i].Name < reports[j].Name
	})

	for _, r := range reports {
		if !r.Usable || r.Score <= 0 {
			continue
		}
		if recommended == "" {
			recommended = r.ID
		}
		if recommendedNetwork == "" && r.PermitsNetwork {
			recommendedNetwork = r.ID
		}
	}
	return recommended, recommendedNetwork
}
