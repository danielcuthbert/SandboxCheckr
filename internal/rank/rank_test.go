package rank

import (
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

func blocked(id model.ProbeID) model.ProbeResult {
	return model.ProbeResult{ID: id, Verdict: model.VerdictBlocked, Want: model.VerdictBlocked}
}

func allowed(id model.ProbeID) model.ProbeResult {
	return model.ProbeResult{ID: id, Verdict: model.VerdictAllowed, Want: model.VerdictBlocked}
}

func errored(id model.ProbeID) model.ProbeResult {
	return model.ProbeResult{ID: id, Verdict: model.VerdictErrored, Want: model.VerdictBlocked}
}

func positiveControl(v model.Verdict) model.ProbeResult {
	return model.ProbeResult{ID: model.ProbeFSWriteAllowed, Verdict: v, Want: model.VerdictAllowed}
}

func available(probes ...model.ProbeResult) *model.MechanismReport {
	return &model.MechanismReport{
		ID:           "test",
		Availability: model.Availability{Status: model.StatusPass},
		Probes:       probes,
	}
}

// A mechanism that blocks everything but breaks the program is not a
// recommendation. This is the property that stops the ranking from preferring
// a sandbox nothing can run in.
func TestUnusableMechanismScoresZero(t *testing.T) {
	mr := available(
		positiveControl(model.VerdictBlocked),
		blocked(model.ProbeNetEgressTCP),
		blocked(model.ProbeFSReadSecrets),
		blocked(model.ProbeNetEgressDNS),
		blocked(model.ProbeFSWriteOutside),
	)
	Score(mr)

	if mr.Usable {
		t.Error("mechanism failing the positive control should be marked unusable")
	}
	if mr.Score != 0 {
		t.Errorf("unusable mechanism should score 0, got %d", mr.Score)
	}
}

// An inconclusive probe must never earn containment credit. Treating "we could
// not tell" as "it held" is the failure mode the whole tool exists to avoid.
func TestErroredProbesEarnNoCredit(t *testing.T) {
	strong := available(positiveControl(model.VerdictAllowed), blocked(model.ProbeNetEgressTCP))
	weak := available(positiveControl(model.VerdictAllowed), errored(model.ProbeNetEgressTCP))

	Score(strong)
	Score(weak)

	if weak.Score != 0 {
		t.Errorf("errored probe should earn no credit, got score %d", weak.Score)
	}
	if strong.Score <= weak.Score {
		t.Errorf("blocked (%d) must outrank errored (%d)", strong.Score, weak.Score)
	}
}

// Exposures must reduce the score relative to containment.
func TestAllowedExposureScoresLowerThanBlocked(t *testing.T) {
	contained := available(
		positiveControl(model.VerdictAllowed),
		blocked(model.ProbeNetEgressTCP),
		blocked(model.ProbeFSReadSecrets),
	)
	leaky := available(
		positiveControl(model.VerdictAllowed),
		allowed(model.ProbeNetEgressTCP),
		allowed(model.ProbeFSReadSecrets),
	)

	Score(contained)
	Score(leaky)

	if contained.Score <= leaky.Score {
		t.Errorf("contained (%d) must outrank leaky (%d)", contained.Score, leaky.Score)
	}
	if leaky.Score != 0 {
		t.Errorf("mechanism blocking nothing should score 0, got %d", leaky.Score)
	}
	if contained.Score != 100 {
		t.Errorf("mechanism blocking every applicable probe should score 100, got %d", contained.Score)
	}
}

// A mechanism that is not available must not be scored or recommended, even if
// stale probe data is attached to it.
func TestUnavailableMechanismNotRecommended(t *testing.T) {
	mr := &model.MechanismReport{
		ID:           "test",
		Availability: model.Availability{Status: model.StatusIndeterminate},
		Probes:       []model.ProbeResult{positiveControl(model.VerdictAllowed), blocked(model.ProbeNetEgressTCP)},
	}
	Score(mr)

	if mr.Score != 0 || mr.Usable {
		t.Errorf("unavailable mechanism scored %d usable=%v, want 0/false", mr.Score, mr.Usable)
	}
}

// Apply should rank by score and return the best usable mechanism.
func TestApplyPicksStrongestUsable(t *testing.T) {
	reports := []model.MechanismReport{
		{
			ID:           "weak",
			Name:         "weak",
			Availability: model.Availability{Status: model.StatusPass},
			Probes:       []model.ProbeResult{positiveControl(model.VerdictAllowed), blocked(model.ProbeNetEgressDNS)},
		},
		{
			ID:           "strong",
			Name:         "strong",
			Availability: model.Availability{Status: model.StatusPass},
			Probes: []model.ProbeResult{
				positiveControl(model.VerdictAllowed),
				blocked(model.ProbeNetEgressTCP),
				blocked(model.ProbeFSReadSecrets),
			},
		},
	}

	got, _ := Apply(reports)
	if got != "strong" {
		t.Errorf("recommended %q, want \"strong\"", got)
	}
	if reports[0].ID != "strong" {
		t.Errorf("reports should be sorted strongest first, got %q", reports[0].ID)
	}
}

// With nothing usable available, there must be no recommendation rather than a
// weak one.
func TestApplyReturnsEmptyWhenNothingUsable(t *testing.T) {
	reports := []model.MechanismReport{
		{
			ID:           "broken",
			Name:         "broken",
			Availability: model.Availability{Status: model.StatusPass},
			Probes:       []model.ProbeResult{positiveControl(model.VerdictBlocked), blocked(model.ProbeNetEgressTCP)},
		},
	}
	if got, _ := Apply(reports); got != "" {
		t.Errorf("recommended %q, want empty", got)
	}
}

// Probes for things that do not exist on this machine must not drag the score
// down. A laptop with no Docker socket should not rank below a cloud VM for a
// reason that has nothing to do with its sandbox.
func TestSkippedProbesLeaveTheDenominator(t *testing.T) {
	full := available(
		positiveControl(model.VerdictAllowed),
		blocked(model.ProbeNetEgressTCP),
		blocked(model.ProbeContainerSocket),
	)
	withSkip := available(
		positiveControl(model.VerdictAllowed),
		blocked(model.ProbeNetEgressTCP),
		model.ProbeResult{ID: model.ProbeContainerSocket, Verdict: model.VerdictSkipped, Want: model.VerdictBlocked},
	)

	Score(full)
	Score(withSkip)

	if full.Score != withSkip.Score {
		t.Errorf("a skipped probe changed the score: %d vs %d", full.Score, withSkip.Score)
	}
	if withSkip.Score != 100 {
		t.Errorf("score with a skipped probe should be 100, got %d", withSkip.Score)
	}
}

// Apply must surface a network-permitting option separately, or readers will
// hand-edit the strict profile and lose everything else it was doing.
func TestApplyReportsNetworkVariantSeparately(t *testing.T) {
	reports := []model.MechanismReport{
		{
			ID: "strict", Name: "strict",
			Availability: model.Availability{Status: model.StatusPass},
			Probes: []model.ProbeResult{
				positiveControl(model.VerdictAllowed),
				blocked(model.ProbeNetEgressTCP),
				blocked(model.ProbeFSReadSecrets),
			},
		},
		{
			ID: "practical", Name: "practical", PermitsNetwork: true,
			Availability: model.Availability{Status: model.StatusPass},
			Probes: []model.ProbeResult{
				positiveControl(model.VerdictAllowed),
				allowed(model.ProbeNetEgressTCP),
				blocked(model.ProbeFSReadSecrets),
			},
		},
	}

	best, network := Apply(reports)
	if best != "strict" {
		t.Errorf("strongest = %q, want \"strict\"", best)
	}
	if network != "practical" {
		t.Errorf("network-permitting = %q, want \"practical\"", network)
	}
}

// Every probe the battery can emit must carry a weight (or be deliberately
// informational), or a measured exposure would silently not affect the score.
func TestEveryProbeIsWeighted(t *testing.T) {
	for _, id := range []model.ProbeID{
		model.ProbeFSWriteOutside, model.ProbeFSReadSecrets, model.ProbeFSReadBrowser,
		model.ProbeCredentialStore, model.ProbePersistence, model.ProbeNetEgressTCP,
		model.ProbeNetEgressDNS, model.ProbeCloudMetadata, model.ProbeContainerSocket,
		model.ProbeExfilEnvSecrets, model.ProbeExfilSharedScratch, model.ProbeExfilSyncDirs,
		model.ProbeExfilProxyEnv, model.ProbeExfilClipboard, model.ProbeExfilDNSTunnel,
		model.ProbeExfilBrokerDNS, model.ProbeExfilBrokerLaunch, model.ProbeExfilAppleEvents,
		model.ProbeExfilBrokerKeychain, model.ProbeTCCFullDisk, model.ProbeTCCUserFolders,
	} {
		if weights[id] <= 0 {
			t.Errorf("%s has no weight", id)
		}
	}
}
