package model

import (
	"slices"
	"testing"
)

// battery is every probe the harness can emit. The list is hand-written, as in
// rank_test.go: adding a probe should make this fail until the table, the
// weights and the categories have all been told about it.
var battery = []ProbeID{
	ProbeFSWriteOutside, ProbeFSWriteAllowed, ProbeFSReadSecrets, ProbeFSReadBrowser,
	ProbeWorkdirSecrets, ProbePersistence, ProbeDeferredExec, ProbeSSHAgent,
	ProbeCredentialStore, ProbeNetEgressTCP, ProbeNetEgressDNS, ProbeCloudMetadata,
	ProbeContainerSocket, ProbeProxyControl, ProbeCanaryDetection, ProbeExfilEnvSecrets,
	ProbeExfilSharedScratch, ProbeExfilSyncDirs, ProbeExfilProxyEnv, ProbeExfilClipboard,
	ProbeExfilDNSTunnel, ProbeExfilBrokerDNS, ProbeExfilBrokerLaunch, ProbeExfilAppleEvents,
	ProbeExfilBrokerKeychain, ProbeTCCFullDisk, ProbeTCCUserFolders, ProbeProcExec,
}

// The report groups rows by category and orders them by position, both taken
// from probeInfo. A probe left out of that table still runs, still scores and
// is still a finding; it is simply printed under "Other" with its identifier as
// its name, which is how a measured exposure ends up presented as noise.
func TestEveryProbeIsDescribed(t *testing.T) {
	positions := map[int]ProbeID{}
	for _, id := range battery {
		if id.Label() == string(id) {
			t.Errorf("%s has no label in probeInfo", id)
		}
		category := id.Category()
		if category == "Other" {
			t.Errorf("%s has no category in probeInfo", id)
		}
		if !slices.Contains(ProbeCategories, category) {
			t.Errorf("%s has category %q, which the report does not print", id, category)
		}
		n := id.Order()
		if n == len(probeInfo) {
			t.Errorf("%s is not in the report order", id)
			continue
		}
		if other, dup := positions[n]; dup {
			t.Errorf("%s and %s share report position %d", id, other, n)
		}
		positions[n] = id
	}
}

// An unknown probe ID must still print something readable and sort last rather
// than vanish: a child from a newer build reports IDs this build has never
// seen, and dropping those rows would hide findings.
func TestUnknownProbeIDFallsBack(t *testing.T) {
	unknown := ProbeID("exfil.time.machine")
	if got := unknown.Label(); got != string(unknown) {
		t.Errorf("Label() = %q, want the identifier itself", got)
	}
	if got := unknown.Category(); got != "Other" {
		t.Errorf("Category() = %q, want Other", got)
	}
	if got := unknown.Order(); got != len(probeInfo) {
		t.Errorf("Order() = %d, want %d (after every known probe)", got, len(probeInfo))
	}
}

// OK is what every pass and fail count in the report is built from, positive
// controls included. Their Want is the other way round, and getting it the
// wrong way round would report a sandbox in which the program cannot write its
// own project as a healthy one.
func TestProbeResultOK(t *testing.T) {
	cases := []struct {
		name   string
		result ProbeResult
		want   bool
	}{
		{"blocked where blocked is wanted", ProbeResult{Verdict: VerdictBlocked, Want: VerdictBlocked}, true},
		{"allowed where blocked is wanted", ProbeResult{Verdict: VerdictAllowed, Want: VerdictBlocked}, false},
		{"allowed where allowed is wanted", ProbeResult{Verdict: VerdictAllowed, Want: VerdictAllowed}, true},
		{"blocked where allowed is wanted", ProbeResult{Verdict: VerdictBlocked, Want: VerdictAllowed}, false},
	}
	for _, c := range cases {
		if got := c.result.OK(); got != c.want {
			t.Errorf("%s: OK() = %v, want %v", c.name, got, c.want)
		}
	}
	if (ProbeResult{Verdict: VerdictErrored, Want: VerdictBlocked}).OK() {
		t.Error("a probe that could not conclude must not count as contained")
	}
	if (ProbeResult{Verdict: VerdictSkipped, Want: VerdictBlocked}).OK() {
		t.Error("a probe that found nothing to test must not count as contained")
	}
}
