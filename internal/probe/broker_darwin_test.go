//go:build darwin

package probe

import (
	"testing"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// The brokered-egress probes must declare BLOCKED as healthy (a daemon fetching
// on the process's behalf is a leak) and always carry an explanation.
func TestBrokerProbesDeclareWantBlocked(t *testing.T) {
	got := brokerProbes()
	if len(got) != 3 {
		t.Fatalf("expected 3 broker probes, got %d", len(got))
	}
	for _, r := range got {
		if r.Want != model.VerdictBlocked {
			t.Errorf("%s wants %s, should want BLOCKED", r.ID, r.Want)
		}
		if r.Detail == "" {
			t.Errorf("%s produced no detail", r.ID)
		}
	}
}
