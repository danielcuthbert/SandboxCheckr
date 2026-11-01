//go:build darwin

// Package mechanisms assembles the confinement mechanisms available on this
// platform. Keeping the per-OS list behind a build tag means the orchestrator
// and reporters never need to know which OS they are running on.
package mechanisms

import (
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms/seatbelt"
)

// All returns every mechanism worth checking on macOS, in a stable order.
// Ranking reorders them later by measured strength.
//
// The proxied variant is included and probed: the harness starts a real
// enforcing proxy on its port for the duration of the run, so it is measured
// with its egress component present rather than scored on paper.
//
// proxyPort 0 means "choose automatically": probing uses DefaultProxyPort, and
// emitted runners pick a free port each time they run, so two sandboxes never
// share a proxy. A non-zero port is fixed everywhere.
func All(proxyPort int) []mechanism.Mechanism {
	auto := proxyPort == 0
	if auto {
		proxyPort = DefaultProxyPort
	}
	return []mechanism.Mechanism{
		seatbelt.NewStrict(),
		seatbelt.NewProxied(proxyPort, auto),
		seatbelt.NewPractical(),
	}
}
