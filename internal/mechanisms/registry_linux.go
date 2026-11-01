//go:build linux

package mechanisms

import (
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanism"
	"github.com/danielcuthbert/sandboxcheckr/internal/mechanisms/bwrap"
)

// All returns every mechanism worth checking on Linux, in a stable order.
// Ranking reorders them later by measured strength.
//
// Rootless containers and a Landlock-enforcing mechanism are not implemented
// yet; the Landlock ABI is reported in the host posture inventory instead.
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
		bwrap.NewStrict(),
		bwrap.NewProxied(proxyPort, auto),
		bwrap.NewPractical(),
	}
}
