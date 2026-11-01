//go:build !darwin

package probe

import "github.com/danielcuthbert/sandboxcheckr/internal/model"

// brokerProbes has no non-macOS implementation: brokered egress via
// LaunchServices and mDNSResponder is a macOS-specific concept. On Linux the
// analogous concern (a shared D-Bus / host network) is covered by the bwrap
// namespace configuration instead.
func brokerProbes() []model.ProbeResult { return nil }
