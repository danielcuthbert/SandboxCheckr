//go:build !darwin

package probe

import "github.com/danielcuthbert/sandboxcheckr/internal/model"

// tccProbes has no non-macOS implementation: TCC is an Apple concept. Windows'
// nearest analogue, Controlled Folder Access, is reported in host posture.
func tccProbes(home, bool) []model.ProbeResult { return nil }
