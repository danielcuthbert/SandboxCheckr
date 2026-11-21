//go:build !darwin

package probe

import (
	"context"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// tccProbes has no non-macOS implementation: TCC is an Apple concept. Windows'
// nearest analogue, Controlled Folder Access, is reported in host posture.
func tccProbes(context.Context, home, bool) []model.ProbeResult { return nil }
