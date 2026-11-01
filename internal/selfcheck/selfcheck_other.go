//go:build !darwin && !linux && !windows

package selfcheck

import "github.com/danielcuthbert/sandboxcheckr/internal/model"

// detect has no implementation on this platform. It reports no evidence of
// confinement, which the report renders as "not detected", never as "absent".
func detect() model.Confinement { return model.Confinement{} }
