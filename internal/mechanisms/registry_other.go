//go:build !darwin && !linux

package mechanisms

import "github.com/danielcuthbert/sandboxcheckr/internal/mechanism"

// All returns no mechanisms on platforms without an implementation yet
// (Windows included). The report still runs the unsandboxed baseline and host
// posture, and says plainly that no sandbox could be built — rather than
// failing to compile, or implying one exists.
func All(int) []mechanism.Mechanism { return nil }
