//go:build !darwin && !linux

package probe

import "os"

// FileID has no portable implementation here. Returning "" disables the
// identity comparison, so the child falls back to treating whatever it finds
// at the home path as the real home — the conservative direction, since it can
// only over-report exposure.
func FileID(os.FileInfo) string { return "" }
