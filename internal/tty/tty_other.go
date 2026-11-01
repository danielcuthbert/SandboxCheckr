//go:build !darwin && !linux

package tty

import "os"

// ioctlWidth has no portable implementation off darwin/linux; Width falls back
// to the COLUMNS environment variable there. Present so the package still builds
// under any GOOS.
func ioctlWidth(*os.File) int { return 0 }
