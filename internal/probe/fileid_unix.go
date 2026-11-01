//go:build darwin || linux

package probe

import (
	"os"
	"strconv"
	"syscall"
)

// FileID returns a "device:inode" identity for fi, or "" when unavailable.
//
// The harness records the host's identity for the home directory and the
// child compares it with what it sees. A sandbox that mounts an empty tmpfs at
// the same path produces a different identity, which is how the child tells
// "the real home, writable" apart from "a throwaway directory with the same
// name" — two cases with opposite security meaning.
func FileID(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
}
