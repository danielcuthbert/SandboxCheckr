//go:build unix

package proxy

import (
	"os"
	"syscall"
)

const oNoFollow = syscall.O_NOFOLLOW

func ownedByRoot(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
