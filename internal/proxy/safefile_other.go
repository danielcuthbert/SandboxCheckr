//go:build !unix

package proxy

import "os"

// No O_NOFOLLOW here; checkNoSymlink's Lstat checks still apply.
const oNoFollow = 0

func ownedByRoot(os.FileInfo) bool { return false }
