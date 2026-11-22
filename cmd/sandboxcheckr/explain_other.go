//go:build !darwin

package main

import "time"

// kernelLogDenials has nothing to ask. bubblewrap refuses inside a network
// namespace, a read-only bind tree and a seccomp filter, and none of that is
// logged anywhere a normal user can read: the program simply gets EPERM. The
// caller turns this into a plain statement rather than an empty table, which
// would read as "nothing was refused".
func kernelLogDenials(since, until time.Time) ([]string, error) {
	return nil, errExplainUnsupported
}
