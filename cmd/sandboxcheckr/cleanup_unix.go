//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// staleAfter is how old one of the tool's scratch directories must be before a
// later start clears it away. A run's own trap removes them; this only ever
// sees the ones left by a run that was killed outright.
const staleAfter = 6 * time.Hour

// stalePrefix is this tool's scratch namespace in /tmp: the private runner
// directories (the generated policy script, which nothing outside the run
// needs), the proxy's own log, the planted canary set, the peer harness's two
// shared directories. Anything under the prefix is scratch unless it is named
// below.
const stalePrefix = "sandboxcheckr-"

// keepPrefix marks the one thing under that prefix that is not scratch: the
// default event log. An old run's findings are the thing a user is most likely
// to come back for, so the sweep leaves them alone.
const keepPrefix = "sandboxcheckr-events-"

// sweepStalePrivateDirs removes this user's leftover scratch directories from
// /tmp. A crash or a kill -9 skips the trap that would have removed them, and
// on a machine where the tool is used daily that is a quiet leak of directories
// the user never asked to keep, holding copies of the runner policy.
//
// A directory is only removed when three things hold: it belongs to this uid
// (the sticky bit on /tmp is not a permission model to lean on), it is older
// than staleAfter, and no live process claims it. The liveness check matters
// for the canary directory above all: a run that is still going is writing to
// it, and its child.pid is the runner's own record of that.
//
// Called at the start of a run rather than from a cleaner subcommand, because a
// subcommand nobody runs is a leak that stays.
func sweepStalePrivateDirs() {
	seen := map[string]bool{}
	for _, base := range []string{"/tmp", os.TempDir()} {
		if base == "" || seen[base] {
			continue
		}
		seen[base] = true
		sweepStale(base)
	}
}

// sweepStale clears one scratch directory base. Split out so the rule can be
// exercised against a temporary directory instead of the real /tmp.
func sweepStale(base string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, stalePrefix) || strings.HasPrefix(name, keepPrefix) {
			continue
		}
		path := filepath.Join(base, name)
		fi, err := os.Lstat(path)
		if err != nil || !fi.IsDir() || time.Since(fi.ModTime()) < staleAfter || !ownedByMe(fi) {
			continue
		}
		if dirInUse(path) {
			continue
		}
		_ = os.RemoveAll(path)
	}
}

// ownedByMe reports whether fi belongs to the current user, so the sweep never
// reaches into another account's scratch, sticky bit or not.
func ownedByMe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// dirInUse reports whether a process still holds the directory: the runner
// writes the sandboxed program's pid into child.pid and the proxy's pid into
// .proxy-pid, both inside the private directory the sandbox cannot see.
func dirInUse(path string) bool {
	for _, name := range []string{"child.pid", ".proxy-pid"} {
		b, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 1 {
			continue
		}
		if syscall.Kill(pid, 0) == nil {
			return true
		}
		if name == ".proxy-pid" && aliveProxy(pid) {
			return true
		}
	}
	return false
}
