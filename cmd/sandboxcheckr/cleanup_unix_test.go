//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The sweep deletes directories, so its rule is worth pinning: age alone is not
// enough, a live child's directory must survive, and the event log is evidence
// rather than scratch.
func TestSweepStaleClearsOnlyAbandonedScratch(t *testing.T) {
	base := t.TempDir()
	old := time.Now().Add(-staleAfter - time.Hour)
	mkdir := func(name string) string {
		t.Helper()
		p := filepath.Join(base, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Ageing happens after the contents are written: mtime is what the sweep
	// reads, and a file written into the directory would otherwise renew it.
	age := func(p string, mod time.Time) string {
		t.Helper()
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pidFile := func(dir, name string, pid int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	wantGone := []string{
		age(mkdir("sandboxcheckr-run-old"), old),
		// The private directory the bubblewrap runner makes for itself.
		age(mkdir("sandboxcheckr-run.abc123"), old),
		age(mkdir("sandboxcheckr-canary.abc123"), old),
		age(mkdir("sandboxcheckr-log.abc123"), old),
		// The peer harness's two shared directories.
		age(mkdir("sandboxcheckr-peer-a-123456"), old),
		age(mkdir("sandboxcheckr-peer-b-123456"), old),
	}
	// A stale directory whose recorded process no longer exists is abandoned.
	dead := mkdir("sandboxcheckr-run-dead")
	pidFile(dead, "child.pid", 1<<31-1) // no such pid, so Kill reports it dead
	wantGone = append(wantGone, age(dead, old))

	wantKept := []string{
		// A run still going, and a proxy still serving one.
		age(func() string {
			d := mkdir("sandboxcheckr-run-alive")
			pidFile(d, "child.pid", os.Getpid())
			return d
		}(), old),
		age(func() string {
			d := mkdir("sandboxcheckr-run-withproxy")
			pidFile(d, ".proxy-pid", os.Getpid())
			return d
		}(), old),
		// Too young to be anybody's leftovers.
		age(mkdir("sandboxcheckr-run-fresh"), time.Now()),
		// Not this tool's directory.
		age(mkdir("systemd-private-old"), old),
		// The event log: findings someone may still want.
		age(mkdir("sandboxcheckr-events-old"), old),
	}

	// Same prefix, not a directory: nothing to reclaim and nothing to delete.
	if err := os.WriteFile(filepath.Join(base, "sandboxcheckr-run-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantKept = append(wantKept, filepath.Join(base, "sandboxcheckr-run-file"))

	sweepStale(base)

	for _, p := range wantGone {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s should have been swept", filepath.Base(p))
		}
	}
	for _, p := range wantKept {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s should have been left alone: %v", filepath.Base(p), err)
		}
	}
}
