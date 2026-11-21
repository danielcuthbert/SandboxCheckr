package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// DenyFile is a list of hosts to refuse, re-read whenever it changes, so a
// person watching a run can cut a destination off without restarting
// anything. It is a kill switch layered on the allow-list, never a substitute
// for it: it can only take access away. That is also why it is safe for the
// file to be edited while the proxy runs — the worst an edit can do is return
// the proxy to its allow-list.
//
// One host per line; '#' starts a comment. An entry matches the host and its
// subdomains: "evil.com" refuses "evil.com" and "a.evil.com", because when
// you are cutting something off you mean all of it. Entries that are not
// valid hostnames are ignored and counted.
//
// The idea comes from agent-seatbelt-sandbox's live blocked.txt, which showed
// how useful a mid-run kill switch is next to a live log.
type DenyFile struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	exists  bool
	entries []string
	invalid int
	// truncated says the file was cut off at maxDenyFileBytes, so hosts past
	// that point are not enforced.
	truncated bool
}

// maxDenyFileBytes caps how much of the file is read.
const maxDenyFileBytes = 1 << 20

// NewDenyFile returns a DenyFile for path and loads it. A missing file is an
// empty list, not an error: the runners point at a default path that exists
// only once someone blocks something.
func NewDenyFile(path string) (*DenyFile, error) {
	d := &DenyFile{path: path}
	if _, err := d.Refresh(); err != nil {
		return nil, err
	}
	return d, nil
}

// Path is the file being watched.
func (d *DenyFile) Path() string { return d.path }

// Refresh re-reads the file if it changed since the last read, reporting
// whether it did. The stat, the read and the parse all happen without the lock
// held: Match is on the path of every connection and every relayed query, so a
// reload must not be able to stall the decision path behind a file read.
func (d *DenyFile) Refresh() (bool, error) {
	d.mu.Lock()
	same := d.exists
	mt, sz := d.modTime, d.size
	d.mu.Unlock()

	fi, err := os.Stat(d.path)
	if os.IsNotExist(err) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.exists {
			return false, nil
		}
		d.exists, d.entries, d.invalid, d.truncated = false, nil, 0, false
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("deny file %s is not a regular file", d.path)
	}
	if same && fi.ModTime().Equal(mt) && fi.Size() == sz {
		return false, nil
	}
	f, err := os.Open(d.path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	// One byte past the cap is read so that hitting the cap is observable: the
	// file is append-mostly, so the entry lost to truncation is the one someone
	// added last, which is the opposite of what a kill switch should do quietly.
	data, err := io.ReadAll(io.LimitReader(f, maxDenyFileBytes+1))
	if err != nil {
		return false, err
	}
	truncated := len(data) > maxDenyFileBytes
	if truncated {
		data = data[:maxDenyFileBytes]
	}
	entries, invalid := ParseDenyList(data)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.exists, d.modTime, d.size = true, fi.ModTime(), fi.Size()
	d.entries, d.invalid, d.truncated = entries, invalid, truncated
	return true, nil
}

// ParseDenyList reads deny-file content: the valid entries, normalised, and
// the number of lines that were not hostnames.
func ParseDenyList(data []byte) (entries []string, invalid int) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		h := normHost(strings.TrimPrefix(strings.TrimSpace(line), "*."))
		if h == "" {
			continue
		}
		if !ValidHostname(h) {
			invalid++
			continue
		}
		if !seen[h] {
			seen[h] = true
			entries = append(entries, h)
		}
	}
	return entries, invalid
}

// Match reports the entry that refuses host, if any. It refreshes the list
// first, so an edit takes effect on the very next connection.
func (d *DenyFile) Match(host string) (string, bool) {
	if d == nil {
		return "", false
	}
	// No Refresh here: the watcher goroutine is the sole reloader, so every
	// reload is logged exactly once (a decision-path refresh would consume the
	// mtime change and starve the watcher's "DENYFILE reloaded" line).
	return d.match(host)
}

func (d *DenyFile) match(host string) (string, bool) {
	h := normHost(host)
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if h == e || strings.HasSuffix(h, "."+e) {
			return e, true
		}
	}
	return "", false
}

// Entries returns the current list and the number of invalid lines skipped.
func (d *DenyFile) Entries() ([]string, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.entries...), d.invalid
}

// Truncated reports whether the last read hit the size cap, meaning hosts
// listed past that point are not enforced. The caller logs it: a kill switch
// that silently stops covering the list is worse than one that fails loudly.
func (d *DenyFile) Truncated() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.truncated
}
