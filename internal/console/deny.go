package console

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

// editDeny adds hosts to, or removes them from, the kill-switch file. Every
// proxy started with --deny-file pointing at it re-reads it within a second
// and cuts open connections to an added host.
//
// The file is rewritten whole, via a temporary file and a rename, so a proxy
// never reads half an edit. Comments and the order of the remaining lines are
// kept.
func (c *Console) editDeny(hosts []string, add bool) error {
	if c.DenyPath == "" {
		return fmt.Errorf("no kill-switch file configured (--deny-file)")
	}
	var want []string
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(h), "*.")), ".")
		if !proxy.ValidHostname(h) {
			return fmt.Errorf("%q is not a hostname", events.Clean(h, 60))
		}
		want = append(want, h)
	}
	old, err := os.ReadFile(c.DenyPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	current, _ := proxy.ParseDenyList(old)
	has := map[string]bool{}
	for _, e := range current {
		has[e] = true
	}

	var lines []string
	if len(old) > 0 {
		lines = strings.Split(strings.TrimRight(string(old), "\n"), "\n")
	} else {
		lines = []string{
			"# SandboxCheckr kill switch: hosts every running proxy refuses, even if allowed.",
			"# One per line; subdomains are included. Edits take effect within a second.",
		}
	}
	var changed []string
	if add {
		for _, h := range want {
			if !has[h] {
				lines = append(lines, h)
				has[h] = true
				changed = append(changed, h)
			}
		}
	} else {
		drop := map[string]bool{}
		for _, h := range want {
			if has[h] {
				drop[h] = true
				changed = append(changed, h)
			}
		}
		kept := lines[:0]
		for _, l := range lines {
			entry := l
			if i := strings.IndexByte(entry, '#'); i >= 0 {
				entry = entry[:i]
			}
			entry = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(entry), "*.")), ".")
			if !drop[entry] {
				kept = append(kept, l)
			}
		}
		lines = kept
	}
	if len(changed) == 0 {
		if add {
			fmt.Fprintln(c.Out.W, "already blocked")
		} else {
			fmt.Fprintln(c.Out.W, "none of those were blocked; try: blocked")
		}
		return nil
	}
	if err := writeAtomic(c.DenyPath, []byte(strings.Join(lines, "\n")+"\n")); err != nil {
		return err
	}
	if add {
		fmt.Fprintf(c.Out.W, "%s %s — every proxy using %s refuses %s now, and cuts open connections to %s within a second\n",
			c.Out.c("31;1", "BLOCKED"), strings.Join(changed, ", "), events.Clean(c.DenyPath, 80),
			map[bool]string{true: "them", false: "it"}[len(changed) > 1],
			map[bool]string{true: "them", false: "it"}[len(changed) > 1])
		fmt.Fprintln(c.Out.W, c.Out.c("2", "  (subdomains included; a proxy started without --deny-file is unaffected)"))
	} else {
		fmt.Fprintf(c.Out.W, "unblocked %s — back to each proxy's allow-list\n", strings.Join(changed, ", "))
	}
	return nil
}

func (c *Console) showDeny() error {
	if c.DenyPath == "" {
		return fmt.Errorf("no kill-switch file configured (--deny-file)")
	}
	data, err := os.ReadFile(c.DenyPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(c.Out.W, "nothing blocked (%s does not exist yet)\n", events.Clean(c.DenyPath, 80))
		return nil
	}
	if err != nil {
		return err
	}
	entries, invalid := proxy.ParseDenyList(data)
	if len(entries) == 0 {
		fmt.Fprintln(c.Out.W, "nothing blocked")
	}
	for _, e := range entries {
		fmt.Fprintf(c.Out.W, "  %s\n", events.Clean(e, 80))
	}
	if invalid > 0 {
		fmt.Fprintf(c.Out.W, "  (%d lines are not hostnames and are ignored)\n", invalid)
	}
	fmt.Fprintln(c.Out.W, c.Out.c("2", "  file: "+events.Clean(c.DenyPath, 100)))
	return nil
}

// writeAtomic replaces path with data via a temporary file in the same
// directory, refusing to write through a symlink.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write %s: it is a symlink", path)
	}
	tmp, err := os.CreateTemp(dir, ".deny-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
