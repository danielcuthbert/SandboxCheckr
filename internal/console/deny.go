package console

import (
	"fmt"
	"os"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/events"
	"github.com/danielcuthbert/sandboxcheckr/internal/proxy"
)

// editDeny adds hosts to, or removes them from, the kill-switch file. Every
// proxy started with --deny-file pointing at it re-reads it within a second
// and cuts open connections to an added host.
//
// The file is rewritten whole via proxy.WriteFileNoFollow: the temporary file
// and rename mean a proxy never reads half an edit, the fsync before the rename
// means a crash cannot leave the file zero-length (a lost write here silently
// unblocks every host the operator cut off), and the no-follow checks mean a
// program that can write the workdir cannot point the write at ~/.ssh by
// replacing the directory with a symlink. Comments and the order of the
// remaining lines are kept.
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
	if err := proxy.WriteFileNoFollow(c.DenyPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
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
	// Print the lines as the file holds them, not ParseDenyList's normalised
	// entries: it strips the "*." of "*.example.com", so the list showed
	// "example.com" and "unblock example.com" then deleted the broader
	// wildcard while the user believed they had removed something narrower.
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			fmt.Fprintf(c.Out.W, "  %s\n", events.Clean(l, 80))
		}
	}
	if invalid > 0 {
		fmt.Fprintf(c.Out.W, "  (%d lines are not hostnames and are ignored)\n", invalid)
	}
	fmt.Fprintln(c.Out.W, c.Out.c("2", "  file: "+events.Clean(c.DenyPath, 100)))
	return nil
}
