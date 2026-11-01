// Package detect performs the passive host-posture inventory.
//
// This is deliberately separate from the mechanism checks. A mechanism answers
// "how can I confine a process here"; posture answers "what is true about this
// machine regardless of what I confine". The second question still matters when
// the answer to the first is "nothing" — a reader who learns that no sandbox is
// available also needs to know whether SIP is on, whether the disk is
// encrypted, and whether a container runtime is sitting there unused.
//
// Every check is read-only and side-effect free.
package detect

import (
	"context"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// Run collects the platform's posture findings.
func Run(ctx context.Context) []model.PostureFinding {
	return collect(ctx)
}

// The parsing helpers below are kept free of I/O so they can be unit-tested on
// any platform against captured fixtures. The collectors do the I/O and hand
// raw text to these.

// parseCsrutil interprets the output of `csrutil status`.
//
// SIP protects system files from modification even by root. With it disabled,
// malicious code that gains root can alter the OS itself, and no user-space
// sandbox recommendation survives that.
func parseCsrutil(out string) model.PostureFinding {
	f := model.PostureFinding{
		ID:   "sip",
		Name: "System Integrity Protection",
		Raw:  strings.TrimSpace(out),
	}
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "status: enabled"):
		f.Status, f.Value = model.StatusPass, "enabled"
		f.Impact = "System files are protected from modification even by root."
	case strings.Contains(low, "status: disabled"):
		f.Status, f.Value = model.StatusFail, "DISABLED"
		f.Impact = "SIP is OFF. Code that gains root can modify the operating system itself, " +
			"which defeats any user-space sandbox you layer on top."
	case strings.Contains(low, "unknown"), low == "":
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Could not determine SIP status."
	default:
		// Partial/custom configurations report which protections are disabled.
		f.Status, f.Value = model.StatusDegraded, "partially configured"
		f.Impact = "SIP is partially configured; some protections are disabled."
	}
	return f
}

// parseSpctl interprets `spctl --status`.
func parseSpctl(out string) model.PostureFinding {
	f := model.PostureFinding{
		ID:   "gatekeeper",
		Name: "Gatekeeper",
		Raw:  strings.TrimSpace(out),
	}
	switch {
	case strings.Contains(out, "assessments enabled"):
		f.Status, f.Value = model.StatusPass, "enabled"
		f.Impact = "Unsigned and unnotarised downloaded binaries are blocked from launching."
	case strings.Contains(out, "assessments disabled"):
		f.Status, f.Value = model.StatusFail, "DISABLED"
		f.Impact = "Gatekeeper is OFF. Any downloaded binary will launch without signature or " +
			"notarisation checks."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}

// mountInfo is one parsed line of `mount` output.
type mountInfo struct {
	Device  string
	Point   string
	Options []string
}

func (m mountInfo) has(opt string) bool {
	for _, o := range m.Options {
		if o == opt {
			return true
		}
	}
	return false
}

// parseMounts parses BSD-style `mount` output:
//
//	/dev/disk3s1 on /System/Volumes/Data (apfs, local, journaled, nobrowse)
func parseMounts(out string) []mountInfo {
	var mounts []mountInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		onIdx := strings.Index(line, " on ")
		openParen := strings.LastIndex(line, "(")
		closeParen := strings.LastIndex(line, ")")
		if onIdx < 0 || openParen < 0 || closeParen < openParen {
			continue
		}
		m := mountInfo{
			Device: strings.TrimSpace(line[:onIdx]),
			Point:  strings.TrimSpace(line[onIdx+4 : openParen]),
		}
		for _, o := range strings.Split(line[openParen+1:closeParen], ",") {
			if o = strings.TrimSpace(o); o != "" {
				m.Options = append(m.Options, o)
			}
		}
		mounts = append(mounts, m)
	}
	return mounts
}

// findMount returns the mount entry whose point exactly matches p.
func findMount(mounts []mountInfo, p string) (mountInfo, bool) {
	for _, m := range mounts {
		if m.Point == p {
			return m, true
		}
	}
	return mountInfo{}, false
}

// rootVolumeFinding reports whether the system volume is sealed and read-only,
// which is what stops untrusted code from tampering with the OS on disk.
func rootVolumeFinding(mounts []mountInfo) model.PostureFinding {
	f := model.PostureFinding{ID: "root-volume", Name: "System volume protection"}
	m, ok := findMount(mounts, "/")
	if !ok {
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Could not identify the root mount."
		return f
	}
	f.Raw = strings.Join(m.Options, ",")
	sealed, ro := m.has("sealed"), m.has("read-only")
	switch {
	case sealed && ro:
		f.Status, f.Value = model.StatusPass, "sealed, read-only"
		f.Impact = "The system volume is a sealed, read-only snapshot; OS files cannot be modified on disk."
	case ro:
		f.Status, f.Value = model.StatusDegraded, "read-only, not sealed"
		f.Impact = "The system volume is read-only but not sealed."
	default:
		f.Status, f.Value = model.StatusFail, "WRITABLE"
		f.Impact = "The system volume is writable, so OS files can be tampered with."
	}
	return f
}
