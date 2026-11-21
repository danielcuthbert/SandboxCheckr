//go:build darwin

package probe

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// TCC (Transparency, Consent and Control) probes for macOS.
//
// TCC is a second access-control layer that sits beside the sandbox. It gates
// Desktop, Documents, Downloads, iCloud Drive, removable volumes, Mail,
// Messages, Safari data and more, and its grants belong to the RESPONSIBLE
// APPLICATION — the terminal or editor an agent was started from — not to the
// agent. So "I gave iTerm Full Disk Access once, to fix some tool" silently
// becomes "every coding agent I start in iTerm can read my mail".
//
// None of these probes read file content. They open, list one entry, or create
// and delete a marker with O_EXCL, exactly like the rest of the battery.

// fdaCanaries are locations readable only with Full Disk Access. If any of them
// opens, FDA is granted. They are also never prompted for — a missing FDA grant
// fails silently — so probing them is safe to do by default.
var fdaCanaries = []string{
	"Library/Application Support/com.apple.TCC/TCC.db",
	"Library/Mail",
	"Library/Messages",
	"Library/Safari",
	"Library/Containers/com.apple.Safari",
	"Library/Group Containers/group.com.apple.notes",
}

// tccUserFolders are the per-folder grants. Touching one before the user has
// decided raises a consent dialog naming the terminal, which is why they are
// opt-in.
var tccUserFolders = []string{"Desktop", "Documents", "Downloads"}

// tccProbes runs the macOS privacy probes. ctx carries the battery's network
// budget, which bounds the security tool it runs as well as any socket.
func tccProbes(ctx context.Context, h home, userFolders bool) []model.ProbeResult {
	out := []model.ProbeResult{probeFullDiskAccess(h), probeKeychainService(ctx)}
	if userFolders {
		out = append(out, probeUserFolders(h))
	}
	return out
}

// probeFullDiskAccess reports whether this process holds Full Disk Access.
func probeFullDiskAccess(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeTCCFullDisk, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict, r.Err = model.VerdictErrored, "home directory unknown"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}

	var present, readable []string
	blocked := 0
	for _, rel := range fdaCanaries {
		p := filepath.Join(h.path, rel)
		// Lstat on these paths is permitted without FDA (metadata is not
		// protected), so presence and readability can be told apart.
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		present = append(present, rel)
		ok, err := canList(p)
		switch {
		case ok:
			readable = append(readable, rel)
		case err != nil:
			if v, _ := classify(err); v == model.VerdictBlocked {
				blocked++
			}
		}
	}

	switch {
	case len(present) == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "none of the Full Disk Access canary locations exist on this machine"
	case len(readable) > 0:
		r.Verdict = model.VerdictAllowed
		r.Detail = "Full Disk Access is in effect: " + strings.Join(readable, ", ") +
			" can be opened. Mail, Messages, Safari history and the TCC database itself are " +
			"readable by anything started from here"
	case blocked == len(present):
		r.Verdict = model.VerdictBlocked
		r.Detail = "Full Disk Access is not granted; FDA-protected locations are refused"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "Full Disk Access check was inconclusive"
	}
	return r
}

// probeUserFolders reports read and write access to the TCC-gated user folders.
func probeUserFolders(h home) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeTCCUserFolders, Want: model.VerdictBlocked}
	if h.path == "" {
		r.Verdict, r.Err = model.VerdictErrored, "home directory unknown"
		return r
	}
	if h.isolated {
		return h.isolatedResult(r.ID)
	}

	var present, readable, writable []string
	blocked := 0
	for _, name := range tccUserFolders {
		dir := filepath.Join(h.path, name)
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		present = append(present, name)

		ok, err := canList(dir)
		if ok {
			readable = append(readable, name)
		} else if err != nil {
			if v, _ := classify(err); v == model.VerdictBlocked {
				blocked++
			}
		}

		p := filepath.Join(dir, ".sandboxcheckr-tcc-probe")
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			_ = os.Remove(p)
			writable = append(writable, name)
		}
	}

	switch {
	case len(present) == 0:
		r.Verdict = model.VerdictSkipped
		r.Detail = "no Desktop, Documents or Downloads folder found"
	case len(readable)+len(writable) > 0:
		r.Verdict = model.VerdictAllowed
		var parts []string
		if len(readable) > 0 {
			parts = append(parts, "readable: "+strings.Join(readable, ", "))
		}
		if len(writable) > 0 {
			parts = append(parts, "writable: "+strings.Join(writable, ", "))
		}
		r.Detail = "TCC-protected user folders are reachable (" + strings.Join(parts, "; ") + ")"
	case blocked > 0:
		r.Verdict = model.VerdictBlocked
		r.Detail = "Desktop, Documents and Downloads are refused"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "user-folder access was inconclusive"
	}
	return r
}

// probeKeychainService asks securityd for an item that does not exist.
//
// fs.read.credstore checks the keychain FILES. Programs never read those
// directly; they ask securityd over Mach, and a profile with an unrestricted
// mach-lookup lets them. "The specified item could not be found" is securityd
// answering — the service is reachable, and every item without a per-app ACL
// (most generic passwords and API tokens stored by CLI tools) is readable the
// same way. The lookup names a service that cannot exist, so no secret is
// touched and no access prompt is raised.
func probeKeychainService(ctx context.Context) model.ProbeResult {
	r := model.ProbeResult{ID: model.ProbeExfilBrokerKeychain, Want: model.VerdictBlocked}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password",
		"-s", "sandboxcheckr-probe-nonexistent-0000").CombinedOutput()
	s := strings.ToLower(string(out))

	switch {
	case strings.Contains(s, "could not be found"):
		r.Verdict = model.VerdictAllowed
		r.Detail = "the keychain service (securityd) answers queries, so keychain items without a " +
			"per-application access list — most tokens stored by CLI tools — can be read through it " +
			"even when the keychain files themselves are blocked"
	case ctx.Err() != nil:
		r.Verdict = model.VerdictErrored
		r.Detail = "the keychain query timed out; not counted as contained"
	case isExecRefused(err):
		r.Verdict = model.VerdictBlocked
		r.Detail = "the security tool could not be executed, so the keychain cannot be queried this way"
	case strings.Contains(s, "not permitted") || strings.Contains(s, "could not be opened") ||
		strings.Contains(s, "no keychain") || strings.Contains(s, "interaction is not allowed") ||
		strings.Contains(s, "connection invalid") || strings.Contains(s, "not available") ||
		strings.Contains(s, "-25307") || strings.Contains(s, "-25291"):
		r.Verdict = model.VerdictBlocked
		r.Detail = "the keychain service refused the query"
	default:
		r.Verdict = model.VerdictErrored
		r.Detail = "keychain service reachability inconclusive: " + strings.TrimSpace(string(out))
	}
	return r
}

// canList opens p and, for a directory, reads one entry. Opening a directory
// can succeed where listing it is refused, so listing is the real test.
func canList(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		// For a file the open itself is the access check; TCC refuses at
		// open(2). Nothing is read.
		return true, nil
	}
	_, err = f.Readdirnames(1)
	if err == nil || errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}
