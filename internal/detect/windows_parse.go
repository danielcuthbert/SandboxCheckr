package detect

import (
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// The Windows parsers live in an untagged file so they are unit-tested on every
// platform against captured values, the same way the macOS and Linux parsers
// are. Each takes the raw string PowerShell printed; an empty string means the
// query failed or was not permitted, which is reported as INDETERMINATE.

// parseKV reads KEY=VALUE lines.
func parseKV(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return kv
}

func truthy(v string) (val bool, known bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "on", "enabled":
		return true, true
	case "false", "0", "off", "disabled":
		return false, true
	}
	return false, false
}

func bitLockerFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "bitlocker", Name: "BitLocker (system drive)", Raw: v}
	switch strings.ToLower(v) {
	case "on", "1":
		f.Status, f.Value = model.StatusPass, "on"
		f.Impact = "The system drive is encrypted at rest."
	case "off", "0":
		f.Status, f.Value = model.StatusFail, "OFF"
		f.Impact = "The system drive is NOT encrypted. Anything a sandbox protects at runtime is readable " +
			"by anyone with physical access."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "BitLocker status could not be read (it normally requires an elevated shell)."
	}
	return f
}

func secureBootFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "secureboot", Name: "Secure Boot", Raw: v}
	b, ok := truthy(v)
	switch {
	case ok && b:
		f.Status, f.Value = model.StatusPass, "enabled"
		f.Impact = "Only signed boot components load, so a bootkit cannot sit beneath the OS."
	case ok:
		f.Status, f.Value = model.StatusFail, "DISABLED"
		f.Impact = "Secure Boot is off; code that gains admin can install a bootkit that survives reinstalls."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Secure Boot state could not be read (legacy BIOS, or the query needs elevation)."
	}
	return f
}

// vbsFinding interprets Win32_DeviceGuard: VirtualizationBasedSecurityStatus is
// 0 (off), 1 (enabled, not running) or 2 (running); HVCI is whether service 2
// (hypervisor-enforced code integrity) is running.
func vbsFinding(vbs, hvci string) model.PostureFinding {
	f := model.PostureFinding{ID: "vbs", Name: "Virtualization-based security", Raw: "vbs=" + vbs + " hvci=" + hvci}
	h, _ := truthy(hvci)
	switch vbs {
	case "2":
		if h {
			f.Status, f.Value = model.StatusPass, "running, HVCI on"
			f.Impact = "Kernel code integrity is enforced by the hypervisor, so even admin code cannot load unsigned drivers."
		} else {
			f.Status, f.Value = model.StatusDegraded, "running, HVCI off"
			f.Impact = "VBS is running but memory integrity (HVCI) is off, so vulnerable or unsigned drivers can still load."
		}
	case "1":
		f.Status, f.Value = model.StatusDegraded, "enabled, not running"
		f.Impact = "VBS is configured but not running; its protections are not in effect."
	case "0":
		f.Status, f.Value = model.StatusDegraded, "off"
		f.Impact = "VBS is off. Credential Guard and memory integrity are unavailable."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}

func defenderFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "defender", Name: "Defender real-time protection", Raw: v}
	b, ok := truthy(v)
	switch {
	case ok && b:
		f.Status, f.Value = model.StatusPass, "on"
		f.Impact = "Files are scanned as they are written and executed."
	case ok:
		f.Status, f.Value = model.StatusFail, "OFF"
		f.Impact = "Real-time protection is off (or another AV has replaced it — check before acting)."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Defender status could not be read; a third-party antivirus may be installed instead."
	}
	return f
}

// cfaFinding interprets EnableControlledFolderAccess: 0 off, 1 block, 2 audit.
// Controlled Folder Access is the closest Windows analogue to macOS TCC folder
// protection: it stops unapproved programs writing to Documents, Pictures and
// Desktop. Like TCC, approval is per program, so an approved terminal passes
// that approval to everything it starts.
func cfaFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "controlled-folder-access", Name: "Controlled Folder Access", Raw: v}
	switch v {
	case "1":
		f.Status, f.Value = model.StatusPass, "block"
		f.Impact = "Unapproved programs cannot write to protected folders. Approvals are per program, so " +
			"approving a terminal approves everything started from it."
	case "2":
		f.Status, f.Value = model.StatusDegraded, "audit only"
		f.Impact = "Writes to protected folders are logged, not blocked."
	case "0":
		f.Status, f.Value = model.StatusDegraded, "off"
		f.Impact = "Any program — including an agent — can modify or encrypt Documents, Desktop and Pictures."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}

// smartAppControlFinding interprets VerifiedAndReputablePolicyState: 0 off,
// 1 enforce, 2 evaluation.
func smartAppControlFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "smart-app-control", Name: "Smart App Control", Raw: v}
	switch v {
	case "1":
		f.Status, f.Value = model.StatusPass, "on"
		f.Impact = "Untrusted, unsigned executables are blocked from running."
	case "2":
		f.Status, f.Value = model.StatusDegraded, "evaluation"
		f.Impact = "Smart App Control is evaluating and not yet blocking anything."
	case "0":
		f.Status, f.Value = model.StatusDegraded, "off"
		f.Impact = "A downloaded, unsigned binary will run. (Once turned off it can only be re-enabled by reinstalling Windows.)"
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}

func uacFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "uac", Name: "User Account Control", Raw: v}
	switch v {
	case "1":
		f.Status, f.Value = model.StatusPass, "enabled"
		f.Impact = "Programs run without admin rights unless elevation is approved."
	case "0":
		f.Status, f.Value = model.StatusFail, "DISABLED"
		f.Impact = "UAC is off: every program started by an admin user runs with full admin rights."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}

func windowsSandboxFinding(v string) model.PostureFinding {
	f := model.PostureFinding{ID: "windows-sandbox", Name: "Windows Sandbox", Raw: v}
	switch strings.ToLower(v) {
	case "enabled":
		f.Status, f.Value = model.StatusPass, "enabled"
		f.Impact = "A disposable Hyper-V VM is available for running untrusted programs. SandboxCheckr " +
			"does not generate Windows Sandbox configurations yet."
	case "disabled", "disabledwithpayloadremoved":
		f.Status, f.Value = model.StatusAbsent, "not enabled"
		f.Impact = "Windows Sandbox (Pro/Enterprise) is available as an optional feature but not enabled."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}
