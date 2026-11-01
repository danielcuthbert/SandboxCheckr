//go:build darwin

package detect

import (
	"context"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

func collect(ctx context.Context) []model.PostureFinding {
	var out []model.PostureFinding

	out = append(out, runTool(ctx, "csrutil", []string{"status"}, parseCsrutil))
	out = append(out, runTool(ctx, "spctl", []string{"--status"}, parseSpctl))

	mounts := readMounts(ctx)
	out = append(out, rootVolumeFinding(mounts))
	out = append(out, homeExecFinding(mounts))

	out = append(out, fileVaultFinding(ctx))
	out = append(out, hypervisorFinding(ctx))
	out = append(out, runtimesFinding())

	return out
}

// runTool executes a system tool and hands its output to a pure parser. When
// the tool is missing or fails we report INDETERMINATE rather than inventing a
// verdict — an unanswered question is not a passing grade.
func runTool(ctx context.Context, name string, args []string, parse func(string) model.PostureFinding) model.PostureFinding {
	path, err := sysexec.Lookup(name)
	if err != nil {
		f := parse("")
		f.Status = model.StatusIndeterminate
		f.Impact = name + " is not available, so this could not be checked."
		return f
	}
	out, err := sysexec.Run(ctx, path, args...)
	if err != nil && strings.TrimSpace(out) == "" {
		f := parse("")
		f.Status = model.StatusIndeterminate
		f.Impact = name + " failed: " + err.Error()
		return f
	}
	return parse(out)
}

func readMounts(ctx context.Context) []mountInfo {
	path, err := sysexec.Lookup("mount")
	if err != nil {
		return nil
	}
	out, err := sysexec.Run(ctx, path)
	if err != nil {
		return nil
	}
	return parseMounts(out)
}

// homeExecFinding reports whether the data volume permits setuid binaries and
// execution. Most macOS installs do, so this is usually informational — but it
// is the difference between a dropped payload being runnable and being inert.
func homeExecFinding(mounts []mountInfo) model.PostureFinding {
	f := model.PostureFinding{ID: "data-volume-flags", Name: "Data volume mount flags"}
	m, ok := findMount(mounts, "/System/Volumes/Data")
	if !ok {
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Could not identify the data volume."
		return f
	}
	f.Raw = strings.Join(m.Options, ",")
	noexec, nosuid := m.has("noexec"), m.has("nosuid")
	switch {
	case noexec && nosuid:
		f.Status, f.Value = model.StatusPass, "noexec, nosuid"
		f.Impact = "User data is mounted noexec and nosuid; dropped binaries cannot be executed from it."
	case nosuid:
		f.Status, f.Value = model.StatusDegraded, "exec permitted"
		f.Impact = "User data is nosuid but executable. A downloaded binary placed here can be run, " +
			"though it cannot gain privileges via setuid."
	default:
		f.Status, f.Value = model.StatusDegraded, "exec + setuid permitted"
		f.Impact = "User data is executable and permits setuid. This is the macOS default: any binary " +
			"written to your home directory can be run immediately."
	}
	return f
}

// fileVaultFinding reports disk encryption state. It does not constrain a
// running process, but it decides whether files a sandbox protects at runtime
// are also protected when the machine is off.
func fileVaultFinding(ctx context.Context) model.PostureFinding {
	f := model.PostureFinding{ID: "filevault", Name: "FileVault disk encryption"}
	path, err := sysexec.Lookup("fdesetup")
	if err != nil {
		f.Status = model.StatusIndeterminate
		return f
	}
	out, _ := sysexec.Run(ctx, path, "status")
	f.Raw = strings.TrimSpace(out)
	switch {
	case strings.Contains(out, "FileVault is On"):
		f.Status, f.Value = model.StatusPass, "on"
		f.Impact = "The disk is encrypted at rest."
	case strings.Contains(out, "FileVault is Off"):
		f.Status, f.Value = model.StatusFail, "OFF"
		f.Impact = "The disk is NOT encrypted. Anything a sandbox protects at runtime is readable " +
			"by anyone with physical access."
	default:
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
	}
	return f
}

// hypervisorFinding reports whether hardware virtualisation is available, since
// a VM is the strongest containment boundary on the machine.
func hypervisorFinding(ctx context.Context) model.PostureFinding {
	f := model.PostureFinding{ID: "hypervisor", Name: "Hardware virtualisation"}
	path, err := sysexec.Lookup("sysctl")
	if err != nil {
		f.Status = model.StatusIndeterminate
		return f
	}
	out, _ := sysexec.Run(ctx, path, "-n", "kern.hv_support")
	f.Raw = "kern.hv_support=" + strings.TrimSpace(out)
	if strings.TrimSpace(out) == "1" {
		f.Status, f.Value = model.StatusPass, "supported"
		f.Impact = "Hypervisor.framework is supported, so a VM-based sandbox (the strongest boundary " +
			"available here) is possible."
	} else {
		f.Status, f.Value = model.StatusDegraded, "unavailable"
		f.Impact = "Hardware virtualisation is unavailable; VM-based isolation is not an option."
	}
	return f
}

// containerRuntimes are checked by name. These are legitimately installed
// outside system directories, so they resolve through the weaker unprivileged
// lookup and the report says so.
var containerRuntimes = []string{"container", "docker", "podman", "colima", "lima", "nerdctl"}

func runtimesFinding() model.PostureFinding {
	f := model.PostureFinding{ID: "container-runtimes", Name: "Container / VM runtimes"}

	var found, untrusted []string
	for _, name := range containerRuntimes {
		p, trusted, err := sysexec.LookupUnprivileged(name)
		if err != nil {
			continue
		}
		found = append(found, name)
		if !trusted {
			untrusted = append(untrusted, name+" ("+p+")")
		}
	}

	if len(found) == 0 {
		f.Status, f.Value = model.StatusAbsent, "none installed"
		f.Impact = "No container runtime is installed, so VM-backed isolation — the strongest option " +
			"on macOS — is not currently available."
		return f
	}

	f.Status = model.StatusPass
	f.Value = strings.Join(found, ", ")
	f.Raw = strings.Join(untrusted, "; ")
	f.Impact = "A container runtime is available. On macOS these run inside a Linux VM, which is a " +
		"stronger boundary than Seatbelt."
	if len(untrusted) > 0 {
		f.Impact += " Note: resolved outside system directories via PATH, so the binary itself is " +
			"less trustworthy than a system tool: " + strings.Join(untrusted, ", ") + "."
	}
	return f
}
