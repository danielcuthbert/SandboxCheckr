//go:build linux

package detect

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

func collect(_ context.Context) []model.PostureFinding {
	var out []model.PostureFinding

	out = append(out, landlockFinding())
	out = append(out, lsmFinding(readFile("/sys/kernel/security/lsm")))
	out = append(out, usernsFinding(
		readFile("/proc/sys/kernel/unprivileged_userns_clone"),
		readFile("/proc/sys/user/max_user_namespaces"),
	))
	out = append(out, seccompFinding(readFile("/proc/self/status")))
	out = append(out, cgroupsFinding())
	out = append(out, runtimesFinding())

	return out
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// Landlock syscall numbers. These are identical across architectures because
// Landlock was added after the kernel moved to a shared syscall table for new
// calls, so a single constant is correct on x86_64, arm64 and riscv.
const (
	sysLandlockCreateRuleset = 444
	// landlockVersionFlag asks the kernel for the supported ABI version instead
	// of creating a ruleset.
	landlockVersionFlag = 1 << 0
)

// landlockABI queries the running kernel for its Landlock ABI version.
//
// This is queried at runtime rather than inferred from the kernel version
// string, because distributions backport Landlock and a version number tells
// you nothing reliable about which access rights are actually available.
// Returns 0 when Landlock is unsupported.
func landlockABI() int {
	r, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockVersionFlag)
	if errno != 0 {
		return 0
	}
	return int(r)
}

// abiCapabilities maps an ABI level to what it can actually restrict. Every
// right introduced at level N is present on every kernel reporting >= N.
func abiCapabilities(abi int) string {
	switch {
	case abi >= 10:
		return "filesystem, TCP and UDP ports, unix-socket and signal scoping"
	case abi >= 6:
		return "filesystem, TCP ports, unix-socket and signal scoping (no UDP)"
	case abi >= 4:
		return "filesystem and TCP bind/connect ports (no UDP, no socket scoping)"
	case abi >= 1:
		return "filesystem paths only — no network restriction"
	default:
		return ""
	}
}

func landlockFinding() model.PostureFinding {
	f := model.PostureFinding{ID: "landlock", Name: "Landlock LSM"}
	abi := landlockABI()
	if abi == 0 {
		f.Status, f.Value = model.StatusAbsent, "unsupported"
		f.Impact = "Landlock is unavailable, so unprivileged filesystem confinement without " +
			"namespaces or root is not possible."
		return f
	}
	f.Status = model.StatusPass
	f.Value = "ABI " + strconv.Itoa(abi)
	f.Impact = "Landlock ABI " + strconv.Itoa(abi) + " can restrict: " + abiCapabilities(abi) +
		". It needs no root and no namespaces."
	if abi < 4 {
		f.Status = model.StatusDegraded
		f.Impact += " Network egress cannot be restricted at this ABI, so it cannot stop a " +
			"piped download on its own."
	}
	return f
}

// parseLSM interprets /sys/kernel/security/lsm, a comma-separated list of
// active security modules.
func parseLSM(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func lsmFinding(raw string) model.PostureFinding {
	f := model.PostureFinding{ID: "lsm", Name: "Active security modules"}
	mods := parseLSM(raw)
	if len(mods) == 0 {
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Could not read the active LSM list."
		return f
	}
	f.Raw = strings.Join(mods, ",")

	var major []string
	for _, m := range mods {
		switch m {
		case "apparmor", "selinux", "smack", "tomoyo":
			major = append(major, m)
		}
	}
	if len(major) > 0 {
		f.Status, f.Value = model.StatusPass, strings.Join(major, ", ")
		f.Impact = "A mandatory access control module is active (" + strings.Join(major, ", ") +
			"), which can confine processes independently of any sandbox you choose."
		return f
	}
	f.Status, f.Value = model.StatusDegraded, "no MAC module"
	f.Impact = "No mandatory access control module (AppArmor/SELinux) is active; confinement " +
		"depends entirely on namespaces, seccomp and Landlock."
	return f
}

// usernfFinding reports whether unprivileged user namespaces are permitted.
// They are the foundation of rootless containers and bubblewrap, so a hardened
// kernel that disables them removes most unprivileged sandboxing options.
func usernsFinding(clone, maxNS string) model.PostureFinding {
	f := model.PostureFinding{ID: "userns", Name: "Unprivileged user namespaces"}

	clone, maxNS = strings.TrimSpace(clone), strings.TrimSpace(maxNS)
	f.Raw = strings.TrimSpace("unprivileged_userns_clone=" + clone + " max_user_namespaces=" + maxNS)

	// Debian-family kernels expose the clone toggle; others only expose the max.
	if clone == "0" || maxNS == "0" {
		f.Status, f.Value = model.StatusFail, "DISABLED"
		f.Impact = "Unprivileged user namespaces are DISABLED. Rootless containers and bubblewrap " +
			"will not work, which removes most unprivileged sandboxing options on this host."
		return f
	}
	f.Status, f.Value = model.StatusPass, "permitted"
	f.Impact = "Unprivileged user namespaces are permitted, so rootless containers and bubblewrap " +
		"can confine processes without root."
	return f
}

// parseSeccompMode extracts the Seccomp field from /proc/self/status.
func parseSeccompMode(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
		}
	}
	return ""
}

func seccompFinding(status string) model.PostureFinding {
	f := model.PostureFinding{ID: "seccomp", Name: "seccomp-bpf"}
	mode := parseSeccompMode(status)
	if mode == "" {
		f.Status, f.Value = model.StatusIndeterminate, "unknown"
		f.Impact = "Could not determine seccomp support."
		return f
	}
	f.Value, f.Raw = "available", "mode "+mode
	f.Status = model.StatusPass
	f.Impact = "The kernel exposes seccomp, so syscall filtering is available to confine what a " +
		"process can ask the kernel to do."
	return f
}

func cgroupsFinding() model.PostureFinding {
	f := model.PostureFinding{ID: "cgroups", Name: "cgroups v2"}
	if c := readFile("/sys/fs/cgroup/cgroup.controllers"); strings.TrimSpace(c) != "" {
		f.Status, f.Value = model.StatusPass, "available"
		f.Raw = strings.TrimSpace(c)
		f.Impact = "cgroups v2 is available, so CPU, memory and process limits can be enforced on " +
			"a confined process."
		return f
	}
	f.Status, f.Value = model.StatusDegraded, "unavailable"
	f.Impact = "cgroups v2 is unavailable; resource limits cannot be applied via the unified hierarchy."
	return f
}

var containerRuntimes = []string{"docker", "podman", "nerdctl", "bwrap", "firejail", "systemd-run", "nsjail"}

func runtimesFinding() model.PostureFinding {
	f := model.PostureFinding{ID: "container-runtimes", Name: "Sandbox / container tooling"}
	var found []string
	for _, name := range containerRuntimes {
		if _, _, err := sysexec.LookupUnprivileged(name); err == nil {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		f.Status, f.Value = model.StatusAbsent, "none installed"
		f.Impact = "No sandboxing tool is installed. Installing bubblewrap would provide " +
			"unprivileged namespace-based confinement."
		return f
	}
	f.Status = model.StatusPass
	f.Value = strings.Join(found, ", ")
	f.Impact = "Sandboxing tools are installed and can confine an untrusted process."
	return f
}
