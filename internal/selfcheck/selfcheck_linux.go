//go:build linux

package selfcheck

import (
	"bufio"
	"os"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// detect looks for evidence that this process is already confined on Linux.
//
// Linux is more forthcoming than macOS: the kernel publishes most of what we
// need in /proc/self, so these checks read files rather than inferring from the
// failure of an operation.
func detect() model.Confinement {
	return conclude([]signal{
		seccompActive(),
		userNamespaced(),
		landlockDomain(),
		containerized(),
	})
}

// procStatusField reads a single field from /proc/self/status.
func procStatusField(name string) (string, bool) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", false
	}
	defer f.Close()

	prefix := name + ":"
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
		}
	}
	return "", false
}

// seccompActive reports whether a seccomp filter is installed on this process.
// Mode 2 is SECCOMP_MODE_FILTER; mode 1 is strict mode.
func seccompActive() signal {
	v, ok := procStatusField("Seccomp")
	if !ok {
		return signal{}
	}
	switch strings.TrimSpace(v) {
	case "1":
		return signal{present: true, kind: "seccomp", detail: "seccomp strict mode (1) is active on this process"}
	case "2":
		return signal{present: true, kind: "seccomp", detail: "a seccomp-bpf filter (mode 2) is installed on this process"}
	}
	return signal{}
}

// userNamespaced reports whether we are in a non-initial user namespace.
//
// The initial namespace maps the whole uid range in one entry starting at 0
// ("0 0 4294967295"). Anything else means we have been remapped, which implies
// a sandbox, container, or unprivileged userns.
func userNamespaced() signal {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return signal{}
	}
	line := strings.Fields(strings.TrimSpace(string(b)))
	if len(line) == 3 && line[0] == "0" && line[1] == "0" && line[2] == "4294967295" {
		return signal{}
	}
	return signal{
		present: true,
		kind:    "userns",
		detail:  "uid_map indicates a non-initial user namespace: " + strings.TrimSpace(string(b)),
	}
}

// landlockDomain reports whether a Landlock ruleset is enforced on us.
// The kernel exposes the number of enclosing Landlock domains in
// /proc/self/status on kernels that support the field.
func landlockDomain() signal {
	// Landlock reports via the "Landlock" field where available.
	if v, ok := procStatusField("Landlock"); ok && strings.TrimSpace(v) != "0" {
		return signal{present: true, kind: "landlock", detail: "a Landlock domain is enforced on this process"}
	}
	return signal{}
}

// containerized looks for the usual container tells. These are heuristics —
// each can be absent in a real container and present outside one — so they are
// reported as evidence lines rather than treated as proof on their own.
func containerized() signal {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return signal{present: true, kind: "container", detail: "/.dockerenv is present"}
	}
	if v := os.Getenv("container"); v != "" {
		return signal{present: true, kind: "container", detail: "the 'container' environment variable is set to " + v}
	}
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		s := string(b)
		for _, marker := range []string{"/docker/", "/podman/", "libpod", "kubepods", "/lxc/"} {
			if strings.Contains(s, marker) {
				return signal{present: true, kind: "container", detail: "cgroup path contains container marker " + marker}
			}
		}
	}
	return signal{}
}
