//go:build windows

package selfcheck

import (
	"os"
	"strings"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

// detect looks for evidence that this process is already confined on Windows.
//
// The authoritative signal — an AppContainer or low-integrity token — needs
// GetTokenInformation, which is reachable without cgo but is not implemented
// yet. These heuristics catch the common container and Windows Sandbox cases;
// the absence of a signal is NOT proof of being unconfined, and the report's
// Windows status section says so.
func detect() model.Confinement {
	return conclude([]signal{windowsSandbox(), containerUser()})
}

// windowsSandbox recognises the Windows Sandbox VM, whose single account is
// always WDAGUtilityAccount.
func windowsSandbox() signal {
	if strings.EqualFold(os.Getenv("USERNAME"), "WDAGUtilityAccount") {
		return signal{present: true, kind: "windows-sandbox",
			detail: "running as WDAGUtilityAccount, the Windows Sandbox account"}
	}
	return signal{}
}

// containerUser recognises Windows containers, which run as ContainerUser or
// ContainerAdministrator.
func containerUser() signal {
	u := os.Getenv("USERNAME")
	if strings.EqualFold(u, "ContainerUser") || strings.EqualFold(u, "ContainerAdministrator") {
		return signal{present: true, kind: "container",
			detail: "running as " + u + ", a Windows container account"}
	}
	return signal{}
}
