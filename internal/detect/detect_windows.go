//go:build windows

package detect

import (
	"context"
	"os"
	"path/filepath"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
	"github.com/danielcuthbert/sandboxcheckr/internal/sysexec"
)

// collect gathers Windows host posture.
//
// Most of these come from one PowerShell invocation, because PowerShell is the
// only in-box tool that exposes BitLocker, Secure Boot, Defender and Device
// Guard state uniformly. The script only reads (Get-* cmdlets and CIM
// queries) and emits KEY=VALUE lines that the pure parsers below interpret, so
// the parsing is unit-tested without Windows.
func collect(ctx context.Context) []model.PostureFinding {
	kv := map[string]string{}
	if ps, err := sysexec.Lookup("powershell.exe"); err == nil {
		out, _ := sysexec.Run(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", postureScript)
		kv = parseKV(out)
	}
	return []model.PostureFinding{
		bitLockerFinding(kv["BITLOCKER"]),
		secureBootFinding(kv["SECUREBOOT"]),
		vbsFinding(kv["VBS"], kv["HVCI"]),
		defenderFinding(kv["DEFENDER_RTP"]),
		cfaFinding(kv["CFA"]),
		smartAppControlFinding(kv["SAC"]),
		uacFinding(kv["UAC"]),
		windowsSandboxFinding(kv["SANDBOX_FEATURE"]),
		wslFinding(),
	}
}

// postureScript prints KEY=VALUE lines. Every query is wrapped so that a
// missing cmdlet or an access-denied (BitLocker needs admin) yields an empty
// value, which the parsers report as INDETERMINATE rather than as a failure.
const postureScript = `
$ErrorActionPreference = 'SilentlyContinue'
function Out-KV($k, $v) { Write-Output ("{0}={1}" -f $k, $v) }
$bl = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
Out-KV BITLOCKER $bl
Out-KV SECUREBOOT (Confirm-SecureBootUEFI)
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
Out-KV VBS $dg.VirtualizationBasedSecurityStatus
Out-KV HVCI (($dg.SecurityServicesRunning) -contains 2)
$mp = Get-MpComputerStatus
Out-KV DEFENDER_RTP $mp.RealTimeProtectionEnabled
Out-KV CFA (Get-MpPreference).EnableControlledFolderAccess
Out-KV SAC (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
Out-KV UAC (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
Out-KV SANDBOX_FEATURE (Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).State
`

func wslFinding() model.PostureFinding {
	f := model.PostureFinding{ID: "wsl", Name: "WSL2 / Hyper-V isolation"}
	if _, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "wsl.exe")); err == nil {
		f.Status, f.Value = model.StatusPass, "wsl.exe present"
		f.Impact = "WSL2 runs a Linux VM. Running an agent inside WSL2 under bubblewrap gives a VM boundary " +
			"plus namespace confinement — but note that WSL mounts your Windows drives at /mnt/c by default, " +
			"which the sandbox must not expose."
		return f
	}
	f.Status, f.Value = model.StatusAbsent, "not installed"
	f.Impact = "WSL2 is not installed. It is the most practical way to get a strong sandbox for agents on Windows today."
	return f
}
