//go:build windows

package osmgmt

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

type WindowsManager struct{}

func NewManager() Manager {
	return &WindowsManager{}
}

// ensureAccountScript creates or rotates the LAPS service account and re-asserts its administrator rights. It runs as one idempotent unit so the account cannot be left half configured between separate commands. Secrets arrive through the environment (LAPS_TARGET_USER / LAPS_NEW_PASS), never as arguments. The old implementation ran `net user <user> <password>`, which puts the password on a command line — the single most widely collected artefact on a Windows endpoint (Sysmon EventID 1 logs CommandLine by default; process environment blocks are not collected). `Set-LocalUser` takes a SecureString, so there is no argv exposure at all. The Administrators group is addressed by its well-known SID S-1-5-32-544: the display name is localised, so the previous `net localgroup Administrators ...` silently did nothing on a non-English Windows — and once its error stopped being discarded it would have failed the run outright on those devices.
const ensureAccountScript = `
$ErrorActionPreference = 'Stop'

$target = $env:LAPS_TARGET_USER
$plain  = $env:LAPS_NEW_PASS
if ([string]::IsNullOrWhiteSpace($target)) { throw 'LAPS_TARGET_USER is empty' }
if ([string]::IsNullOrWhiteSpace($plain))  { throw 'LAPS_NEW_PASS is empty' }
$secure = ConvertTo-SecureString $plain -AsPlainText -Force

$existing = Get-LocalUser -Name $target -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    New-LocalUser -Name $target -Password $secure -FullName 'IT Admin' -Description 'GoLAPS managed local administrator' -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword | Out-Null
    Write-Output 'ACCOUNT_CREATED'
} else {
    Set-LocalUser -Name $target -Password $secure -PasswordNeverExpires $true -UserMayChangePassword $false
    Write-Output 'PASSWORD_ROTATED'
}

$account = Get-LocalUser -Name $target -ErrorAction SilentlyContinue
if ($null -eq $account) { throw "account $target does not exist after the rotation" }
if (-not $account.Enabled) {
    Enable-LocalUser -Name $target
    Write-Output 'ACCOUNT_ENABLED'
}

# Admin By Request revokes standing administrator rights on managed Windows devices and can
# demote this account between runs. Membership used to be granted only at creation time, so a
# demotion was permanent and invisible: the password kept rotating into 1Password while the
# account it belonged to was no longer an administrator and useless for recovery.
$isMember = $false
try {
    foreach ($m in Get-LocalGroupMember -SID 'S-1-5-32-544') {
        if ((($m.Name -split '\\')[-1]) -ieq $target) { $isMember = $true; break }
    }
} catch {
    # Get-LocalGroupMember throws when the group holds an unresolvable SID. Re-adding an
    # existing member is harmless, so an unreadable membership list is not a reason to stop.
    Write-Output "ADMIN_CHECK_FAILED: $($_.Exception.Message)"
}

if ($isMember) {
    Write-Output 'ALREADY_ADMIN'
} else {
    try {
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $target
        Write-Output 'ADMIN_GRANTED'
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        Write-Output 'ALREADY_ADMIN'
    }
}

Write-Output 'OK'
`

// serialScript reads the machine serial without wmic, which is deprecated and absent from Windows 11 24H2. Win32_ComputerSystemProduct is the fallback when the BIOS record is blank (common on some VMs).
const serialScript = `
$ErrorActionPreference = 'SilentlyContinue'
$serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
if ([string]::IsNullOrWhiteSpace($serial)) {
    $serial = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).IdentifyingNumber
}
Write-Output $serial
`

// psEncode renders a script for powershell.exe -EncodedCommand (base64 of UTF-16LE). Passing multi-line scripts this way removes every layer of quoting between Go, CreateProcess and the PowerShell parser.
func psEncode(script string) string {
	var buf bytes.Buffer
	for _, unit := range utf16.Encode([]rune(script)) {
		buf.WriteByte(byte(unit))
		buf.WriteByte(byte(unit >> 8))
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// runPowerShell executes a script and returns its combined output. extraEnv carries secrets that must not appear in the command line.
func runPowerShell(ctx context.Context, script string, extraEnv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", psEncode(script))
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}

	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("powershell failed: %w | output: %s", err, text)
	}
	return text, nil
}

func (w *WindowsManager) GetSystemInfo(ctx context.Context) (string, string) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UnknownHost"
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	serial := "Unknown"
	out, err := runPowerShell(ctx, serialScript)
	if err != nil {
		log.Printf("[WARNING] Could not read the machine serial: %v\n", err)
	} else if trimmed := strings.TrimSpace(out); trimmed != "" {
		serial = trimmed
	}

	return hostname, serial
}

func (w *WindowsManager) EnsureUserAndChangePassword(ctx context.Context, user, oldPass, altOldPass, newPass string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Every step is checked and the account is verified inside the script. The previous version discarded the result of all five commands it ran and always returned nil, so a rejected password still ended up escrowed in 1Password while the machine kept the old one.
	out, err := runPowerShell(ctx, ensureAccountScript,
		"LAPS_TARGET_USER="+user,
		"LAPS_NEW_PASS="+newPass,
	)
	if err != nil {
		return fmt.Errorf("failed to provision %s: %w", user, err)
	}
	if !strings.Contains(out, "OK") {
		return fmt.Errorf("provisioning %s did not complete: %s", user, out)
	}

	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" && line != "OK" {
			log.Printf("[INFO] %s: %s\n", user, line)
		}
	}

	return nil
}

func (w *WindowsManager) ManageSecureToken(ctx context.Context, targetUser, newPass string, availableCreds map[string]string) string {
	return "N/A (Windows)"
}

func (w *WindowsManager) DeleteServiceAccountToken(ctx context.Context) error {
	return nil
}
