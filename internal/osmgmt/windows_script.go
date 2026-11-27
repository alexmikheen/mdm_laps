// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package osmgmt

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const resultMarker = "LAPS_RESULT=OK"

const ensureAccountScript = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$target = $env:LAPS_TARGET_USER
$plain  = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($target)) { throw 'LAPS_TARGET_USER is empty' }
if ([string]::IsNullOrWhiteSpace($plain))  { throw 'no password arrived on stdin' }
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
$plain = $null

$existing = Get-LocalUser -Name $target -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    New-LocalUser -Name $target -Password $secure -FullName 'IT Admin' -Description 'GoLAPS managed local administrator' -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword | Out-Null
    Write-Output 'ACCOUNT_CREATED'
} else {
    Set-LocalUser -Name $target -Password $secure -PasswordNeverExpires $true -AccountNeverExpires -UserMayChangePassword $false
    Write-Output 'PASSWORD_ROTATED'
}

$account = Get-LocalUser -Name $target -ErrorAction SilentlyContinue
if ($null -eq $account) { throw "account $target does not exist after the rotation" }
if (-not $account.Enabled) {
    Enable-LocalUser -Name $target
    Write-Output 'ACCOUNT_ENABLED'
}

$isMember = $false
try {
    foreach ($m in Get-LocalGroupMember -SID 'S-1-5-32-544') {
        if ($m.SID.Value -eq $account.SID.Value) { $isMember = $true; break }
    }
} catch {
    Write-Output "ADMIN_CHECK_FAILED: $($_.Exception.Message)"
}

if ($isMember) {
    Write-Output 'ALREADY_ADMIN'
} else {
    try {
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $account
        Write-Output 'ADMIN_GRANTED'
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        Write-Output 'ALREADY_ADMIN'
    }
}

Write-Output 'LAPS_RESULT=OK'
`

// serialScript prints tagged lines because Windows PowerShell 5.1 can mix progress XML into stdout.
const serialScript = `
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
Write-Output ('BIOS=' + (Get-CimInstance -ClassName Win32_BIOS).SerialNumber)
$csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct
Write-Output ('CSP=' + $csp.IdentifyingNumber)
Write-Output ('UUID=' + $csp.UUID)
`

func powerShellPath(systemRoot string) string {
	return strings.TrimRight(systemRoot, `\`) + `\System32\WindowsPowerShell\v1.0\powershell.exe`
}

func powerShellEnv(systemRoot, temp string, extra ...string) []string {
	root := strings.TrimRight(systemRoot, `\`)
	if temp == "" {
		temp = root + `\Temp`
	}
	env := []string{
		"SystemRoot=" + root,
		"windir=" + root,
		"PATH=" + root + `\System32;` + root + `\System32\WindowsPowerShell\v1.0`,
		"TEMP=" + temp,
		"TMP=" + temp,
	}
	return append(env, extra...)
}

func scriptReportsSuccess(out string) bool {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		return line == resultMarker
	}
	return false
}

var windowsSerialPlaceholders = []string{
	"Unknown",
	"To be filled by O.E.M.",
	"Default string",
	"0",
	"System Serial Number",
	"Chassis Serial Number",
	"Board Serial Number",
	"Not Specified",
	"None",
	"N/A",
}

func validateWindowsSerial(raw string) (string, error) {
	serial := strings.TrimSpace(raw)
	if serial == "" {
		return "", errors.New("the firmware reported no serial")
	}
	for _, r := range serial {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("the firmware serial contains control characters: %q", serial)
		}
	}
	if strings.Trim(serial, "0-") == "" || strings.Trim(strings.ToUpper(serial), "F-") == "" {
		return "", fmt.Errorf("the firmware reported an all-zero or all-F placeholder serial %q", serial)
	}
	for _, placeholder := range windowsSerialPlaceholders {
		if strings.EqualFold(serial, placeholder) {
			return "", fmt.Errorf("the firmware reported the placeholder serial %q", serial)
		}
	}
	return serial, nil
}

func pickWindowsSerial(raw string) (string, error) {
	var firstErr error
	tagged := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		value, ok := strings.CutPrefix(line, "BIOS=")
		if !ok {
			value, ok = strings.CutPrefix(line, "CSP=")
		}
		if !ok {
			value, ok = strings.CutPrefix(line, "UUID=")
		}
		if !ok {
			continue
		}
		tagged = true
		serial, err := validateWindowsSerial(value)
		if err == nil {
			return serial, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if !tagged {
		return "", errors.New("the serial script printed no tagged BIOS, CSP, or UUID line")
	}
	return "", firstErr
}
