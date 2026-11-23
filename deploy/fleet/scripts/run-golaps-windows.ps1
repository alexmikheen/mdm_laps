# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet MDM trigger script for GoLAPS on Windows (runs as SYSTEM).
# Fleet substitutes FLEET_SECRET_* values on the server before execution.
$ErrorActionPreference = 'Stop'

$LapsBinary = 'C:\Program Files\GoLAPS\golaps.exe'

# Set non-secret defaults if machine environment variables are not present.
if (-not $env:LAPS_ADMIN_USER) { $env:LAPS_ADMIN_USER = 'example-admin' }
if (-not $env:LAPS_VAULT_TYPE) { $env:LAPS_VAULT_TYPE = 'onepassword' }
if (-not $env:LAPS_VAULT_ID)   { $env:LAPS_VAULT_ID   = 'your-vault-id' }

# Read the Fleet-substituted secret with a single-quoted here-string to prevent expansion.
$VaultToken = @'
$FLEET_SECRET_GOLAPS_VAULT_TOKEN
'@

# Split the literal marker so Fleet does not substitute inside the check.
if ([string]::IsNullOrWhiteSpace($VaultToken) -or $VaultToken -eq ('$' + 'FLEET_SECRET_GOLAPS_VAULT_TOKEN')) {
    Write-Error '[ERROR] FLEET_SECRET_GOLAPS_VAULT_TOKEN is empty or not configured.'
    exit 1
}

# Verify that the binary exists, is not a symbolic link, and is owned by SYSTEM or Administrators.
if (-not (Test-Path -LiteralPath $LapsBinary -PathType Leaf)) {
    Write-Error "[ERROR] GoLAPS binary not found at $LapsBinary."
    exit 1
}

$Item = Get-Item -LiteralPath $LapsBinary -Force
if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    Write-Error "[ERROR] Refusing to run symbolic link or reparse point: $LapsBinary."
    exit 1
}

$Acl = Get-Acl -LiteralPath $LapsBinary
$OwnerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($OwnerSid -notin @('S-1-5-18', 'S-1-5-32-544')) {
    Write-Error "[ERROR] Untrusted owner SID ($OwnerSid) on $LapsBinary."
    exit 1
}

Write-Output '[INFO] Starting GoLAPS rotation...'

# Pass the vault token over stdin only so it never appears in process arguments or environment variables.
$StartInfo = New-Object System.Diagnostics.ProcessStartInfo
$StartInfo.FileName = $LapsBinary
$StartInfo.Arguments = '--secrets-from-stdin'
$StartInfo.UseShellExecute = $false
$StartInfo.RedirectStandardInput = $true

$Process = [System.Diagnostics.Process]::Start($StartInfo)
try {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $Bytes = $Utf8NoBom.GetBytes("$($VaultToken.Trim())`n`n")
    $Process.StandardInput.BaseStream.Write($Bytes, 0, $Bytes.Length)
    $Process.StandardInput.BaseStream.Flush()
    $Process.StandardInput.Close()
    $Process.WaitForExit()
    $ExitCode = $Process.ExitCode
} finally {
    $VaultToken = $null
    $Process.Dispose()
}

if ($ExitCode -ne 0) {
    Write-Error "[ERROR] GoLAPS failed with exit code $ExitCode."
    exit $ExitCode
}

Write-Output '[SUCCESS] GoLAPS rotation completed.'
exit 0
