# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet MDM trigger script for GoLAPS on Windows (runs as SYSTEM).
# Fleet substitutes FLEET_SECRET_* values on the server before execution.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$LapsBinary = 'C:\Program Files\GoLAPS\golaps.exe'
$StateDir   = 'C:\ProgramData\GoLAPS'
$MarkerPath = Join-Path $StateDir 'last_rotation.txt'

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

# Verify that the binary and its parent directories are not reparse points, are owned by a privileged SID,
# and do not grant write/modify permissions to non-admin principals.
$TrustedSids = @(
    'S-1-5-18',                                                           # LocalSystem
    'S-1-5-32-544',                                                       # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'      # NT SERVICE\TrustedInstaller
)
$WriteRights = [System.Security.AccessControl.FileSystemRights](
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)

function Assert-TrustedPath([string]$Path, [bool]$ExpectFile) {
    if ($ExpectFile) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Write-Error "[ERROR] GoLAPS binary not found at $Path."
            exit 1
        }
    } elseif (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Write-Error "[ERROR] Parent directory not found at $Path."
        exit 1
    }

    $Item = Get-Item -LiteralPath $Path -Force
    if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-Error "[ERROR] Refusing to trust symbolic link or reparse point: $Path."
        exit 1
    }

    $Acl = Get-Acl -LiteralPath $Path
    $OwnerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($OwnerSid -notin $TrustedSids) {
        Write-Error "[ERROR] Untrusted owner SID ($OwnerSid) on $Path."
        exit 1
    }

    foreach ($Rule in $Acl.Access) {
        if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        if ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }
        if (($Rule.FileSystemRights -band $WriteRights) -eq 0) {
            continue
        }
        if ($Rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            $Sid = $Rule.IdentityReference.Value
        } else {
            try {
                $Sid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                Write-Error "[ERROR] Could not resolve principal ($($Rule.IdentityReference)) with write access on $Path."
                exit 1
            }
        }
        if ($Sid -notin $TrustedSids) {
            Write-Error "[ERROR] Untrusted principal ($Sid) has write access on $Path."
            exit 1
        }
    }
}

Assert-TrustedPath -Path $LapsBinary -ExpectFile $true
$Parent = Split-Path -Parent $LapsBinary
$Root   = [System.IO.Path]::GetPathRoot($LapsBinary).TrimEnd('\')
while ($Parent -and $Parent.TrimEnd('\') -ne $Root) {
    Assert-TrustedPath -Path $Parent -ExpectFile $false
    $Parent = Split-Path -Parent $Parent
}

# Remove any stray secret environment variables before starting the child process.
foreach ($Name in @(
    'LAPS_VAULT_TOKEN', 'OP_SERVICE_ACCOUNT_TOKEN', 'VAULT_TOKEN',
    'VAULT_SKIP_VERIFY', 'BWS_ACCESS_TOKEN', 'BW_API_KEY', 'AZURE_CLIENT_SECRET',
    'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'LEGACY_ADMIN_PASS'
)) {
    Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
}

Write-Output '[INFO] Starting GoLAPS rotation...'

# Pass the vault token over stdin only as BOM-free UTF-8 so it never appears in argv or env.
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
    $Bytes = $null
    $Process.Dispose()
}

if ($ExitCode -eq 75) {
    Write-Output '[INFO] GoLAPS skipped rotation (exit 75); leaving last_rotation.txt unchanged.'
    exit 0
}

if ($ExitCode -ne 0) {
    Write-Error "[ERROR] GoLAPS failed with exit code $ExitCode."
    exit $ExitCode
}

# Record rotation timestamp for Fleet osquery compliance policies with hardened ACLs.
if (Test-Path -LiteralPath $StateDir) {
    $StateItem = Get-Item -LiteralPath $StateDir -Force
    if ($StateItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-Error "[ERROR] Refusing to use reparse point state directory: $StateDir."
        exit 1
    }
} else {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
}

$DirAcl = New-Object System.Security.AccessControl.DirectorySecurity
$DirAcl.SetAccessRuleProtection($true, $false)
$DirAcl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
$DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-18',
    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
$DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544',
    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
$DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-545',
    'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $StateDir -AclObject $DirAcl

if (Test-Path -LiteralPath $MarkerPath) {
    $MarkerItem = Get-Item -LiteralPath $MarkerPath -Force
    if ($MarkerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-Error "[ERROR] Refusing to write to reparse point marker file: $MarkerPath."
        exit 1
    }
}

Set-Content -LiteralPath $MarkerPath -Value ([DateTimeOffset]::UtcNow.ToString('o')) -Encoding ASCII

$FileAcl = New-Object System.Security.AccessControl.FileSecurity
$FileAcl.SetAccessRuleProtection($true, $false)
$FileAcl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
$FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-18', 'FullControl', 'Allow')))
$FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544', 'FullControl', 'Allow')))
$FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-545', 'ReadAndExecute', 'Allow')))
Set-Acl -LiteralPath $MarkerPath -AclObject $FileAcl

Write-Output '[SUCCESS] GoLAPS rotation completed.'
exit 0
