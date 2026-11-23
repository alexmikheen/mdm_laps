# Copyright 2026 Aleksandr Mikheenko
# SPDX-License-Identifier: MIT

# Fleet software install script for GoLAPS on Windows (runs as SYSTEM).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$InstallDir = 'C:\Program Files\GoLAPS'
$TargetPath = Join-Path $InstallDir 'golaps.exe'

if ([string]::IsNullOrWhiteSpace($env:INSTALLER_PATH) -or -not (Test-Path -LiteralPath $env:INSTALLER_PATH -PathType Leaf)) {
    Write-Error '[ERROR] INSTALLER_PATH is missing or does not point to a file.'
    exit 1
}

if (Test-Path -LiteralPath $InstallDir) {
    $DirItem = Get-Item -LiteralPath $InstallDir -Force
    if ($DirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-Error "[ERROR] Refusing to install into reparse point directory: $InstallDir."
        exit 1
    }
} else {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# Apply protected ACL on the directory before copying the binary.
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
Set-Acl -LiteralPath $InstallDir -AclObject $DirAcl

if (Test-Path -LiteralPath $TargetPath) {
    $TargetItem = Get-Item -LiteralPath $TargetPath -Force
    if ($TargetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-Error "[ERROR] Refusing to overwrite reparse point binary: $TargetPath."
        exit 1
    }
}

Copy-Item -LiteralPath $env:INSTALLER_PATH -Destination $TargetPath -Force

# Reset explicit ACL on the binary so an existing file never keeps weaker permissions.
$FileAcl = New-Object System.Security.AccessControl.FileSecurity
$FileAcl.SetAccessRuleProtection($true, $false)
$FileAcl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
$FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-18', 'FullControl', 'Allow')))
$FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544', 'FullControl', 'Allow')))
$FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-32-545', 'ReadAndExecute', 'Allow')))
Set-Acl -LiteralPath $TargetPath -AclObject $FileAcl

Write-Output "[SUCCESS] Installed GoLAPS to $TargetPath."
exit 0
