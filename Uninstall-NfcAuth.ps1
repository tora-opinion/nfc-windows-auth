<#
.SYNOPSIS
    Removes the NFC sign-in service and its Windows Credential Provider.

.DESCRIPTION
    Unregisters and deletes the Credential Provider DLL and removes the reader
    service. Registered cards and the stored credential are left in place
    unless -Purge is given, so the setup can be reinstalled without
    re-enrolling.

    If the lock screen ever becomes unusable, boot into Safe Mode and run this
    script there; PIN and password sign-in are never disabled by the installer.

.PARAMETER Purge
    Also delete C:\ProgramData\NfcAuth, which holds the registered cards, the
    HMAC key and any stored credential.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Purge
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dllTarget = Join-Path $env:SystemRoot 'System32\NfcCredentialProvider.dll'
$installRoot = Join-Path $env:ProgramFiles 'NfcAuth'
$serviceScript = Join-Path $installRoot 'src\nfc_auth_service.py'
$serviceName = 'NfcAuthService'
$dataDir = Join-Path $env:ProgramData 'NfcAuth'

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Note { param([string]$Message) Write-Host "    $Message" -ForegroundColor DarkGray }

function Resolve-Python {
    foreach ($candidate in @(@('py', '-3'), @('python'))) {
        $command = Get-Command $candidate[0] -ErrorAction SilentlyContinue
        if (-not $command) { continue }
        $arguments = @($candidate[1..($candidate.Length - 1)]) + @('-c', 'import win32serviceutil')
        & $command.Source @arguments 2>$null
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                Path = $command.Source
                Prefix = @($candidate[1..($candidate.Length - 1)])
            }
        }
    }
    return $null
}

Write-Step 'Removing the reader service'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    $python = Resolve-Python
    if ($python) {
        & $python.Path @($python.Prefix + @($serviceScript, 'remove'))
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        # Fall back to the service controller when Python is gone or failed.
        & sc.exe delete $serviceName | Out-Null
    }
    Write-Note "Removed $serviceName"
}
else {
    Write-Note 'The service was not installed'
}

Write-Step 'Removing the Credential Provider'
if (Test-Path -LiteralPath $dllTarget) {
    & regsvr32.exe /s /u $dllTarget
    try {
        Remove-Item -LiteralPath $dllTarget -Force
        Write-Note "Deleted $dllTarget"
    }
    catch {
        Write-Note 'The DLL is still loaded; it will be deleted after a reboot.'
        $pending = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $existing = (Get-ItemProperty -Path $pending -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
        $entry = @("\??\$dllTarget", '')
        $values = if ($existing) { @($existing) + $entry } else { $entry }
        Set-ItemProperty -Path $pending -Name 'PendingFileRenameOperations' -Value $values -Type MultiString
    }
}
else {
    Write-Note 'The DLL was not installed'
}

Write-Step 'Removing the installed service files'
if (Test-Path -LiteralPath $installRoot) {
    Remove-Item -LiteralPath $installRoot -Recurse -Force
    Write-Note "Deleted $installRoot"
}
else {
    Write-Note 'Nothing was installed there'
}

if ($Purge) {
    Write-Step 'Deleting registered cards and stored credentials'
    if (Test-Path -LiteralPath $dataDir) {
        Remove-Item -LiteralPath $dataDir -Recurse -Force
        Write-Note "Deleted $dataDir"
    }
}
else {
    Write-Step 'Keeping registered cards'
    Write-Note "$dataDir was left in place. Re-run with -Purge to delete it."
}

Write-Host ''
Write-Host 'Done. Sign in with your PIN or password as usual.' -ForegroundColor Green
