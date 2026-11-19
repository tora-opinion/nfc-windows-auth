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
    # Each prefix is carried explicitly: slicing a one-element array with
    # 1..($length - 1) yields the descending range 1,0 rather than nothing,
    # which throws under Set-StrictMode and would abort on a machine that has
    # python.exe but no py launcher.
    foreach ($candidate in @(
        @{ Command = 'py'; Prefix = @('-3') },
        @{ Command = 'python'; Prefix = @() }
    )) {
        $command = Get-Command $candidate.Command -ErrorAction SilentlyContinue
        if (-not $command) { continue }
        $arguments = @($candidate.Prefix) + @('-c', 'import win32serviceutil')
        # The output is discarded rather than left on the pipeline, where it
        # would join this function's own output and turn the returned object
        # into an array that strict mode rejects on a property access.
        #
        # The probe is also allowed to fail outright: PATH often holds a
        # Microsoft Store execution alias for python.exe that cannot even be
        # started, and that is a terminating error here. Treat any failure as
        # "this interpreter is unusable" and keep looking.
        $usable = $false
        try {
            $null = & $command.Source @arguments 2>&1
            $usable = $LASTEXITCODE -eq 0
        }
        catch {
            $usable = $false
        }
        if ($usable) {
            return [pscustomobject]@{
                Path = $command.Source
                Prefix = @($candidate.Prefix)
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
        # Silencing the lookup does not silence a property read on the $null it
        # returns, which strict mode turns into a terminating error and would
        # skip both the scheduled deletion and the cleanup below.
        $current = Get-ItemProperty -Path $pending -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        $existing = if ($current) { @($current.PendingFileRenameOperations) } else { @() }
        $values = $existing + @("\??\$dllTarget", '')
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
