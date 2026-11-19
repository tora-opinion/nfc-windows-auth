<#
.SYNOPSIS
    Installs the NFC sign-in service and its Windows Credential Provider.

.DESCRIPTION
    Builds and registers the Credential Provider DLL, installs the LocalSystem
    service that watches the RC-S300 reader, and retires the older file-signal
    based setup if it is still present.

    Sign-in with a PIN or password is left untouched, so a problem here never
    locks anyone out of the machine.

.PARAMETER SkipBuild
    Register the DLL already present in credential_provider\build instead of
    rebuilding it.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$dllSource = Join-Path $repoRoot 'credential_provider\build\NfcCredentialProvider.dll'
$dllTarget = Join-Path $env:SystemRoot 'System32\NfcCredentialProvider.dll'
$serviceScript = Join-Path $repoRoot 'src\nfc_auth_service.py'
$serviceName = 'NfcAuthService'

# The first provider in this project; it read a signal file any user could
# create, so its registration is removed rather than carried forward.
$legacyClsid = '{A0B1C2D3-E4F5-6789-ABCD-EF0123456789}'
$legacyTasks = @('NFC Auth On Lock', 'NFC_Login_Unlock')

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
    throw 'No Python with pywin32 was found. Install it with: py -3 -m pip install pywin32'
}

Write-Step 'Checking prerequisites'
$python = Resolve-Python
Write-Note "Python: $($python.Path) $($python.Prefix -join ' ')"

if (-not $SkipBuild) {
    Write-Step 'Building the Credential Provider'
    & (Join-Path $repoRoot 'credential_provider\build.ps1')
}
if (-not (Test-Path -LiteralPath $dllSource)) {
    throw "The Credential Provider DLL was not found: $dllSource"
}

Write-Step 'Stopping anything already running'
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    Write-Note "Stopped $serviceName"
}
if (Test-Path -LiteralPath $dllTarget) {
    & regsvr32.exe /s /u $dllTarget
    Write-Note 'Unregistered the previously installed DLL'
}

Write-Step 'Installing the Credential Provider'
try {
    Copy-Item -LiteralPath $dllSource -Destination $dllTarget -Force
}
catch {
    throw ("The DLL is in use and could not be replaced. Sign out or reboot, " +
           "then run this script again. ($($_.Exception.Message))")
}
& regsvr32.exe /s $dllTarget
if ($LASTEXITCODE -ne 0) { throw "regsvr32 failed with exit code $LASTEXITCODE." }
Write-Note "Registered $dllTarget"

Write-Step 'Installing the reader service'
$serviceArguments = $python.Prefix + @($serviceScript, '--startup', 'auto', 'install')
& $python.Path @serviceArguments
if ($LASTEXITCODE -ne 0) {
    $serviceArguments = $python.Prefix + @($serviceScript, '--startup', 'auto', 'update')
    & $python.Path @serviceArguments
    if ($LASTEXITCODE -ne 0) { throw "Installing $serviceName failed with exit code $LASTEXITCODE." }
}
Start-Service -Name $serviceName
Write-Note "$serviceName is $((Get-Service -Name $serviceName).Status)"

Write-Step 'Retiring the previous setup'
$legacyCpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$legacyClsid"
foreach ($key in @($legacyCpKey, "Registry::HKEY_CLASSES_ROOT\CLSID\$legacyClsid")) {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse -Force
        Write-Note "Removed $key"
    }
}
foreach ($task in $legacyTasks) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        Write-Note "Removed scheduled task: $task"
    }
}

$passwordless = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -Name 'DevicePasswordLessBuildVersion' -ErrorAction SilentlyContinue
if ($passwordless -and $passwordless.DevicePasswordLessBuildVersion -ne 0) {
    Write-Host ''
    Write-Host 'WARNING: "Windows Hello sign-in only" is enabled on this PC.' -ForegroundColor Yellow
    Write-Host '         It hides password-based providers, including this one.' -ForegroundColor Yellow
    Write-Host '         Turn it off under Settings > Accounts > Sign-in options.' -ForegroundColor Yellow
}

Write-Host ''
Write-Step 'Done. Next steps:'
Write-Host ''
Write-Host '  1. Register your iPhone against your Windows account:'
Write-Host "       $($python.Path) $($python.Prefix -join ' ') tools\nfc_cards.py register --name iPhone --windows-user ""$env:USERDOMAIN\$env:USERNAME"""
Write-Host '     For a Microsoft account use MicrosoftAccount\your@email as the user.'
Write-Host ''
Write-Host '  2. Optional, for hands-free sign-in, store the password:'
Write-Host "       $($python.Path) $($python.Prefix -join ' ') tools\nfc_cards.py set-credential --windows-user ""MicrosoftAccount\your@email"""
Write-Host '     Without this the tap is a first factor and you still type the password.'
Write-Host ''
Write-Host '  3. Lock with Win+L and hold the iPhone to the reader.'
Write-Host ''
