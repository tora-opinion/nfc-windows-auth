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
# The service runs as LocalSystem, so its code must live somewhere an
# unprivileged user cannot rewrite. A working copy under the user's profile
# would otherwise hand out SYSTEM to anyone who can edit it.
$installRoot = Join-Path $env:ProgramFiles 'NfcAuth'
$serviceScript = Join-Path $installRoot 'src\nfc_auth_service.py'
$serviceName = 'NfcAuthService'

# The first provider in this project; it read a signal file any user could
# create, so its registration is removed rather than carried forward.
$legacyClsid = '{A0B1C2D3-E4F5-6789-ABCD-EF0123456789}'
$legacyTasks = @('NFC Auth On Lock', 'NFC_Login_Unlock')

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

Write-Step 'Copying the service to a protected location'
foreach ($subdirectory in @('src', 'tools')) {
    $destination = Join-Path $installRoot $subdirectory
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
}

# Protect the tree explicitly rather than trusting whatever Program Files
# happens to be configured with: full control for SYSTEM and Administrators,
# read and execute for everyone else.
$acl = Get-Acl -LiteralPath $installRoot
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRule($rule) }
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagation = [System.Security.AccessControl.PropagationFlags]::None
foreach ($grant in @(
    @('S-1-5-18', 'FullControl'),
    @('S-1-5-32-544', 'FullControl'),
    @('S-1-5-32-545', 'ReadAndExecute')
)) {
    $identity = New-Object System.Security.Principal.SecurityIdentifier($grant[0])
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, $grant[1], $inherit, $propagation, 'Allow')))
}
Set-Acl -LiteralPath $installRoot -AclObject $acl

Copy-Item -Path (Join-Path $repoRoot 'src\*.py') -Destination (Join-Path $installRoot 'src') -Force
$libusb = Join-Path $repoRoot 'src\libusb-1.0.dll'
if (Test-Path -LiteralPath $libusb) {
    Copy-Item -LiteralPath $libusb -Destination (Join-Path $installRoot 'src') -Force
}
Copy-Item -Path (Join-Path $repoRoot 'tools\*.py') -Destination (Join-Path $installRoot 'tools') -Force
Write-Note "Installed to $installRoot"

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
Write-Host "       $($python.Path) $($python.Prefix -join ' ') ""$installRoot\tools\nfc_cards.py"" register --name iPhone --windows-user ""$env:USERDOMAIN\$env:USERNAME"""
Write-Host '     For a Microsoft account use MicrosoftAccount\your@email as the user.'
Write-Host ''
Write-Host '  2. Optional, for hands-free sign-in, store the password:'
Write-Host "       $($python.Path) $($python.Prefix -join ' ') ""$installRoot\tools\nfc_cards.py"" set-credential --windows-user ""MicrosoftAccount\your@email"""
Write-Host '     Without this the tap is a first factor and you still type the password.'
Write-Host ''
Write-Host '  3. Lock with Win+L and hold the iPhone to the reader.'
Write-Host ''
