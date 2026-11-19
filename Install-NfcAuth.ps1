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

.PARAMETER AllowUnprotectedPython
    Install even when the chosen Python installation can be modified
    without administrator rights. Doing so hands SYSTEM to anyone who can
    write to it.

.PARAMETER PythonPath
    Use this interpreter instead of searching. Point it at a machine-wide
    installation that already has pywin32 and pyusb.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$AllowUnprotectedPython,
    [string]$PythonPath
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

function Get-PythonCandidates {
    <#
        Machine-wide installations come first. The LocalSystem service loads
        whichever interpreter is chosen, so a per-user one is only a fallback
        and the caller is warned about it afterwards.
    #>
    # An explicitly named interpreter is the whole list: falling back to
    # another one would quietly install the service against a different
    # environment than the administrator chose.
    if ($PythonPath) { return @(@{ Path = $PythonPath; Prefix = @() }) }

    $candidates = @()

    foreach ($view in @('', ('WOW6432Node' + [char]92))) {
        $root = 'HKLM:' + [char]92 + 'SOFTWARE' + [char]92 + $view + 'Python' + [char]92 + 'PythonCore'
        foreach ($version in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            $install = Get-ItemProperty -Path (Join-Path $version.PSPath 'InstallPath') -ErrorAction SilentlyContinue
            if (-not $install) { continue }
            $home_ = $install.'(default)'
            if (-not $home_) { continue }
            $exe = Join-Path $home_ 'python.exe'
            if (Test-Path -LiteralPath $exe) { $candidates += @{ Path = $exe; Prefix = @() } }
        }
    }
    foreach ($exe in (Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Python*') -Directory -ErrorAction SilentlyContinue)) {
        $full = Join-Path $exe.FullName 'python.exe'
        if (Test-Path -LiteralPath $full) { $candidates += @{ Path = $full; Prefix = @() } }
    }

    # Each prefix is carried explicitly: slicing a one-element array with
    # 1..($length - 1) yields the descending range 1,0 rather than nothing,
    # which throws under Set-StrictMode.
    foreach ($name in @(@{ Command = 'py'; Prefix = @('-3') }, @{ Command = 'python'; Prefix = @() })) {
        $command = Get-Command $name.Command -ErrorAction SilentlyContinue
        if ($command) { $candidates += @{ Path = $command.Source; Prefix = $name.Prefix } }
    }
    return @($candidates)
}

function Resolve-Python {
    foreach ($candidate in (Get-PythonCandidates)) {
        if (-not (Test-Path -LiteralPath $candidate.Path)) {
            if ($PythonPath) { throw "No interpreter at -PythonPath: $($candidate.Path)" }
            continue
        }
        # Every requirement in one probe, each with its own exit code, so a
        # candidate that cannot actually run the service is skipped rather
        # than installed and discovered broken later:
        #   3  32-bit, but the bundled libusb-1.0.dll is x64
        #   4  older than the Python 3.9 the service code needs
        #   other non-zero  pywin32 or pyusb is missing
        # The version test comes first and parses under Python 2, so an old
        # registered interpreter reports itself instead of a syntax error.
        $probe = @'
import sys
if sys.version_info < (3, 9): sys.exit(4)
if sys.maxsize <= 2**32: sys.exit(3)
import win32serviceutil
import usb.core
'@
        $arguments = @($candidate.Prefix) + @('-c', $probe)
        # The output is discarded rather than left on the pipeline, where it
        # would join this function's own output and turn the returned object
        # into an array that strict mode rejects on a property access.
        #
        # The probe is also allowed to fail outright: PATH often holds a
        # Microsoft Store execution alias for python.exe that cannot even be
        # started, and that is a terminating error here. Treat any failure as
        # "this interpreter is unusable" and keep looking.
        $usable = $false
        $exitCode = $null
        try {
            $null = & $candidate.Path @arguments 2>&1
            $exitCode = $LASTEXITCODE
            $usable = $exitCode -eq 0
        }
        catch {
            $usable = $false
        }
        if ($usable) {
            return [pscustomobject]@{
                Path = $candidate.Path
                Prefix = @($candidate.Prefix)
            }
        }
        if ($PythonPath) {
            $why = switch ($exitCode) {
                3 { 'is 32-bit, and the bundled libusb-1.0.dll is x64' }
                4 { 'is older than Python 3.9' }
                default { 'cannot import pywin32 and pyusb' }
            }
            throw "The interpreter at -PythonPath $($why): $($candidate.Path)"
        }
    }
    throw @'
No Python with pywin32 was found.

Install Python for all users, then add the dependencies to that
installation, for example:
  "C:\Program Files\Python313\python.exe" -m pip install pywin32 pyusb

Or pass -PythonPath to point at an interpreter that already has them.
'@
}

# Identities expected to hold write access to a machine-wide installation.
# Anyone else who has it can replace code the LocalSystem service loads.
$script:TrustedWriters = @(
    'S-1-5-18',      # LocalSystem
    'S-1-5-32-544',  # Administrators
    'S-1-5-32-549',  # Server Operators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',  # TrustedInstaller
    'S-1-3-0'        # CREATOR OWNER
)

function Get-UnprotectedWriters {
    <#
        Returns the identities that can modify $Path without being
        administrators. The service runs as LocalSystem, so everything it
        loads must be out of an ordinary user's reach.
    #>
    param([Parameter(Mandatory)][string]$Path)

    # Only individual bits, never composites: FullControl and Modify include
    # the read bits, so masking with them matches plain Read & Execute and
    # would flag a correctly locked-down Program Files.
    $rights = [System.Security.AccessControl.FileSystemRights]
    $dangerous = [int]($rights::WriteData -bor $rights::AppendData -bor
                       $rights::Delete -bor $rights::DeleteSubdirectoriesAndFiles -bor
                       $rights::ChangePermissions -bor $rights::TakeOwnership)
    # GENERIC_ALL and GENERIC_WRITE, which appear in ACEs unmapped.
    $dangerous = $dangerous -bor 0x10000000 -bor 0x40000000

    $writers = @()
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ((([int]$rule.FileSystemRights) -band $dangerous) -eq 0) { continue }
        $sid = try {
            $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            $null
        }
        if ($sid -and $script:TrustedWriters -contains $sid) { continue }
        $writers += $rule.IdentityReference.Value
    }
    return @($writers | Sort-Object -Unique)
}

Write-Step 'Checking prerequisites'
$python = Resolve-Python
Write-Note "Python: $($python.Path) $($python.Prefix -join ' ')"

# Moving our own scripts into Program Files is not enough by itself: the
# service also loads this interpreter and pywin32 from wherever they live.
$pythonHome = & $python.Path @($python.Prefix + @('-c', 'import sys; print(sys.prefix)'))
if ($LASTEXITCODE -ne 0 -or -not $pythonHome) {
    throw 'Could not determine the Python installation directory.'
}
$pythonHome = "$pythonHome".Trim()
# Wrapped in @(): an empty return would otherwise be $null, and reading
# .Count on that is a terminating error under strict mode.
$unprotected = @(Get-UnprotectedWriters -Path $pythonHome)
if ($unprotected.Count -gt 0) {
    $who = $unprotected -join ', '
    if (-not $AllowUnprotectedPython) {
        throw @"
The Python installation at
  $pythonHome
can be modified by: $who

NfcAuthService runs as LocalSystem and loads this interpreter, so anyone able
to write there could run code as SYSTEM. Install Python for all users, under
Program Files, and run this script again - or pass -AllowUnprotectedPython to
accept that risk deliberately.
"@
    }
    Write-Host ''
    Write-Host "WARNING: $pythonHome can be modified by: $who" -ForegroundColor Yellow
    Write-Host '         Anyone who can write there can run code as SYSTEM.' -ForegroundColor Yellow
    Write-Host ''
}
else {
    Write-Note "Python is administrator-protected: $pythonHome"
}

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
