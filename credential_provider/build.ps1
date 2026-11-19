param(
    [string]$BuildRelativePath = 'build'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found: $vswhere"
}

$vsPath = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1).Trim()
if (-not $vsPath) {
    throw 'Visual Studio 2022 C++ x64 tools were not found by vswhere.'
}

$devCmd = Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $devCmd)) {
    throw "VsDevCmd.bat was not found: $devCmd"
}

$environmentOutput = & $env:ComSpec /d /s /c "call `"$devCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
if ($LASTEXITCODE -ne 0) {
    throw "VsDevCmd.bat failed with exit code $LASTEXITCODE."
}
foreach ($line in $environmentOutput) {
    $separator = $line.IndexOf('=')
    if ($separator -gt 0) {
        $name = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

$cmakeCommand = Get-Command cmake -ErrorAction SilentlyContinue
$cmake = if ($cmakeCommand) { $cmakeCommand.Source } else { $null }
if (-not $cmake) {
    $cmakeCandidate = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    if (Test-Path -LiteralPath $cmakeCandidate) {
        $cmake = $cmakeCandidate
    }
}
$buildRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'build'))
if ([IO.Path]::IsPathRooted($BuildRelativePath)) {
    throw 'BuildRelativePath must stay under credential_provider\build.'
}
$buildDir = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $BuildRelativePath))
if (-not $buildDir.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar,
                               [StringComparison]::OrdinalIgnoreCase) -and
    -not $buildDir.Equals($buildRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BuildRelativePath must stay under credential_provider\build.'
}
if ($cmake) {
    & $cmake -S $PSScriptRoot -B $buildDir -G 'Visual Studio 17 2022' -A x64
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with exit code $LASTEXITCODE." }

    & $cmake --build $buildDir --config Release --parallel
    if ($LASTEXITCODE -ne 0) { throw "Release x64 build failed with exit code $LASTEXITCODE." }

    $ctest = Join-Path (Split-Path -Parent $cmake) 'ctest.exe'
    if (-not (Test-Path -LiteralPath $ctest)) { throw "ctest.exe was not found next to CMake: $ctest" }
    & $ctest --test-dir $buildDir -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "CTest failed with exit code $LASTEXITCODE." }
}
else {
    # VS C++ workloads do not always include CMake. Use the same Release x64
    # source and library lists when CMake is unavailable.
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    $objRoot = Join-Path $buildDir 'obj'
    $dllObj = Join-Path $objRoot 'dll'
    $kerbObj = Join-Path $objRoot 'kerb-test'
    $pipeObj = Join-Path $objRoot 'pipe-test'
    $flowObj = Join-Path $objRoot 'flow-test'
    New-Item -ItemType Directory -Path $dllObj,$kerbObj,$pipeObj,$flowObj -Force | Out-Null

    $common = @('/nologo','/std:c++17','/EHsc','/W4','/WX','/guard:cf','/permissive-','/utf-8',
                '/DUNICODE','/D_UNICODE','/DWIN32_LEAN_AND_MEAN','/DNOMINMAX')
    $dll = Join-Path $buildDir 'NfcCredentialProvider.dll'
    & cl.exe @common '/LD' "/Fo$dllObj\" "/Fd$buildDir\NfcCredentialProvider.pdb" `
        "/Fe$dll" `
        (Join-Path $PSScriptRoot 'src\Credential.cpp') `
        (Join-Path $PSScriptRoot 'src\Dll.cpp') `
        (Join-Path $PSScriptRoot 'src\KerbPack.cpp') `
        (Join-Path $PSScriptRoot 'src\PipeClient.cpp') `
        (Join-Path $PSScriptRoot 'src\Provider.cpp') `
        (Join-Path $PSScriptRoot 'src\SubmitFlow.cpp') `
        /link "/DEF:$(Join-Path $PSScriptRoot 'src\NfcAuthCredentialProvider.def')" `
        '/GUARD:CF' '/DYNAMICBASE' '/NXCOMPAT' '/HIGHENTROPYVA' `
        "/IMPLIB:$(Join-Path $buildDir 'NfcCredentialProvider.lib')" `
        secur32.lib advapi32.lib ole32.lib shlwapi.lib credui.lib uuid.lib
    if ($LASTEXITCODE -ne 0) { throw "Release x64 DLL build failed with exit code $LASTEXITCODE." }

    $kerbTest = Join-Path $buildDir 'test_kerb_pack.exe'
    & cl.exe @common "/Fo$kerbObj\" "/Fe$kerbTest" `
        (Join-Path $PSScriptRoot 'tests\test_kerb_pack.cpp') `
        (Join-Path $PSScriptRoot 'src\KerbPack.cpp') ole32.lib
    if ($LASTEXITCODE -ne 0) { throw "KerbPack test build failed with exit code $LASTEXITCODE." }
    & $kerbTest
    if ($LASTEXITCODE -ne 0) { throw "KerbPack tests failed with exit code $LASTEXITCODE." }

    $pipeTest = Join-Path $buildDir 'test_pipe_client_parse.exe'
    & cl.exe @common "/Fo$pipeObj\" "/Fe$pipeTest" `
        (Join-Path $PSScriptRoot 'tests\test_pipe_client_parse.cpp') `
        (Join-Path $PSScriptRoot 'src\PipeClient.cpp') /DNFC_AUTH_TESTING advapi32.lib
    if ($LASTEXITCODE -ne 0) { throw "PipeClient test build failed with exit code $LASTEXITCODE." }
    & $pipeTest
    if ($LASTEXITCODE -ne 0) { throw "PipeClient parser tests failed with exit code $LASTEXITCODE." }

    $flowTest = Join-Path $buildDir 'test_submit_flow.exe'
    & cl.exe @common "/Fo$flowObj\" "/Fe$flowTest" `
        (Join-Path $PSScriptRoot 'tests\test_submit_flow.cpp') `
        (Join-Path $PSScriptRoot 'src\SubmitFlow.cpp') `
        (Join-Path $PSScriptRoot 'src\KerbPack.cpp') ole32.lib
    if ($LASTEXITCODE -ne 0) { throw "SubmitFlow test build failed with exit code $LASTEXITCODE." }
    & $flowTest
    if ($LASTEXITCODE -ne 0) { throw "SubmitFlow tests failed with exit code $LASTEXITCODE." }
}

$dll = Join-Path $buildDir 'NfcCredentialProvider.dll'
if (-not (Test-Path -LiteralPath $dll)) { throw "Expected DLL was not produced: $dll" }
$dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
if (-not $dumpbin) { throw 'dumpbin.exe was not found in the VS Developer environment.' }
$exports = & $dumpbin.Source /exports $dll
if ($LASTEXITCODE -ne 0) { throw "dumpbin failed with exit code $LASTEXITCODE." }
foreach ($export in @('DllGetClassObject', 'DllCanUnloadNow', 'DllRegisterServer', 'DllUnregisterServer')) {
    if (($exports -join "`n") -notmatch "\b$export\b") {
        throw "Expected export was not found: $export"
    }
}
$hardening = & $dumpbin.Source /headers /loadconfig $dll
if ($LASTEXITCODE -ne 0) { throw "dumpbin /headers /loadconfig failed with exit code $LASTEXITCODE." }
$hardeningText = $hardening -join "`n"
foreach ($flag in @('Control Flow Guard', 'Dynamic base', 'NX compatible', 'High Entropy Virtual Addresses')) {
    if ($hardeningText -notmatch [regex]::Escape($flag)) {
        throw "Expected DLL hardening flag was not found: $flag"
    }
}
if ($hardeningText -notmatch '(?im)^\s+CF instrumented\s*$' -or
    $hardeningText -notmatch '(?im)^\s+FID table present\s*$') {
    throw 'The DLL load configuration is missing Control Flow Guard instrumentation or its FID table.'
}

Write-Host 'Credential Provider Release x64 build succeeded.'
Write-Host 'KerbPack, PipeClient parser/harness, and SubmitFlow tests passed.'
Write-Host 'All four required DLL exports were found.'
Write-Host 'Control Flow Guard and required DLL hardening flags were found.'
