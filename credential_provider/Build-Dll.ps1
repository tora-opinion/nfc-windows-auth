# Build-Dll.ps1 - NfcCredentialProvider.dll を Visual Studio 2022 でビルド

$ErrorActionPreference = 'Stop'

$vcvars  = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
$clExe   = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
$src     = $PSScriptRoot + '\NfcCredentialProvider.cpp'
$def     = $PSScriptRoot + '\NfcCredentialProvider.def'
$outDir  = $PSScriptRoot + '\build'
$dllOut  = $outDir + '\NfcCredentialProvider.dll'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# vcvars64.bat から環境変数をインポート
Write-Host "vcvars64.bat から環境変数をロード中..." -ForegroundColor Cyan
$envLines = cmd /c "`"$vcvars`" > nul 2>&1 && set"
foreach ($line in $envLines) {
    if ($line -match '^([^=]+)=(.*)$') {
        $name  = $matches[1]
        $value = $matches[2]
        [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

# SDK インクルードパスを確認
$sdkRoot = [System.Environment]::GetEnvironmentVariable('WindowsSdkDir', 'Process')
$sdkVer  = [System.Environment]::GetEnvironmentVariable('WindowsSDKVersion', 'Process')
Write-Host "SDK: $sdkRoot $sdkVer"

# カレントをビルドディレクトリに変更
Push-Location $outDir
try {
    Write-Host "コンパイル中..." -ForegroundColor Cyan
    & $clExe `
        /nologo /W3 /O2 /EHsc /MD `
        /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DNDEBUG `
        /LD $src `
        /Fe"NfcCredentialProvider.dll" `
        /link `
        /DEF:$def `
        crypt32.lib shlwapi.lib advapi32.lib secur32.lib ole32.lib oleaut32.lib

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ビルド失敗 (exit=$LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

if (Test-Path $dllOut) {
    Write-Host "`nビルド成功: $dllOut" -ForegroundColor Green
    Write-Host "`n次のステップ（管理者PowerShellで実行）:"
    Write-Host "  Copy-Item '$dllOut' C:\Windows\System32\"
    Write-Host "  regsvr32 C:\Windows\System32\NfcCredentialProvider.dll"
} else {
    Write-Host "DLLが見つかりません: $dllOut" -ForegroundColor Red
    exit 1
}
