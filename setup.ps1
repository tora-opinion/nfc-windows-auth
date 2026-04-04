#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NFC Windows Auth セットアップスクリプト

.DESCRIPTION
    1. Python依存ライブラリをインストール
    2. register.py でSuicaとパスワードを登録
    3. install_task.py でデーモンをタスクスケジューラに登録
    4. Credential Provider DLL をビルド・インストール（Visual Studio必須）
#>

$ErrorActionPreference = 'Stop'
$Root   = $PSScriptRoot
$Daemon = Join-Path $Root 'daemon'
$CP     = Join-Path $Root 'credential_provider'

Write-Host '=== NFC Windows Auth セットアップ ===' -ForegroundColor Cyan

# --- Step 1: Python依存インストール ---
Write-Host "`n[1/4] Python依存ライブラリをインストール中..." -ForegroundColor Yellow
python -m pip install -r "$Daemon\requirements.txt"

# --- Step 2: Suica + パスワード登録 ---
Write-Host "`n[2/4] Suicaとパスワードを登録..." -ForegroundColor Yellow
Write-Host "iPhoneをRC-S300に置き、指示に従ってください。`n"
python "$Daemon\register.py"

# --- Step 3: デーモンをタスクスケジューラに登録 ---
Write-Host "`n[3/4] デーモンをタスクスケジューラに登録中..." -ForegroundColor Yellow
python "$Daemon\install_task.py"

# --- Step 4: Credential Provider DLL のビルドと登録 ---
Write-Host "`n[4/4] Credential Provider DLL のビルドと登録..." -ForegroundColor Yellow

# cmake / Visual Studio の確認
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    Write-Warning "cmake が見つかりません。Visual Studio 2022 (C++デスクトップ開発) をインストールしてください。"
    Write-Warning "スキップします。手動でビルドする場合は credential_provider\ フォルダ内の CMakeLists.txt を使用してください。"
} else {
    $BuildDir = Join-Path $CP 'build'
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

    Push-Location $BuildDir
    try {
        cmake .. -G "Visual Studio 17 2022" -A x64
        cmake --build . --config Release
        $DllPath = Join-Path $BuildDir 'Release\NfcCredentialProvider.dll'
        if (Test-Path $DllPath) {
            Copy-Item $DllPath 'C:\Windows\System32\' -Force
            & regsvr32 /s 'C:\Windows\System32\NfcCredentialProvider.dll'
            Write-Host 'Credential Provider DLL を登録しました。' -ForegroundColor Green
        } else {
            Write-Warning "DLLが見つかりません: $DllPath"
        }
    } finally {
        Pop-Location
    }
}

# --- デーモンを今すぐ起動 ---
Write-Host "`nデーモンを今すぐ起動しますか？ (y/n): " -NoNewline
$ans = Read-Host
if ($ans -eq 'y') {
    schtasks /run /tn NfcAuthDaemon
    Write-Host 'デーモン起動済み。' -ForegroundColor Green
}

Write-Host "`n=== セットアップ完了 ===" -ForegroundColor Cyan
Write-Host "iPhoneをRC-S300に置いてWindowsをロック解除してください。"
Write-Host "ログ: $Daemon\nfc_daemon.log"
