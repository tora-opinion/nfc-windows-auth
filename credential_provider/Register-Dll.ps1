#Requires -RunAsAdministrator
$dll = 'C:\Users\suger.G-GEAR\nfc-windows-auth\credential_provider\build\NfcCredentialProvider.dll'
$dst = 'C:\Windows\System32\NfcCredentialProvider.dll'

Copy-Item $dll $dst -Force
Write-Host "コピー完了: $dst"

$result = Start-Process regsvr32 -ArgumentList "/s `"$dst`"" -Wait -PassThru
if ($result.ExitCode -eq 0) {
    Write-Host "DLL登録成功" -ForegroundColor Green
} else {
    Write-Host "regsvr32 失敗 (exit=$($result.ExitCode))" -ForegroundColor Red
}
