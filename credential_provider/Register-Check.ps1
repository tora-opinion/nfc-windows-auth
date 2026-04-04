#Requires -RunAsAdministrator
$log = 'C:\Users\suger.G-GEAR\nfc-windows-auth\register_log.txt'
"=== $(Get-Date) ===" | Out-File $log -Encoding utf8

$dst      = 'C:\Windows\System32\NfcCredentialProvider.dll'
$clsidKey = 'HKLM:\SOFTWARE\Classes\CLSID\{A5E8C3B2-1234-5678-ABCD-0F1E2D3C4B5A}'
$cpKey    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A5E8C3B2-1234-5678-ABCD-0F1E2D3C4B5A}'

"DLL exists: $(Test-Path $dst)" | Tee-Object -FilePath $log -Append

# Run regsvr32
$p = Start-Process 'regsvr32' -ArgumentList "/s `"$dst`"" -Wait -PassThru
"regsvr32 exit: $($p.ExitCode)" | Tee-Object -FilePath $log -Append
"CLSID after regsvr32: $(Test-Path $clsidKey)" | Tee-Object -FilePath $log -Append

# Manual registration if regsvr32 failed
if (!(Test-Path $clsidKey)) {
    "Manual registry creation..." | Tee-Object -FilePath $log -Append
    New-Item -Path "$clsidKey\InprocServer32" -Force | Out-Null
    Set-ItemProperty -Path "$clsidKey\InprocServer32" -Name '(default)' -Value $dst
    Set-ItemProperty -Path "$clsidKey\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'
    New-Item -Path $cpKey -Force | Out-Null
    Set-ItemProperty -Path $cpKey -Name '(default)' -Value 'NFC Credential Provider'
    "Manual registration done" | Tee-Object -FilePath $log -Append
}

"Final CLSID: $(Test-Path $clsidKey)" | Tee-Object -FilePath $log -Append
"Final CP:    $(Test-Path $cpKey)"    | Tee-Object -FilePath $log -Append
"Done. See log: $log"
