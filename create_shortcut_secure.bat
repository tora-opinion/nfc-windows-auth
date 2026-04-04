@echo off
cd /d "%~dp0"
set PYTHON=C:\Users\suger.G-GEAR\AppData\Local\Python\bin\pythonw.exe
set SCRIPT=%~dp0src\nfc_login_secure.py
set SHORTCUT=%USERPROFILE%\Desktop\NFC Login.lnk

echo === Creating Secure NFC Login Shortcut ===
echo.

REM Create shortcut that runs as admin
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT%'); $s.TargetPath = '%PYTHON%'; $s.Arguments = '\"%SCRIPT%\" run'; $s.WorkingDirectory = '%~dp0'; $s.Description = 'NFC Login - Place iPhone to unlock'; $s.Save()"

REM Set to run as admin
powershell -Command "$bytes = [System.IO.File]::ReadAllBytes('%SHORTCUT%'); $bytes[0x15] = $bytes[0x15] -bor 0x20; [System.IO.File]::WriteAllBytes('%SHORTCUT%', $bytes)"

echo.
echo Shortcut created with admin privileges!
echo.
echo Usage:
echo   1. Click "NFC Login" (UAC prompt will appear)
echo   2. Lock PC (Win+L)
echo   3. Place iPhone - auto unlock!
echo.
pause
