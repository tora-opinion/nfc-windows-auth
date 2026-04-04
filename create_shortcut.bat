@echo off
cd /d "%~dp0"
set PYTHON=C:\Users\suger.G-GEAR\AppData\Local\Python\bin\pythonw.exe
set SCRIPT=%~dp0src\nfc_login.py
set SHORTCUT=%USERPROFILE%\Desktop\NFC Login.lnk

echo === Creating Desktop Shortcut ===

powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT%'); $s.TargetPath = '%PYTHON%'; $s.Arguments = '\"%SCRIPT%\" run'; $s.WorkingDirectory = '%~dp0'; $s.Description = 'NFC Login - Place iPhone on reader'; $s.Save()"

echo.
echo Shortcut created on Desktop!
echo.
echo Usage:
echo   1. Click "NFC Login" shortcut
echo   2. Lock PC (Win+L)
echo   3. Place iPhone on reader
echo   4. Auto unlock!
echo.
pause
