@echo off
cd /d "%~dp0"
set PYTHON=C:\Users\suger.G-GEAR\AppData\Local\Python\bin\python.exe
set SCRIPT=%~dp0src\nfc_login.py

echo === Installing NFC Login Task ===
echo.

REM Create task that triggers on workstation lock
schtasks /create /tn "NFC_Login_Unlock" /tr "\"%PYTHON%\" \"%SCRIPT%\" run" /sc onevent /ec System /mo "*[System[Provider[@Name='Microsoft-Windows-Winlogon'] and EventID=4800]]" /rl highest /f

if %errorlevel% equ 0 (
    echo Task created successfully!
    echo NFC Login will run when PC is locked.
) else (
    echo Failed to create task. Try running as Administrator.
)

echo.
pause
