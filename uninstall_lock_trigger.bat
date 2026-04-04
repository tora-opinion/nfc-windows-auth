@echo off
REM Uninstall NFC Lock Trigger Task
REM Run as Administrator!

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator!
    pause
    exit /b 1
)

echo Removing NFC Auth task...
schtasks /delete /tn "NFC Auth On Lock" /f

echo Done.
pause
