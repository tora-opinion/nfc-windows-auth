@echo off
REM Run as Administrator!

set DLL_PATH=%~dp0bin\NFCCredentialProvider.dll
set GUID={A0B1C2D3-E4F5-6789-ABCD-EF0123456789}

echo === NFC Credential Provider Registration ===
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Check if DLL exists
if not exist "%DLL_PATH%" (
    echo ERROR: DLL not found at %DLL_PATH%
    echo Please build the DLL first.
    pause
    exit /b 1
)

echo Registering DLL...
regsvr32 /s "%DLL_PATH%"

echo Adding registry entries...

REM Register the credential provider
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%GUID%" /ve /t REG_SZ /d "NFC Credential Provider" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%GUID%" /v "Disabled" /t REG_DWORD /d 0 /f

REM Add CLSID entry
reg add "HKCR\CLSID\%GUID%" /ve /t REG_SZ /d "NFC Credential Provider" /f
reg add "HKCR\CLSID\%GUID%\InprocServer32" /ve /t REG_SZ /d "%DLL_PATH%" /f
reg add "HKCR\CLSID\%GUID%\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f

echo.
echo Registration complete!
echo.
echo Next steps:
echo 1. Run the NFC daemon to monitor for cards
echo 2. Lock your PC (Win+L)
echo 3. Place iPhone on reader to login!
echo.
pause
