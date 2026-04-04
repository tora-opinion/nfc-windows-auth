@echo off
cd /d "%~dp0"
set PYTHON=C:\Users\suger.G-GEAR\AppData\Local\Python\bin\python.exe

echo === NFC Login Secure Setup ===
echo.
echo This uses Windows DPAPI for secure password storage.
echo.

"%PYTHON%" src/nfc_login_secure.py setup

pause
