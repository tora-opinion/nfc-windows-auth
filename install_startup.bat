@echo off
cd /d "%~dp0"
set PYTHON=C:\Users\suger.G-GEAR\AppData\Local\Python\bin\python.exe
echo === Installing NFC Login to Startup ===
"%PYTHON%" src/nfc_login.py install
echo.
pause
