@echo off
cd /d "%~dp0"
set PYTHON=C:\Users\suger.G-GEAR\AppData\Local\Python\bin\python.exe
echo === NFC Login Password Setup ===
echo.
set /p PASSWORD="Enter your Windows password: "
"%PYTHON%" -c "import sys; sys.path.insert(0,'src'); from nfc_login import NFCLogin; l=NFCLogin(); l._save_password('%PASSWORD%'); print('Password saved!')"
echo.
echo Setup complete!
echo.
pause
