@echo off
REM NFC Daemon Starter - runs minimized in background
cd /d "%~dp0"
start /min "" pythonw src/nfc_daemon_service.py run
