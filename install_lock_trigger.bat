@echo off
REM Install NFC Auth Task - Triggers on Workstation Lock
REM Run as Administrator!

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator!
    pause
    exit /b 1
)

set SCRIPT_PATH=%~dp0nfc_on_lock.py
set PYTHON_PATH=C:\Users\suger.G-GEAR\AppData\Local\Programs\Python\Python312\pythonw.exe

echo === Installing NFC Lock Trigger Task ===
echo.

REM Delete existing task if any
schtasks /delete /tn "NFC Auth On Lock" /f >nul 2>&1

REM Create task triggered on workstation lock (Event ID 4800)
schtasks /create /tn "NFC Auth On Lock" /tr "\"%PYTHON_PATH%\" \"%SCRIPT_PATH%\"" /sc onevent /ec Security /mo "*[System[EventID=4800]]" /ru "%USERNAME%" /rl highest /f

if %errorlevel% equ 0 (
    echo.
    echo Task created successfully!
    echo.
    echo NFC polling will now ONLY run when you lock the PC.
    echo No more interference with patent applications.
) else (
    echo.
    echo Note: Security event trigger requires audit policy.
    echo Creating alternative trigger using Task Scheduler XML...

    REM Create XML for session lock trigger
    echo ^<?xml version="1.0" encoding="UTF-16"?^> > "%TEMP%\nfc_task.xml"
    echo ^<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"^> >> "%TEMP%\nfc_task.xml"
    echo   ^<Triggers^> >> "%TEMP%\nfc_task.xml"
    echo     ^<SessionStateChangeTrigger^> >> "%TEMP%\nfc_task.xml"
    echo       ^<Enabled^>true^</Enabled^> >> "%TEMP%\nfc_task.xml"
    echo       ^<StateChange^>SessionLock^</StateChange^> >> "%TEMP%\nfc_task.xml"
    echo     ^</SessionStateChangeTrigger^> >> "%TEMP%\nfc_task.xml"
    echo     ^<EventTrigger^> >> "%TEMP%\nfc_task.xml"
    echo       ^<Enabled^>true^</Enabled^> >> "%TEMP%\nfc_task.xml"
    echo       ^<Subscription^>^&lt;QueryList^&gt;^&lt;Query Id="0" Path="System"^&gt;^&lt;Select Path="System"^&gt;*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]^&lt;/Select^&gt;^&lt;/Query^&gt;^&lt;/QueryList^&gt;^</Subscription^> >> "%TEMP%\nfc_task.xml"
    echo     ^</EventTrigger^> >> "%TEMP%\nfc_task.xml"
    echo   ^</Triggers^> >> "%TEMP%\nfc_task.xml"
    echo   ^<Principals^> >> "%TEMP%\nfc_task.xml"
    echo     ^<Principal id="Author"^> >> "%TEMP%\nfc_task.xml"
    echo       ^<LogonType^>InteractiveToken^</LogonType^> >> "%TEMP%\nfc_task.xml"
    echo       ^<RunLevel^>HighestAvailable^</RunLevel^> >> "%TEMP%\nfc_task.xml"
    echo     ^</Principal^> >> "%TEMP%\nfc_task.xml"
    echo   ^</Principals^> >> "%TEMP%\nfc_task.xml"
    echo   ^<Settings^> >> "%TEMP%\nfc_task.xml"
    echo     ^<MultipleInstancesPolicy^>IgnoreNew^</MultipleInstancesPolicy^> >> "%TEMP%\nfc_task.xml"
    echo     ^<DisallowStartIfOnBatteries^>false^</DisallowStartIfOnBatteries^> >> "%TEMP%\nfc_task.xml"
    echo     ^<StopIfGoingOnBatteries^>false^</StopIfGoingOnBatteries^> >> "%TEMP%\nfc_task.xml"
    echo     ^<AllowHardTerminate^>true^</AllowHardTerminate^> >> "%TEMP%\nfc_task.xml"
    echo     ^<StartWhenAvailable^>false^</StartWhenAvailable^> >> "%TEMP%\nfc_task.xml"
    echo     ^<RunOnlyIfNetworkAvailable^>false^</RunOnlyIfNetworkAvailable^> >> "%TEMP%\nfc_task.xml"
    echo     ^<AllowStartOnDemand^>true^</AllowStartOnDemand^> >> "%TEMP%\nfc_task.xml"
    echo     ^<Enabled^>true^</Enabled^> >> "%TEMP%\nfc_task.xml"
    echo     ^<Hidden^>false^</Hidden^> >> "%TEMP%\nfc_task.xml"
    echo     ^<ExecutionTimeLimit^>PT2M^</ExecutionTimeLimit^> >> "%TEMP%\nfc_task.xml"
    echo     ^<Priority^>7^</Priority^> >> "%TEMP%\nfc_task.xml"
    echo   ^</Settings^> >> "%TEMP%\nfc_task.xml"
    echo   ^<Actions Context="Author"^> >> "%TEMP%\nfc_task.xml"
    echo     ^<Exec^> >> "%TEMP%\nfc_task.xml"
    echo       ^<Command^>%PYTHON_PATH%^</Command^> >> "%TEMP%\nfc_task.xml"
    echo       ^<Arguments^>"%SCRIPT_PATH%"^</Arguments^> >> "%TEMP%\nfc_task.xml"
    echo       ^<WorkingDirectory^>%~dp0^</WorkingDirectory^> >> "%TEMP%\nfc_task.xml"
    echo     ^</Exec^> >> "%TEMP%\nfc_task.xml"
    echo   ^</Actions^> >> "%TEMP%\nfc_task.xml"
    echo ^</Task^> >> "%TEMP%\nfc_task.xml"

    schtasks /create /tn "NFC Auth On Lock" /xml "%TEMP%\nfc_task.xml" /f
    del "%TEMP%\nfc_task.xml"

    if %errorlevel% equ 0 (
        echo.
        echo Task created with SessionLock trigger!
    ) else (
        echo.
        echo Failed to create task. Please check Task Scheduler manually.
    )
)

echo.
pause
