@echo off
setlocal

set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
    echo Error: vcvars64.bat not found
    exit /b 1
)

call %VCVARS%

set OUT_DIR=%~dp0build
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

set SRC=%~dp0NfcCredentialProvider.cpp
set DEF=%~dp0NfcCredentialProvider.def
set DLL=%OUT_DIR%\NfcCredentialProvider.dll
set PDB=%OUT_DIR%\NfcCredentialProvider.pdb

echo === Compiling NfcCredentialProvider.dll ===

cl.exe /nologo /W3 /O2 /EHsc /MD ^
    /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DNDEBUG ^
    /LD ^
    "%SRC%" ^
    /Fe"%DLL%" ^
    /Fd"%PDB%" ^
    /link ^
    /DEF:"%DEF%" ^
    /SUBSYSTEM:WINDOWS ^
    crypt32.lib shlwapi.lib advapi32.lib secur32.lib ole32.lib oleaut32.lib ^
    /OUT:"%DLL%"

if %ERRORLEVEL% neq 0 (
    echo Build FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo Build succeeded: %DLL%
echo.
echo 管理者PowerShellで以下を実行して登録してください:
echo   Copy-Item "%DLL%" C:\Windows\System32\
echo   regsvr32 C:\Windows\System32\NfcCredentialProvider.dll

endlocal
