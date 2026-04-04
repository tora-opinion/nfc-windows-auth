@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1

if not exist "C:\Users\suger.G-GEAR\nfc-windows-auth\credential_provider\build" (
    mkdir "C:\Users\suger.G-GEAR\nfc-windows-auth\credential_provider\build"
)

cd /d "C:\Users\suger.G-GEAR\nfc-windows-auth\credential_provider\build"

cl.exe /nologo /W3 /O2 /EHsc /MD /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DNDEBUG /LD "..\NfcCredentialProvider.cpp" /Fe"NfcCredentialProvider.dll" /link /DEF:"..\NfcCredentialProvider.def" crypt32.lib shlwapi.lib advapi32.lib secur32.lib ole32.lib oleaut32.lib

echo Build exit code: %ERRORLEVEL%
