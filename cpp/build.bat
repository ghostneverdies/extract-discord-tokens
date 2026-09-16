@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSDIR="

where cl >nul 2>&1
if %errorlevel%==0 goto :build

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
)

if not defined VSDIR (
    if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community" set "VSDIR=%ProgramFiles%\Microsoft Visual Studio\18\Community"
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community" set "VSDIR=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community"
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community" set "VSDIR=%ProgramFiles%\Microsoft Visual Studio\2022\Community"
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools" set "VSDIR=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools"
    if exist "%ProgramFiles%\Microsoft Visual Studio\2019\Community" set "VSDIR=%ProgramFiles%\Microsoft Visual Studio\2019\Community"
)

if not defined VSDIR (
    echo MSVC not found on this computer
    exit /b 1
)

if not exist "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" (
    echo MSVC not found on this computer
    exit /b 1
)

call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo MSVC not found on this computer
    exit /b 1
)

:build
cl /nologo /EHsc /std:c++17 /O2 /Fe:main.exe main.cpp /link winhttp.lib
exit /b %errorlevel%