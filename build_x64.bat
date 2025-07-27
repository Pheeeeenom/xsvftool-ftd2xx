@echo off
echo Building 64-bit (x64) version...
echo.
echo IMPORTANT: You need the FTDI libraries in ftdilib\amd64\
echo.

REM Try to find Visual Studio x64 tools
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\*" (
    for /d %%i in ("%ProgramFiles%\Microsoft Visual Studio\2022\*") do (
        if exist "%%i\Common7\Tools\VsDevCmd.bat" (
            call "%%i\Common7\Tools\VsDevCmd.bat" -arch=x64
            goto :build
        )
    )
)

if exist "%ProgramFiles%\Microsoft Visual Studio\2019\*" (
    for /d %%i in ("%ProgramFiles%\Microsoft Visual Studio\2019\*") do (
        if exist "%%i\Common7\Tools\VsDevCmd.bat" (
            call "%%i\Common7\Tools\VsDevCmd.bat" -arch=x64
            goto :build
        )
    )
)

echo ERROR: Could not find Visual Studio x64 tools
echo Please run from "x64 Native Tools Command Prompt for VS"
pause
exit /b 1

:build
if not exist "ftdilib\amd64\ftd2xx.lib" (
    echo ERROR: ftdilib\amd64\ftd2xx.lib not found!
    echo Please set up the ftdilib folder first.
    pause
    exit /b 1
)
nmake clean
nmake
pause