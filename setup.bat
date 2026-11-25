@echo off
rem ===========================================================================
rem  IGMP Tester - one-time setup for Windows
rem
rem  Creates the .venv virtual environment with Python 3.12 and installs the
rem  packages from docker\requirements.txt. Run it again at any time to repair
rem  or update the environment.
rem ===========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "PYVER=3.12"
set "VENV=.venv"
set "ERRORS=0"

echo.
echo  IGMP Tester setup
echo  =================
echo.

rem --------------------------------------------------------------- Python 3.12
echo [1/5] Looking for Python %PYVER%...
set "PYTHON="
py -%PYVER% -c "import sys" >nul 2>&1 && set "PYTHON=py -%PYVER%"
if not defined PYTHON (
    for /f "tokens=2" %%v in ('python --version 2^>nul') do (
        echo %%v | findstr /b /l /c:"%PYVER%." >nul && set "PYTHON=python"
    )
)
if not defined PYTHON (
    echo       Python %PYVER% is not installed. The pinned packages in
    echo       docker\requirements.txt need this version.
    where py >nul 2>&1
    if !errorlevel! equ 0 (
        choice /c YN /m "      Install Python %PYVER% now with 'py install %PYVER%'"
        if !errorlevel! equ 1 (
            py install %PYVER%
            py -%PYVER% -c "import sys" >nul 2>&1 && set "PYTHON=py -%PYVER%"
        )
    )
)
if not defined PYTHON (
    echo.
    echo  ERROR: Python %PYVER% is still not available.
    echo         Install it from https://www.python.org/downloads/ and run setup.bat again.
    goto :fail
)
for /f "delims=" %%v in ('%PYTHON% --version') do echo       Found %%v ^(%PYTHON%^)

rem --------------------------------------------------------------- Npcap
echo [2/5] Checking for Npcap...
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo       Npcap is installed.
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo       A WinPcap compatible driver is installed.
) else (
    echo       WARNING: Npcap was not found. It is needed to send and capture packets.
    echo                Install it from https://npcap.com and enable
    echo                "WinPcap API-compatible mode" during installation.
    set /a ERRORS+=1
)

rem --------------------------------------------------------------- WpdPack
echo [3/5] Checking for the WinPcap developer pack...
if exist "C:\WpdPack\Include\pcap.h" (
    echo       C:\WpdPack found.
) else (
    echo       WARNING: C:\WpdPack was not found. It is needed to build pcapy-ng.
    echo                Download it from https://www.winpcap.org/devel.htm and
    echo                extract it so that C:\WpdPack\Include exists.
    set /a ERRORS+=1
)

rem --------------------------------------------------------------- venv
echo [4/5] Creating the virtual environment in %VENV%...
if exist "%VENV%\Scripts\python.exe" (
    for /f "tokens=2" %%v in ('"%VENV%\Scripts\python.exe" --version 2^>nul') do set "VENVVER=%%v"
    echo !VENVVER! | findstr /b /l /c:"%PYVER%." >nul
    if !errorlevel! neq 0 (
        echo       The existing %VENV% uses Python !VENVVER!, recreating it with %PYVER%...
        rmdir /s /q "%VENV%"
    ) else (
        echo       %VENV% already exists, reusing it.
    )
)
if not exist "%VENV%\Scripts\python.exe" (
    %PYTHON% -m venv "%VENV%"
    if errorlevel 1 (
        echo  ERROR: Could not create the virtual environment.
        goto :fail
    )
)

rem --------------------------------------------------------------- packages
echo [5/5] Installing the Python packages...
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip --disable-pip-version-check -q
"%VENV%\Scripts\python.exe" -m pip install --disable-pip-version-check -r docker\requirements.txt
if errorlevel 1 (
    echo.
    echo  ERROR: Installing the packages failed. See the messages above.
    echo         If pcapy-ng failed to build, check that the Microsoft C++ Build Tools
    echo         ^("Desktop development with C++"^) are installed and that C:\WpdPack exists:
    echo         https://visualstudio.microsoft.com/visual-cpp-build-tools/
    goto :fail
)

echo.
echo Checking that everything can be imported...
"%VENV%\Scripts\python.exe" -c "import pcapy, scapy, psutil, pytest; print('      pcapy, scapy, psutil and pytest are OK')"
if errorlevel 1 (
    echo  ERROR: The packages were installed but cannot be imported. See the messages above.
    goto :fail
)

echo.
if %ERRORS% gtr 0 (
    echo  Setup finished with %ERRORS% warning^(s^). Fix them before running the tests.
) else (
    echo  Setup complete. Start the UI with start_ui.bat
)
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1
