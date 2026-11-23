@echo off
rem ===========================================================================
rem  IGMP Tester - start the web UI
rem
rem  Sending and capturing packets needs administrator rights, so this script
rem  asks for them (UAC prompt) when it is not already elevated.
rem  Any arguments are passed to the server, for example:
rem      start_ui.bat --port 9000
rem      start_ui.bat --no-browser
rem ===========================================================================
setlocal
cd /d "%~dp0"

rem --------------------------------------------------------------- elevation
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    if errorlevel 1 (
        echo.
        echo  Administrator rights were not granted. The UI can still be started,
        echo  but sending and capturing packets will most likely fail.
        choice /c YN /m "Start without administrator rights"
        if errorlevel 2 exit /b 1
        goto :run
    )
    exit /b 0
)

:run
rem --------------------------------------------------------------- environment
if not exist ".venv\Scripts\python.exe" (
    echo.
    echo  The virtual environment was not found. Run setup.bat first.
    echo.
    pause
    exit /b 1
)

title IGMP Tester UI
echo.
echo  Starting the IGMP Tester UI. Keep this window open while you use it;
echo  close it or press Ctrl+C to stop the server.
echo.
".venv\Scripts\python.exe" ui\server.py %*
if errorlevel 1 (
    echo.
    echo  The UI server stopped with an error. See the messages above.
    echo  If the port is already in use, try: start_ui.bat --port 9000
)
echo.
pause
