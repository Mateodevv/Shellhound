@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m server.main %*
    goto finished
)
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m server.main %*
    goto finished
)
where python >nul 2>nul
if not errorlevel 1 (
    python -m server.main %*
    goto finished
)
echo [!] Install Python 3.10 or newer from https://www.python.org/downloads/windows/
echo [!] Enable its PATH option, then open this launcher again.
if not defined SHELLHOUND_NO_PAUSE pause
exit /b 1
:finished
set "shellhound_exit=%errorlevel%"
if not "%shellhound_exit%"=="0" (
    echo.
    echo Shellhound stopped. Read the message above, then start again.
    if not defined SHELLHOUND_NO_PAUSE pause
)
exit /b %shellhound_exit%
