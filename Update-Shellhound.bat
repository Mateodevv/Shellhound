@echo off
setlocal
call "%~dp0Start-Shellhound.bat" --update %*
exit /b %errorlevel%
