@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-GreyLog.ps1" %*
exit /b %errorlevel%
