@echo off
REM Kinkntease GitHub Update Launcher
REM Double-click this file to update your GitHub repository

echo Starting GitHub Update Script...
echo.

REM Run PowerShell script with execution policy bypass
powershell.exe -ExecutionPolicy Bypass -File "%~dp0update-github.ps1"

echo.
echo Script complete!
pause
