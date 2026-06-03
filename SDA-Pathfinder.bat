@echo off
rem SDA Pathfinder launcher — Windows. Double-click to run.
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\launcher.ps1"
if errorlevel 1 (
    echo.
    echo SDA Pathfinder exited with an error.
    pause
)
