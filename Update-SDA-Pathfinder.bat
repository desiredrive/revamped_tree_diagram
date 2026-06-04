@echo off
rem SDA Pathfinder — update launcher (Windows).
rem Double-click to check GitHub for a newer release and install it in place.
rem Pure Python stdlib; no venv needed.

cd /d "%~dp0"

echo ====================================
echo   SDA Pathfinder -- Update
echo ====================================
echo.

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY where python3 >nul 2>nul && set "PY=python3"

if not defined PY (
    echo Error: Python 3.10+ not found on PATH.
    echo Install from https://www.python.org/downloads/ (check "Add to PATH" during install) and try again.
    pause
    exit /b 1
)

%PY% update.py %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
