@echo off
REM Bootstrap + launch the SDA Fabric Troubleshooter on Windows.
REM NOTE: the bundled RADKit wheels target manylinux1_x86_64 and will NOT
REM install on Windows. On Windows, install matching RADKit wheels from
REM https://radkit.cisco.com/docs/ and edit requirements.txt accordingly.

setlocal
cd /d "%~dp0"

set "PY=python"
where %PY% >nul 2>nul
if errorlevel 1 (
  echo Error: python not found in PATH. Install Python 3.12.
  exit /b 1
)

if not exist ".venv" (
  echo Creating virtualenv in .venv ...
  %PY% -m venv .venv || exit /b 1
)

call .venv\Scripts\activate.bat

if not exist ".venv\.installed" (
  echo Installing dependencies ...
  pip install --upgrade pip || exit /b 1
  pip install -r requirements.txt || exit /b 1
  echo done> .venv\.installed
)

if "%HOST%"=="" set "HOST=127.0.0.1"
if "%PORT%"=="" set "PORT=8000"
echo Starting server on http://%HOST%:%PORT%
uvicorn server:app --host %HOST% --port %PORT%
