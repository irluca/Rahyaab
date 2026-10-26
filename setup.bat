@echo off
title Tunnel Studio Pro - Setup
echo ========================================================
echo   Tunnel Studio Pro - one-time setup
echo ========================================================
cd /d "%~dp0"

rem --- Python must exist and be 3.11 or newer -------------------------------
python --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python was not found on this machine.
  echo         Install Python 3.11 or newer from https://www.python.org/downloads/
  echo         and tick "Add python.exe to PATH" during the installation.
  pause
  exit /b 1
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 (
  echo [ERROR] Python 3.11 or newer is required. Your version:
  python --version
  echo         Install a newer Python from https://www.python.org/downloads/
  pause
  exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [OK] %%v

rem --- Private environment ----------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
  echo [*] Creating the private Python environment (.venv) ...
  python -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Could not create .venv - see the message above.
    pause
    exit /b 1
  )
) else (
  echo [OK] Private environment already exists (.venv)
)

rem --- Pinned dependencies -----------------------------------------------------
echo [*] Installing the pinned dependencies (requirements.txt) ...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Dependency installation failed - check the network and retry.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install "pytest==9.1.1" >nul 2>&1

".venv\Scripts\python.exe" -c "import paramiko, cryptography; print('[OK] Dependencies verified')"
if errorlevel 1 (
  echo [ERROR] Dependencies installed but could not be imported.
  pause
  exit /b 1
)

echo ========================================================
echo   Setup complete.
echo   Start the dashboard any time with:  start_dashboard.bat
echo ========================================================
pause
