@echo off
title Tunnel Studio Pro - Safe Update
echo ========================================================
echo   Tunnel Studio Pro - safe update
echo   The new version is adopted ONLY if the full offline
echo   test suite passes; otherwise this script puts the
echo   previous version back, untouched.
echo ========================================================
cd /d "%~dp0"

git --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Git was not found. Install it from https://git-scm.com/downloads
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] No private environment found - run setup.bat first.
  pause
  exit /b 1
)

for /f "tokens=*" %%h in ('git rev-parse HEAD') do set PREV_HEAD=%%h
echo [*] Current version: %PREV_HEAD%

echo [*] Downloading the latest version ...
git pull --ff-only
if errorlevel 1 (
  echo [ERROR] The download did not complete cleanly. Nothing was changed.
  echo         Most often this means local files were edited by hand;
  echo         ask for help before forcing anything.
  pause
  exit /b 1
)

echo [*] Running the offline test suite (this takes a few minutes) ...
".venv\Scripts\python.exe" -m pytest orchestrator\test_offline_suite.py -q -p no:cacheprovider
if errorlevel 1 (
  echo.
  echo [STOP] The new version FAILED its tests - rolling back.
  git reset --hard %PREV_HEAD%
  echo [OK] The previous, working version is back in place.
  pause
  exit /b 1
)

echo.
echo ========================================================
echo   Update complete - the new version passed every test.
echo ========================================================
pause
