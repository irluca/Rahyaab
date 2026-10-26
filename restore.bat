@echo off
title Tunnel Studio Pro - Restore
echo ========================================================
echo   Restore pairs from a backup.
echo   Pairs that already exist are skipped, never overwritten.
echo ========================================================
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  set PY=.venv\Scripts\python.exe
) else (
  set PY=python
)
%PY% orchestrator\backup_tool.py list
echo.
set /p BACKUP_NAME=Type the backup folder name to restore (or leave empty to cancel):
if "%BACKUP_NAME%"=="" (
  echo Cancelled.
  pause
  exit /b 0
)
%PY% orchestrator\backup_tool.py restore "%BACKUP_NAME%"
pause
