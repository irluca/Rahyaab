@echo off
title Tunnel Studio Pro - Backup
echo ========================================================
echo   Backing up your pairs and database
echo   (credentials are never part of a backup)
echo ========================================================
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" orchestrator\backup_tool.py backup
) else (
  python orchestrator\backup_tool.py backup
)
pause
