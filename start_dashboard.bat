@echo off
title Tunnel Studio Pro v2.0 - Live Dashboard
echo ========================================================
echo   Starting Tunnel Studio Pro v2.0 Dashboard (LIVE MODE)
echo   Open your browser at: http://127.0.0.1:8800
echo ========================================================
set BEST_TUNNEL_DRY_RUN=0
rem Live sessions refuse a database inside the repository (it would record the
rem servers' addresses in the working tree), so the live database lives under
rem the operator's own .best_tunnel directory. An operator-set path wins.
if not defined BEST_TUNNEL_DB_PATH set BEST_TUNNEL_DB_PATH=%USERPROFILE%\.best_tunnel\best_tunnel.db
echo   Database: %BEST_TUNNEL_DB_PATH%
rem Prefer the private environment setup.bat created; fall back to system Python
rem so a machine that never ran setup behaves exactly as before.
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" orchestrator\dashboard.py
) else (
  python orchestrator\dashboard.py
)
pause
