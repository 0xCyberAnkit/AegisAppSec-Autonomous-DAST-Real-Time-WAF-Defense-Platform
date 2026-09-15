@echo off
echo ============================================================
echo   Starting AegisAppSec Enterprise DAST & WAF Platform
echo ============================================================
echo.
cd /d "%~dp0"
python backend/run.py
pause
