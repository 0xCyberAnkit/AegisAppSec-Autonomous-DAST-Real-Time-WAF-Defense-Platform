@echo off
echo ============================================================
echo   AegisAppSec // Multi-Container Enterprise Stack
echo   Orchestrating: Web + MySQL + Redis + Celery Worker
echo ============================================================
echo.
cd /d "%~dp0"
docker-compose up --build
pause
