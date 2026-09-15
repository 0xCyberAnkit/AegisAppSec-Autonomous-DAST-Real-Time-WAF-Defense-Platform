@echo off
title AegisAppSec - Multi-Target Vulnerable Cluster
echo ============================================================
echo   AEGIS APPSEC // 4-TARGET VULNERABILITY CLUSTER
echo ============================================================
echo   [1] VoltMart E-Commerce:      http://127.0.0.1:8001
echo   [2] ApexBank FinTech API:     http://127.0.0.1:8002
echo   [3] PulseHealth EHR Portal:   http://127.0.0.1:8003
echo   [4] CloudOps DevOps Console:  http://127.0.0.1:8004
echo ============================================================
echo.
python web_targets\runner.py
pause
