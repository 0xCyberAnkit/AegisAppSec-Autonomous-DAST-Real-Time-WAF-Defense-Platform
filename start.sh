#!/usr/bin/env bash
set -e
echo "============================================================"
echo "  Starting AegisAppSec Enterprise DAST & WAF Platform"
echo "============================================================"
cd "$(dirname "$0")"
python3 backend/run.py
