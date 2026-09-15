"""
AegisAppSec Multi-Target Master Runner
Orchestrates and runs all 4 vulnerable target applications concurrently on separate ports:
- Target 1 (VoltMart E-Commerce):   http://127.0.0.1:8001
- Target 2 (ApexBank FinTech API):  http://127.0.0.1:8002
- Target 3 (PulseHealth EHR):       http://127.0.0.1:8003
- Target 4 (CloudOps DevOps):       http://127.0.0.1:8004
"""

import sys
import os
import time
import threading
import urllib.request
import argparse
from pathlib import Path
import uvicorn

# Add project root to sys.path so imports work seamlessly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

TARGETS_CONFIG = [
    {
        "id": 1,
        "name": "VoltMart Electronics Store",
        "app_module": "web_targets.target1_ecommerce.app:app",
        "port": 8001,
        "cwe_tags": ["CWE-89 (SQLi)", "CWE-79 (XSS)", "CWE-352 (CSRF)", "CWE-639 (IDOR)"],
        "color": "\033[96m" # Cyan
    },
    {
        "id": 2,
        "name": "ApexBank Treasury & FX API",
        "app_module": "web_targets.target2_fintech.app:app",
        "port": 8002,
        "cwe_tags": ["CWE-918 (SSRF)", "CWE-287 (Auth)", "CWE-601 (Redirect)", "CWE-200 (Info)"],
        "color": "\033[92m" # Green
    },
    {
        "id": 3,
        "name": "PulseHealth Hospital EHR",
        "app_module": "web_targets.target3_healthcare.app:app",
        "port": 8003,
        "cwe_tags": ["CWE-22 (LFI/Traversal)", "CWE-611 (XXE)", "CWE-942 (CORS)", "CWE-16 (Misconfig)"],
        "color": "\033[95m" # Purple/Magenta
    },
    {
        "id": 4,
        "name": "CloudOps Cluster Console",
        "app_module": "web_targets.target4_devops.app:app",
        "port": 8004,
        "cwe_tags": ["CWE-78 (CMDi)", "CWE-502 (Deser)", "CWE-1104 (Outdated)", "CWE-200 (Info)"],
        "color": "\033[93m" # Yellow
    }
]

RESET_COLOR = "\033[0m"

def run_server(app_module: str, host: str, port: int):
    """Runs a single uvicorn server instance in the calling thread."""
    config = uvicorn.Config(
        app_module,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
        server_header=False
    )
    server = uvicorn.Server(config)
    server.run()

def check_health(timeout: float = 2.0):
    """Checks and prints the health status of all 4 targets."""
    print("\n" + "=" * 68)
    print("  AEGIS APPSEC // MULTI-TARGET TESTBED HEALTH MATRIX")
    print("=" * 68)
    all_healthy = True
    for t in TARGETS_CONFIG:
        url = f"http://127.0.0.1:{t['port']}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AegisHealthCheck/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                print(f"  [+] Target {t['id']}: {t['name']:<28} | Port {t['port']} -> HTTP {status} (ONLINE)")
                print(f"      Vectors: {', '.join(t['cwe_tags'])}")
        except Exception as e:
            all_healthy = False
            print(f"  [-] Target {t['id']}: {t['name']:<28} | Port {t['port']} -> OFFLINE ({str(e)})")
    print("=" * 68 + "\n")
    return all_healthy

def start_all_targets(host: str = "0.0.0.0"):
    """Starts all 4 target servers in concurrent background daemon threads."""
    print("\n============================================================")
    print("  AEGIS APPSEC // LAUNCHING ALL 4 DAST VULNERABLE TARGETS")
    print("============================================================")
    
    threads = []
    for t in TARGETS_CONFIG:
        print(f"  [+] Starting Target {t['id']}: {t['name']}")
        print(f"      URL:     http://127.0.0.1:{t['port']}")
        print(f"      Vectors: {', '.join(t['cwe_tags'])}\n")
        
        thread = threading.Thread(
            target=run_server,
            args=(t["app_module"], host, t["port"]),
            daemon=True,
            name=f"Target-{t['id']}-Server"
        )
        thread.start()
        threads.append(thread)

    print("  [+] All 4 web targets initialized. Running diagnostics...")
    time.sleep(1.5)
    check_health()
    print("  [i] Targets are active and ready for autonomous scanning.")
    print("  [i] Press CTRL+C to terminate all target servers.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [!] Shutting down all web targets...")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisAppSec Multi-Target Runner")
    parser.add_argument("--health", action="store_true", help="Perform health check on all 4 target ports")
    parser.add_argument("--target", type=int, choices=[1, 2, 3, 4], help="Launch a single target by ID (1-4)")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, help="Override port for single target run")
    args = parser.parse_args()

    if args.health:
        is_ok = check_health()
        sys.exit(0 if is_ok else 1)
    elif args.target:
        cfg = next((c for c in TARGETS_CONFIG if c["id"] == args.target), None)
        port = args.port or cfg["port"]
        print(f"Starting Target {cfg['id']}: {cfg['name']} on http://{args.host}:{port}")
        run_server(cfg["app_module"], args.host, port)
    else:
        start_all_targets(host=args.host)
