# Walkthrough: 4 Vulnerable Web Targets on Multi-Port Architecture

## Summary of Completed Work
Implemented a dedicated, self-contained multi-target vulnerability testbed inside the [`web_targets/`](file:///c:/Users/Dell/Desktop/Projects/CyberSecurityProjects/project/web_targets) directory. The suite consists of **four distinct, realistic web applications**, each running on its own dedicated TCP port with its own minimal, responsive cyber UI, demonstrating specific OWASP Top 10 and CWE Top 25 vulnerability classes.

---

## 1. Target Applications Architecture & Ports

| Target # | Application Name | Local URL | Port | Industry Theme | Demonstrated Vulnerabilities |
|---|---|---|---|---|---|
| **01** | **VoltMart Electronics** | `http://127.0.0.1:8001` | **8001** | Consumer Tech & E-Commerce | • **SQLi** (`[CWE-89]` in `/search?q=`)<br>• **Stored/Reflected XSS** (`[CWE-79]` in `/reviews`)<br>• **CSRF** (`[CWE-352]` in `/account/email`)<br>• **IDOR** (`[CWE-639]` in `/api/orders/{id}`) |
| **02** | **ApexBank Treasury** | `http://127.0.0.1:8002` | **8002** | Corporate FinTech & FX API | • **SSRF** (`[CWE-918]` in `/api/webhooks/test` & `/api/fx/feed`)<br>• **Broken Auth** (`[CWE-287]` in `/api/login`)<br>• **Open Redirect** (`[CWE-601]` in `/redirect?url=`)<br>• **Sensitive Data Leak** (`[CWE-200]` in `/api/debug/system`) |
| **03** | **PulseHealth EHR** | `http://127.0.0.1:8003` | **8003** | Healthcare & Hospital Information | • **Path Traversal / LFI** (`[CWE-22]` in `/records/download?file=`)<br>• **XXE Injection** (`[CWE-611]` in `/api/records/xml-import`)<br>• **CORS Misconfig** (`[CWE-942]` in `/api/patient/{id}`)<br>• **Security Misconfig** (`[CWE-16]`) |
| **04** | **CloudOps Cluster Console** | `http://127.0.0.1:8004` | **8004** | DevOps & Container Infrastructure | • **OS Command Injection** (`[CWE-78]` in `/api/tools/ping`)<br>• **Insecure Deserialization** (`[CWE-502]` in `/api/cluster/state/load`)<br>• **Outdated Components** (`[CWE-1104]` in `Server: Apache/2.2.8 PHP/5.2.4`) |

---

## 2. Directory Structure & Files Created

```
web_targets/
├── __init__.py
├── runner.py                   # Master multi-threaded runner (starts ports 8001-8004)
├── target1_ecommerce/          # Target 01 (Port 8001)
│   ├── app.py                  # FastAPI app with SQLite product & review DB
│   └── templates/
│       └── index.html          # Minimal VoltMart Storefront UI
├── target2_fintech/            # Target 02 (Port 8002)
│   ├── app.py                  # FastAPI app with FX rates & webhook dispatcher
│   └── templates/
│       └── index.html          # Minimal ApexBank Corporate Portal UI
├── target3_healthcare/         # Target 03 (Port 8003)
│   ├── app.py                  # FastAPI app with clinical records & XML parser
│   ├── data/
│   │   └── patient_1001.txt    # Sample clinical chart for LFI demonstration
│   └── templates/
│       └── index.html          # Minimal PulseHealth Hospital UI
└── target4_devops/             # Target 04 (Port 8004)
    ├── app.py                  # FastAPI app with ping RCE & pickle deserializer
    └── templates/
        └── index.html          # Minimal CloudOps Infrastructure UI
```

---

## 3. Launching & Managing the Targets

### Single-Command Batch Launcher
Run the new batch launcher from the project root:
```cmd
start_targets.bat
```

### Command-Line Master Runner
```bash
# 1. Start all 4 targets simultaneously:
python web_targets/runner.py

# 2. Perform automated health check across all 4 ports:
python web_targets/runner.py --health

# 3. Launch an individual target (e.g. Target 2 only on port 8002):
python web_targets/runner.py --target 2
```

---

## 4. Integration with AegisAppSec Console

1. **Scanner Workbench ([`frontend/templates/scanner_console.html`](file:///c:/Users/Dell/Desktop/Projects/CyberSecurityProjects/project/frontend/templates/scanner_console.html))**:
   - The verified target selector now includes all 4 targets as presets:
     - `http://127.0.0.1:8001` (Target 01: VoltMart E-Commerce Store)
     - `http://127.0.0.1:8002` (Target 02: ApexBank Treasury & FX API)
     - `http://127.0.0.1:8003` (Target 03: PulseHealth Hospital EHR)
     - `http://127.0.0.1:8004` (Target 04: CloudOps Infrastructure Console)
2. **Landing Page Dashboard ([`frontend/index.html`](file:///c:/Users/Dell/Desktop/Projects/CyberSecurityProjects/project/frontend/index.html))**:
   - The quick-select dropdown allows 1-click selection of any of the 4 targets for immediate scanning.
3. **Domain Governance ([`backend/app/routers/target_router.py`](file:///c:/Users/Dell/Desktop/Projects/CyberSecurityProjects/project/backend/app/routers/target_router.py))**:
   - Automatically pre-seeds all 4 targets with `is_verified=True` and allows instant registration of any `localhost:*` or `127.0.0.1:*` ports without requiring manual verification tokens.

---

## 5. Verification Results

- **Multi-Target Health Matrix**:
  ```
  ====================================================================
    AEGIS APPSEC // MULTI-TARGET TESTBED HEALTH MATRIX
  ====================================================================
    [+] Target 1: VoltMart Electronics Store   | Port 8001 -> HTTP 200 (ONLINE)
        Vectors: CWE-89 (SQLi), CWE-79 (XSS), CWE-352 (CSRF), CWE-639 (IDOR)
    [+] Target 2: ApexBank Treasury & FX API   | Port 8002 -> HTTP 200 (ONLINE)
        Vectors: CWE-918 (SSRF), CWE-287 (Auth), CWE-601 (Redirect), CWE-200 (Info)
    [+] Target 3: PulseHealth Hospital EHR     | Port 8003 -> HTTP 200 (ONLINE)
        Vectors: CWE-22 (LFI/Traversal), CWE-611 (XXE), CWE-942 (CORS), CWE-16 (Misconfig)
    [+] Target 4: CloudOps Cluster Console     | Port 8004 -> HTTP 200 (ONLINE)
        Vectors: CWE-78 (CMDi), CWE-502 (Deser), CWE-1104 (Outdated), CWE-200 (Info)
  ====================================================================
  ```
- **Vulnerability Verification Script (`scratch/test_targets_vulns.py`)**: All 14 vulnerability probes across all 4 targets verified functional.
- **Full Pytest Suite (`pytest tests/`)**: **39 passed in 2.88s** (all 35 platform tests + 4 new web target integration tests).
