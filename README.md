# AegisAppSec // Autonomous DAST & Real-Time WAF Defense Platform

[![Security: OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010-blue)](https://owasp.org/www-project-top-ten/)
[![Backend: FastAPI](https://img.shields.io/badge/Backend-FastAPI%20(Python)-009688)](https://fastapi.tiangolo.com/)
[![CVSS: v3.1 Scoring](https://img.shields.io/badge/CVSS-v3.1%20Standard-red)](https://www.first.org/cvss/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🌟 Executive Overview & Mission

An enterprise e-commerce platform gearing up for a multi-million-dollar Black Friday flash sale maintains extensive customer portals, supplier portals, and dynamic product catalogs. A coordinated syndicate of cybercriminals targets the platform with automated fuzzers and manual payload craft, probing for SQL Injection, Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), and Cross-Site Request Forgery (CSRF) in search query parameters, feedback forms, and profile upload endpoints.

Commercial DAST scanners (Burp Suite Enterprise, OWASP ZAP) take hours to complete crawl cycles, produce excessive false positives, and fail to defend against double URL-encoding and unicode evasion.

**AegisAppSec** solves this by delivering an autonomous, lightweight DAST vulnerability analyzer, real-time ASGI WAF defense middleware, interactive exploit reproduction engine, and developer remediation hub — all unified into a single startup-ready platform.

---

## 🛡️ Key Features & Capabilities

### 1. Autonomous DAST Vulnerability Scanner
- **Targeted OWASP Top 10 Detectors**:
  - **SQL Injection (SQLi) [CWE-89]**: Error-based, boolean-blind tautologies (`' OR '1'='1`), UNION-based column extraction, time-based blind delay differential.
  - **Cross-Site Scripting (XSS) [CWE-79]**: Stored and reflected script tags, inline DOM event handlers (`<img onerror>`), SVG contexts, and nested tag evasion.
  - **Server-Side Request Forgery (SSRF) [CWE-918]**: Probes AWS EC2 IMDSv1 (`169.254.169.254`), GCP metadata, internal loopback admin gateways (`127.0.0.1`), decimal and hex IP representations.
  - **Cross-Site Request Forgery (CSRF) [CWE-352]**: Tests state-changing transactions for missing anti-CSRF tokens and missing `SameSite` protections.
  - **Insecure Direct Object References (IDOR) [CWE-639]**: Automated horizontal privilege escalation checks traversing tenant order records.
- **Asynchronous Execution Matrix**: Concurrent non-blocking probes via `asyncio` and `httpx.AsyncClient` with real-time WebSocket log streaming.

### 2. Multi-Stage Evasion Normalizer & Regex Signatures
- **Recursive URL Multi-Decoding**: Defeats `%2527` (double URL encoded `'`) and `%253C` bypass tricks.
- **Unicode Homoglyph Normalization (NFKC)**: Neutralizes full-width and lookalike characters.
- **Null-Byte Injection Stripping**: Automatically purges `%00` and `\x00` payloads.
- **SQL Inline Comment Stripping**: Unmasks obfuscations like `1'/**/OR/**/'1'='1'/**/--`.

### 3. Aegis-Shield WAF Middleware (4 Dynamic Modes)
- **`OFF`**: Transparent pass-through, allowing the simulated Black Friday testbed to operate in vulnerable mode.
- **`DETECT`**: Pass-through with security alert headers and real-time telemetry logging.
- **`BLOCK`**: Immediate HTTP 403 Forbidden rejection with a cryptographic Incident ID and triggered rule signature.
- **`SANITIZE`**: Contextual output encoding and input neutralization before passing to backend handlers.

### 4. Platform Self-Defense & Hardening
- **Anti-SSRF Target Guardrails**: Validates target URLs before scanning; strictly forbids external users from coercing the scanner into attacking cloud metadata or sensitive local daemons.
- **Enterprise Security Headers**: Strict Content Security Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, and server cloaking (`Server: Aegis-Gateway/Hardened`).
- **Sliding-Window Rate Limiting**: In-memory rate limiter protecting all platform endpoints against DoS floods.
- **Safe Error Masking**: Suppresses internal stack traces and database internal diagnostics for platform security.

### 5. CVSS v3.1 Scoring & Reproducible PoC Exploits
- Calculates exact CVSS v3.1 Base Scores, Exploitability sub-scores, Impact sub-scores, and vector strings (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- Produces copyable `curl` commands with exact HTTP headers and payloads.
- Displays raw HTTP Request vs. Vulnerable HTTP Response side-by-side diffs.

### 6. Multi-Language Developer Remediation Hub
- Full remediation manuals and before-and-after code diffs across:
  - **Python** (FastAPI / Parameterized SQLite / SQLAlchemy / html.escape)
  - **Node.js** (Express / MySQL2 prepared statements / DOMPurify)
  - **PHP** (PDO Prepared Statements / htmlspecialchars)
  - **Go** (database/sql parameterized queries / template.HTMLEscapeString)

---

## 🏗️ Architecture

```
                                    +-----------------------------------------+
                                    |    Aegis Cyber Operations Dashboard     |
                                    |  (Glassmorphic Dark UI + WebSocket HUD) |
                                    +--------------------+--------------------+
                                                         |
                                 REST API & WebSockets   |
                                                         v
                                    +--------------------+--------------------+
                                    |      FastAPI Application Engine         |
                                    |  (Security Headers + Rate Limiter)      |
                                    +--------------------+--------------------+
                                                         |
                           +-----------------------------+-----------------------------+
                           |                                                           |
                           v                                                           v
       +-------------------+-------------------+               +-----------------------+-----------------------+
       |     Autonomous DAST Scanner Engine    |               |         Aegis-Shield WAF Middleware           |
       |  - Anti-SSRF Target Validator         |               |  - Evasion Normalizer (Double URL, Unicode)   |
       |  - Heuristic OWASP Top 10 Detectors   |               |  - Regex Signature Engine (SQLi, XSS, SSRF)   |
       |  - CVSS v3.1 Scoring Calculator       |               |  - 4 Modes: OFF / DETECT / BLOCK / SANITIZE   |
       |  - PoC Exploit & cURL Generator       |               |  - Real-Time Attack Telemetry Hub             |
       +-------------------+-------------------+               +-----------------------+-----------------------+
                           |                                                           |
                           +-----------------------------+-----------------------------+
                                                         |
                                                         v
                                    +--------------------+--------------------+
                                    |    CyberMart E-Commerce Web Target      |
                                    |    (In-Memory SQLite Flash Sale DB)     |
                                    +-----------------------------------------+
```

---

## 🚀 Quickstart & Deployment

### Option A: Standalone Local Mode (Zero Docker Setup)
```bash
# 1. Install dependencies
pip install -r backend/requirements.txt

# 2. Start server (Windows: double-click start.bat)
python backend/run.py
```
- **Platform Cyber Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger / OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **CyberMart Testbed Storefront**: [http://127.0.0.1:8000/api/shop](http://127.0.0.1:8000/api/shop)

### Option B: Enterprise Multi-Container Stack (Docker Compose)
Orchestrates four resilient microservices:
1. **`web`**: FastAPI ASGI Core, WAF Shield, and Frontend UI (Port 8000)
2. **`db`**: MySQL 8.0 Enterprise Relational Store (Port 3306)
3. **`redis`**: In-Memory Message Broker & Cache (Port 6379)
4. **`celery_worker`**: Distributed Background Task Engine for Large-Scale Scans

```bash
# Windows: double-click docker-start.bat, or run:
docker-compose up --build
```

---

## 🖥️ Platform UI Pages & Workbenches

1. **🎯 Target Domain Governance (`/targets`)**:
   - Register internal/production web assets.
   - Prove domain authorization via HTTP `/.well-known/aegis-verification.txt`, HTML `<meta>`, or DNS TXT.
   - Strict guardrails preventing unauthorized vulnerability probes against unverified hosts.
2. **⚡ Autonomous DAST Scanner (`/scanner`)**:
   - Deep dynamic crawling and injection probing (SQLi, XSS, SSRF, CSRF, IDOR).
   - Real-time WebSocket terminal log streaming and execution matrix.
3. **🔍 Vulnerability Triage & PoC (`/vulnerabilities`)**:
   - Filter by severity (Critical, High, Medium, Low).
   - Instant 1-click **Copy Jira / GitHub Issue** formatted Markdown ticket.
   - Side-by-side Raw HTTP Request vs. Vulnerable Server Response diff viewer.
4. **📜 Scan History & Regression Diff (`/history`)**:
   - Compare any two scan runs (Current vs. Baseline) to identify newly introduced vulnerabilities or verified fixes.
5. **🛡️ WAF Radar & Shield (`/waf`)**:
   - Live attack radar, intercepted request counts, and 4-mode defense switcher (`OFF`, `DETECT`, `BLOCK`, `SANITIZE`).
6. **🧩 Virtual Patching Studio (`/waf-rules`)**:
   - Deploy instant zero-day regex virtual patches into the live inspection engine.
   - Interactive live payload simulation sandbox with match highlights.
7. **📋 Compliance & Audit (`/compliance`)**:
   - Real-time scoring against **OWASP Top 10 (2021)** and **PCI-DSS 4.0** (Requirement 6.4.1/6.4.2).
8. **👥 Team & RBAC Governance (`/team`)**:
   - Team member roster, invite colleague dialog, and interactive Role-Based Access Control matrix.
9. **🔑 CI/CD & API Keys (`/apikeys`)**:
   - Manage automated pipeline tokens (`aegis_live_...`).
   - Copyable GitHub Actions YAML snippet for automated PR regression gating.
   - Slack / Microsoft Teams incident webhooks.
10. **📑 Executive Report Studio (`/report`)**:
    - Print-ready HTML/PDF executive audit document with CVSS v3.1 vectors.
    - 1-click export to Machine JSON, CSV Spreadsheet, and GitHub Markdown.
11. **🔐 Identity & IAM Portal (`/auth`)**:
    - Dedicated IAM workbench with operator profile cards, JWT status, and 1-click persona switching (SecOps Admin, Offensive Pentester, AppSec Developer).
12. **🛒 CyberMart Testbed (`/storefront`)**:
    - Realistic Black Friday e-commerce application with dynamic catalog search, customer reviews, and mock cloud metadata.
13. **🛠️ Developer Remediation Hub (`/remediation`)**:
    - Interactive before-and-after secure code recipes across Python, Node.js, PHP, and Go.

---

## ⚙️ Running Automated Tests
Run pytest across all 29 automated test suites:
```bash
python -m pytest tests/ -o pythonpath=backend -v
```

---

## 📜 Compliance & Standards
- **OWASP Top 10 (2021)**: A01:2021, A03:2021, A10:2021
- **PCI-DSS 4.0**: Requirement 6.4.1 (Public-facing app reviews) & 6.4.2 (Automated WAF defense)
- **CVSS v3.1 Standard**: FIRST.org standard metrics calculator
- **CWE Top 25**: CWE-89, CWE-79, CWE-918, CWE-352, CWE-639

---

*AegisAppSec is engineered for security researchers, penetration testers, corporate security operations centers, and DevSecOps engineering teams.*
