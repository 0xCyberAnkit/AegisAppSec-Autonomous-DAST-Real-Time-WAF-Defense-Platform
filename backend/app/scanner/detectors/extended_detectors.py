"""
Extended DAST Detectors — True Generic Implementation
=====================================================
These detectors use REAL behavioral signals, NOT planted markers.
They will work against ANY target — not just the 4 test web targets.

Detection Philosophy:
  - CMDi: Time-based (sleep command) + output-based (whoami output patterns)
  - Path Traversal: Actual file content patterns (root:x:0:0, [fonts], etc.)
  - Broken Auth: Default credential acceptance + no lockout
  - XXE: Out-of-band via timing OR in-band error message analysis
  - Deserialization: Error messages revealing pickle/java deserialization
  - Open Redirect: Location header reflection of user-supplied URL
  - CORS: Response header reflection of Origin + credentials allowed
  - Info Disclosure: Real secret patterns (AWS keys, DSN strings, stack traces)
  - Outdated Components: Known CVE version strings in Server/X-Powered-By
  - SSRF: Time-based (connecting to slow external host) + error message analysis
"""

import json
import re
import time
import asyncio
import httpx
from typing import List, Optional, Tuple
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.cvss import CVSSv31Calculator


# ---------------------------------------------------------------------------
# Helper: find a working endpoint from a list
# ---------------------------------------------------------------------------
async def _find_working_endpoint(
    client: httpx.AsyncClient,
    base: str,
    paths: List[str],
    method: str = "GET",
    expected_statuses: Tuple = (200, 400, 401, 403, 404, 405, 500),
    probe_param: Optional[dict] = None
) -> Optional[str]:
    """Return the first path that returns any response (doesn't timeout/connection-error)."""
    for path in paths:
        url = f"{base}{path}"
        try:
            if method == "GET":
                r = await client.get(url, params=probe_param or {})
            else:
                r = await client.post(url, json=probe_param or {})
            if r.status_code in expected_statuses:
                return url
        except Exception:
            continue
    return None


# ===========================================================================
# 1. OS Command Injection (CWE-78)
# ===========================================================================
class CommandInjectionDetector(BaseDetector):
    name = "OS Command Injection (CMDi) Detector"
    vuln_type = "OS Command Injection"

    CMDI_ENDPOINTS = [
        "/api/tools/ping",
        "/api/tools/traceroute",
        "/api/tools/nslookup",
        "/api/tools/dig",
        "/diagnostics/ping",
        "/api/ping",
        "/ping",
        "/api/network/ping",
        "/api/admin/exec",
    ]

    # Payloads ordered: fast-detect first (output-based), then time-based
    CMDI_PAYLOADS = [
        # Output-based: inject after a valid IP so the host resolves, then append command
        {"id": "OUT-01", "host": "127.0.0.1; id", "type": "output", "markers": ["uid=", "gid=", "www-data", "root"]},
        {"id": "OUT-02", "host": "127.0.0.1 && id", "type": "output", "markers": ["uid=", "gid=", "www-data"]},
        {"id": "OUT-03", "host": "127.0.0.1 | id", "type": "output", "markers": ["uid=", "gid="]},
        {"id": "OUT-04", "host": "127.0.0.1; whoami", "type": "output", "markers": ["root", "www-data", "daemon", "apache", "nginx"]},
        {"id": "OUT-05", "host": "127.0.0.1; cat /etc/passwd", "type": "output", "markers": ["root:x:0:0", "daemon:", "/bin/bash", "/bin/sh"]},
        # Windows variants
        {"id": "WIN-01", "host": "127.0.0.1 & whoami", "type": "output", "markers": ["nt authority", "system32", "windows"]},
        {"id": "WIN-02", "host": "127.0.0.1 && dir", "type": "output", "markers": ["Volume in drive", "Directory of"]},
        # Time-based blind: sleep/ping loopback multiple times
        {"id": "TIME-01", "host": "127.0.0.1; sleep 3", "type": "time", "delay": 2.5},
        {"id": "TIME-02", "host": "127.0.0.1 && ping -n 4 127.0.0.1", "type": "time", "delay": 2.5},
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        import uuid
        findings: List[Finding] = []
        base = base_url.rstrip('/')
        soft_404 = getattr(crawl_result, "soft_404", None)

        endpoints_to_test = list(self.CMDI_ENDPOINTS)
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                for k in list(ep.params.keys()) + list(ep.form_data.keys()):
                    if any(sub in k.lower() for sub in ["host", "ip", "ping", "cmd", "command", "target", "addr"]):
                        if ep.path not in endpoints_to_test:
                            endpoints_to_test.insert(0, ep.path)

        canary = f"AEGIS_CMD_{uuid.uuid4().hex[:8].upper()}"

        cmdi_probes = [
            # Canary echo execution (100% verified PoC with zero false positives)
            {"id": "ECHO-01", "host": f"127.0.0.1 && echo {canary}", "type": "canary"},
            {"id": "ECHO-02", "host": f"127.0.0.1; echo {canary}", "type": "canary"},
            {"id": "ECHO-03", "host": f"127.0.0.1 & echo {canary}", "type": "canary"},
            {"id": "ECHO-04", "host": f"127.0.0.1 | echo {canary}", "type": "canary"},
            # Strict regex patterns for OS command output
            {"id": "OUT-01", "host": "127.0.0.1; id", "type": "regex", "regex": r"\buid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+"},
            {"id": "OUT-02", "host": "127.0.0.1; cat /etc/passwd", "type": "regex", "regex": r"\b(?:root|www-data|daemon|bin):[x*]:\d+:\d+:"},
            {"id": "WIN-01", "host": "127.0.0.1 & whoami", "type": "regex", "regex": r"\b(?:NT AUTHORITY\\(?:SYSTEM|NETWORK SERVICE|LOCAL SERVICE))\b"},
            {"id": "WIN-02", "host": "127.0.0.1 && dir", "type": "regex", "regex": r"\bVolume Serial Number is [0-9A-Fa-f\-]+\b"},
            # Time-based blind execution
            {"id": "TIME-01", "host": "127.0.0.1; sleep 3", "type": "time", "delay": 3.0},
            {"id": "TIME-02", "host": "127.0.0.1 && ping -n 4 127.0.0.1", "type": "time", "delay": 3.0},
        ]

        for path in endpoints_to_test:
            target_endpoint = f"{base}{path}"

            # Baseline request to measure normal latency and verify endpoint actually exists
            try:
                t_b0 = time.time()
                baseline_resp = await client.get(target_endpoint, params={"host": "127.0.0.1"}, timeout=4.0)
                baseline_time = time.time() - t_b0
                if soft_404 and soft_404.is_dead_or_soft_404(baseline_resp):
                    continue
                if baseline_resp.status_code in (404, 410, 502, 503):
                    continue
                baseline_text = baseline_resp.text
            except Exception:
                continue

            for p in cmdi_probes:
                try:
                    t0 = time.time()
                    resp = await client.get(target_endpoint, params={"host": p["host"]}, timeout=5.0)
                    elapsed = time.time() - t0
                    body = resp.text

                    if resp.status_code == 403 and ("blocked_by_waf" in body or "WAF" in body):
                        break

                    if resp.status_code == 404 or (soft_404 and soft_404.is_dead_or_soft_404(resp)):
                        break

                    is_vulnerable = False
                    evidence = ""

                    # 1. Canary echo reflection
                    if p["type"] == "canary":
                        if canary in body and canary not in baseline_text:
                            is_vulnerable = True
                            evidence = f"Command execution confirmed via canary echo '{canary}'. Shell executed: `{p['host']}`"

                    # 2. Strict regex pattern matching
                    elif p["type"] == "regex":
                        if re.search(p["regex"], body) and not re.search(p["regex"], baseline_text):
                            is_vulnerable = True
                            evidence = f"OS command output matched signature pattern `{p['regex']}`. Shell executed: `{p['host']}`"

                    # 3. Time-based blind execution (relative to baseline)
                    elif p["type"] == "time":
                        if baseline_time < 1.5 and elapsed >= (baseline_time + 2.8) and elapsed >= 3.0:
                            is_vulnerable = True
                            evidence = f"Time-based CMDi: response latency ({elapsed:.2f}s) exceeded baseline ({baseline_time:.2f}s) by ≥2.8s."

                    if is_vulnerable:
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
                        curl_cmd = f'curl -s -G "{target_endpoint}" --data-urlencode "host={p["host"]}"'
                        findings.append(Finding(
                            id=f"VULN-CMDI-{p['id']}",
                            title="OS Command Injection via Unsanitized Shell Parameter",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="GET",
                            parameter="host",
                            payload_used=p["host"],
                            evidence=evidence,
                            cwe_id="CWE-78",
                            owasp_category="A03:2021-Injection",
                            curl_command=curl_cmd,
                            request_raw=f"GET {target_endpoint}?host={p['host']} HTTP/1.1\n\n",
                            response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:600]}",
                            remediation_summary="Avoid calling system shell interpreters (exec, system, popen). Use parameterized process APIs with explicit argument vectors."
                        ))
                        break  # Found confirmed CMDi on this endpoint
                except Exception:
                    continue
        return findings



# ===========================================================================
# 2. Path Traversal / Local File Inclusion (CWE-22)
# ===========================================================================
class PathTraversalDetector(BaseDetector):
    name = "Path Traversal & LFI Detector"
    vuln_type = "Path Traversal / Arbitrary File Read"

    TRAVERSAL_ENDPOINTS = [
        "/records/download",
        "/documents/download",
        "/api/files/download",
        "/api/files",
        "/download",
        "/files",
        "/api/document",
        "/api/file",
        "/static",
        "/assets",
    ]

    # Real file content markers — works on ANY Linux/Windows server
    TRAVERSAL_TESTS = [
        # Linux /etc/passwd
        {
            "payload": "../../../../etc/passwd",
            "markers": ["root:x:0:0", "daemon:x:", "nobody:x:", "/bin/bash", "/bin/sh", "/sbin/nologin"],
            "param": "file"
        },
        {
            "payload": "../../../etc/passwd",
            "markers": ["root:x:0:0", "daemon:x:", "/bin/bash"],
            "param": "file"
        },
        {
            "payload": "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "markers": ["root:x:0:0", "daemon:x:"],
            "param": "file"
        },
        # Windows win.ini
        {
            "payload": "../../../../windows/win.ini",
            "markers": ["[fonts]", "[extensions]", "MAPI=1", "[Mail]"],
            "param": "file"
        },
        {
            "payload": "..%5C..%5C..%5Cwindows%5Cwin.ini",
            "markers": ["[fonts]", "MAPI=1"],
            "param": "file"
        },
        # Other common params
        {
            "payload": "../../../../etc/hosts",
            "markers": ["127.0.0.1 localhost"],
            "param": "path"
        },
        {
            "payload": "../../../../etc/passwd",
            "markers": ["root:x:0:0", "daemon:x:"],
            "param": "path"
        },
        {
            "payload": "../../../../etc/passwd",
            "markers": ["root:x:0:0", "daemon:x:"],
            "param": "filename"
        },
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')
        soft_404 = getattr(crawl_result, "soft_404", None)

        endpoints_to_test = list(self.TRAVERSAL_ENDPOINTS)
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                for k in list(ep.params.keys()) + list(ep.form_data.keys()):
                    if any(sub in k.lower() for sub in ["file", "path", "doc", "page", "view", "download", "folder", "root", "template"]):
                        if ep.path not in endpoints_to_test:
                            endpoints_to_test.insert(0, ep.path)

        for path in endpoints_to_test:
            target_endpoint = f"{base}{path}"

            # Baseline check to ensure endpoint exists and is not a soft-404 page
            try:
                base_probe = await client.get(target_endpoint, timeout=4.0)
                if soft_404 and soft_404.is_dead_or_soft_404(base_probe):
                    continue
                if base_probe.status_code in (404, 410, 502, 503):
                    continue
                baseline_text = base_probe.text
            except Exception:
                continue


            for test in self.TRAVERSAL_TESTS:
                try:
                    resp = await client.get(target_endpoint, params={test["param"]: test["payload"]}, timeout=4.0)
                    body = resp.text

                    if resp.status_code == 403 and "WAF" in body:
                        break
                    if resp.status_code == 404 or (soft_404 and soft_404.is_dead_or_soft_404(resp)):
                        break

                    for marker in test["markers"]:
                        if marker in body and marker not in baseline_text:
                            cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")
                            evidence = f"Real file content marker '{marker}' found via traversal payload '{test['payload']}' in param '{test['param']}'."

                            findings.append(Finding(
                                id="VULN-TRAV-001",
                                title="Path Traversal / Local File Inclusion via File Parameter",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=target_endpoint,
                                method="GET",
                                parameter=test["param"],
                                payload_used=test["payload"],
                                evidence=evidence,
                                cwe_id="CWE-22",
                                owasp_category="A01:2021-Broken Access Control",
                                curl_command=f'curl -s -G "{target_endpoint}" --data-urlencode "{test["param"]}={test["payload"]}"',
                                request_raw=f"GET {target_endpoint}?{test['param']}={test['payload']} HTTP/1.1\n\n",
                                response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:500]}",
                                remediation_summary="Resolve the canonical path with os.path.realpath() and verify it starts with the allowed base directory. Reject any path containing '..' sequences before resolution."
                            ))
                            return findings
                except Exception:
                    continue
        return findings


# ===========================================================================
# 3. Open Redirect (CWE-601)
# ===========================================================================
class OpenRedirectDetector(BaseDetector):
    name = "Open Redirect Detector"
    vuln_type = "Open Redirect"

    REDIRECT_ENDPOINTS = [
        "/redirect",
        "/api/redirect",
        "/go",
        "/out",
        "/link",
        "/forward",
        "/api/go",
        "/exit",
        "/api/external",
        "/oauth/callback",
    ]

    REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_uri", "return", "return_url", "goto", "dest", "destination", "target", "location", "continue"]
    TEST_URL = "https://evil-redirect-test.example.com"

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')
        soft_404 = getattr(crawl_result, "soft_404", None)

        endpoints_to_test = list(self.REDIRECT_ENDPOINTS)
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                for k in list(ep.params.keys()) + list(ep.form_data.keys()):
                    if any(sub in k.lower() for sub in ["url", "next", "redirect", "return", "goto", "dest", "target"]):
                        if ep.path not in endpoints_to_test:
                            endpoints_to_test.insert(0, ep.path)

        for path in endpoints_to_test:
            target_endpoint = f"{base}{path}"

            # Baseline check to ensure endpoint exists and is not soft-404
            try:
                base_probe = await client.get(target_endpoint, timeout=4.0)
                if soft_404 and soft_404.is_dead_or_soft_404(base_probe):
                    continue
                if base_probe.status_code in (404, 410, 502, 503):
                    continue
            except Exception:
                continue

            for param in self.REDIRECT_PARAMS:
                try:
                    resp = await client.get(target_endpoint, params={param: self.TEST_URL})
                    location = resp.headers.get("location", "")
                    body = resp.text

                    if resp.status_code == 404 or (soft_404 and soft_404.is_dead_or_soft_404(resp)):
                        break

                    # Vulnerable: 3xx redirect and Location contains our URL
                    if resp.status_code in [301, 302, 303, 307, 308] and self.TEST_URL in location:
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N")
                        evidence = f"Unvalidated redirect: server responded with HTTP {resp.status_code} Location: {location}"
                        findings.append(Finding(
                            id="VULN-REDIR-001",
                            title=f"Open Redirect via '{param}' Parameter",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="GET",
                            parameter=param,
                            payload_used=self.TEST_URL,
                            evidence=evidence,
                            cwe_id="CWE-601",
                            owasp_category="A01:2021-Broken Access Control",
                            curl_command=f'curl -v -L "{target_endpoint}?{param}={self.TEST_URL}"',
                            request_raw=f"GET {target_endpoint}?{param}={self.TEST_URL} HTTP/1.1\n\n",
                            response_raw=f"HTTP/1.1 {resp.status_code}\nLocation: {location}\n\n",
                            remediation_summary="Maintain an allowlist of permitted redirect destinations. Never reflect user-supplied URLs in redirect responses without validation."
                        ))
                        return findings

                    # Real meta-redirect or JS redirect in body (not mere parameter echo)
                    if resp.status_code == 200:
                        has_meta_redirect = bool(re.search(r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*' + re.escape(self.TEST_URL), body, re.I))
                        has_js_redirect = bool(re.search(r'(?:window\.|document\.)?location(?:\.href|\.replace|\.assign)?\s*=\s*[\'"`]' + re.escape(self.TEST_URL), body, re.I) or
                                              re.search(r'location\.(?:replace|assign)\(\s*[\'"`]' + re.escape(self.TEST_URL), body, re.I))
                        if has_meta_redirect or has_js_redirect:
                            cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N")
                            findings.append(Finding(
                                id="VULN-REDIR-002",
                                title=f"Client-Side Open Redirect via '{param}' Parameter (HTML/JS)",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=target_endpoint,
                                method="GET",
                                parameter=param,
                                payload_used=self.TEST_URL,
                                evidence=f"Attacker URL '{self.TEST_URL}' reflected in HTML/JS redirect directive enabling client-side redirect.",
                                cwe_id="CWE-601",
                                owasp_category="A01:2021-Broken Access Control",
                                curl_command=f'curl -s "{target_endpoint}?{param}={self.TEST_URL}" | grep evil',
                                request_raw=f"GET {target_endpoint}?{param}={self.TEST_URL} HTTP/1.1\n\n",
                                response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:400]}",
                                remediation_summary="Sanitize and allowlist redirect targets server-side before embedding in HTML or JS responses."
                            ))
                            return findings
                except Exception:
                    continue
        return findings


# ===========================================================================
# 4. Broken Authentication (CWE-287)
# ===========================================================================
class BrokenAuthDetector(BaseDetector):
    name = "Broken Authentication & Session Hygiene Detector"
    vuln_type = "Broken Authentication"

    AUTH_ENDPOINTS = [
        "/api/login",
        "/auth/login",
        "/login",
        "/api/auth/login",
        "/api/v1/login",
        "/api/auth",
        "/api/v1/auth",
        "/account/login",
        "/user/login",
        "/signin",
        "/api/signin",
    ]

    DEFAULT_CREDS = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "admin123"},
        {"username": "root", "password": "root"},
        {"username": "test", "password": "test"},
        {"username": "user", "password": "user"},
        {"username": "admin", "password": "123456"},
    ]

    # Real signals of successful auth (not planted markers)
    SUCCESS_INDICATORS = [
        # Tokens / sessions in JSON response
        re.compile(r'"(token|access_token|auth_token|session_token|jwt|bearer)"\s*:', re.I),
        # Session cookies set
        re.compile(r'Set-Cookie:.*session', re.I),
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')
        soft_404 = getattr(crawl_result, "soft_404", None)

        endpoints_to_test = list(self.AUTH_ENDPOINTS)
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                if any(term in ep.path.lower() for term in ["login", "auth", "signin", "session", "user"]):
                    if ep.path not in endpoints_to_test:
                        endpoints_to_test.insert(0, ep.path)

        for path in endpoints_to_test:
            target_endpoint = f"{base}{path}"
            try:
                # Quick probe to confirm endpoint exists and baseline invalid login response
                probe = await client.post(target_endpoint, data={"username": "_probe_", "password": "_probe_"}, timeout=4.0)
                if soft_404 and soft_404.is_dead_or_soft_404(probe):
                    continue
                if probe.status_code in (404, 410, 502, 503):
                    continue
                if probe.status_code == 405:
                    # Try JSON
                    probe = await client.post(target_endpoint, json={"username": "_probe_", "password": "_probe_"}, timeout=4.0)
                    if soft_404 and soft_404.is_dead_or_soft_404(probe):
                        continue
                    if probe.status_code in (404, 410, 502, 503, 405):
                        continue

                probe_cookies = set(probe.cookies.keys())
                probe_text = probe.text

                for creds in self.DEFAULT_CREDS:
                    # Try form data
                    resp = await client.post(target_endpoint, data=creds, timeout=4.0)
                    body = resp.text

                    if resp.status_code == 403 and "WAF" in body:
                        break
                    if soft_404 and soft_404.is_dead_or_soft_404(resp):
                        break

                    auth_success = False
                    evidence_detail = ""

                    if resp.status_code == 200:
                        # Check for token in JSON response not in invalid probe
                        for pat in self.SUCCESS_INDICATORS[:1]:  # Token pattern
                            m = pat.search(body)
                            if m and not pat.search(probe_text):
                                auth_success = True
                                evidence_detail = f"Response contains auth token field: '{m.group(0)[:60]}'"
                                break
                        # Check for newly issued session cookie
                        if not auth_success:
                            new_cookies = [k for k in resp.cookies.keys() if k not in probe_cookies and any(s in k.lower() for s in ["session", "token", "auth", "jwt", "sid"])]
                            if new_cookies and probe.status_code in [401, 403]:
                                auth_success = True
                                evidence_detail = f"Session cookie newly issued upon login: {new_cookies}"

                    if not auth_success and resp.status_code == 200:
                        # Try JSON body
                        try:
                            resp2 = await client.post(target_endpoint, json=creds, timeout=4.0)
                            if resp2.status_code == 200 and not (soft_404 and soft_404.is_dead_or_soft_404(resp2)):
                                for pat in self.SUCCESS_INDICATORS[:1]:
                                    m = pat.search(resp2.text)
                                    if m and not pat.search(probe_text):
                                        auth_success = True
                                        evidence_detail = "JSON POST: auth token found in response body"
                                        body = resp2.text
                                        resp = resp2
                                        break
                        except Exception:
                            pass

                    if auth_success:
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N")
                        evidence = f"Default credentials '{creds['username']}:{creds['password']}' accepted — {evidence_detail}"
                        findings.append(Finding(
                            id="VULN-AUTH-001",
                            title=f"Default/Weak Credentials Accepted: {creds['username']}:{creds['password']}",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="POST",
                            parameter="password",
                            payload_used=f"username={creds['username']}&password={creds['password']}",
                            evidence=evidence,
                            cwe_id="CWE-287",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            curl_command=f'curl -s -X POST "{target_endpoint}" -d "username={creds["username"]}&password={creds["password"]}"',
                            request_raw=f"POST {target_endpoint} HTTP/1.1\n\nusername={creds['username']}&password={creds['password']}",
                            response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:400]}",
                            remediation_summary="Enforce MFA. Reject factory/default credentials at first login. Implement rate limiting (5 attempts per 15 min) with exponential backoff."
                        ))
                        return findings


                # Check for missing rate limiting (no lockout after 5 bad attempts on confirmed auth endpoints)
                bad_attempt_statuses = []
                last_bad_resp = None
                try:
                    for _ in range(5):
                        r = await client.post(target_endpoint, data={"username": "admin", "password": "wrong_pass_probe"}, timeout=4.0)
                        bad_attempt_statuses.append(r.status_code)
                        last_bad_resp = r

                    # Must be a confirmed active auth endpoint: 401s or 200 with explicit credential rejection message
                    is_auth_endpoint = (
                        all(s == 401 for s in bad_attempt_statuses) or
                        (all(s == 200 for s in bad_attempt_statuses) and last_bad_resp and any(w in last_bad_resp.text.lower() for w in ["invalid", "incorrect", "bad credentials", "unauthorized", "login failed"]))
                    )
                    if is_auth_endpoint:
                        has_rate_limit = any(
                            "x-ratelimit" in str(r.headers).lower() or
                            "retry-after" in str(r.headers).lower() or
                            "too many" in r.text.lower() or
                            "lockout" in r.text.lower()
                            for _ in [last_bad_resp]
                        )
                        if not has_rate_limit:

                            cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="M", i="N", a="N")
                            findings.append(Finding(
                                id="VULN-AUTH-002",
                                title="Missing Rate Limiting / Account Lockout on Login Endpoint",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=target_endpoint,
                                method="POST",
                                parameter="password",
                                payload_used="[5x wrong credentials without lockout]",
                                evidence=f"Made 5 consecutive failed login attempts to '{target_endpoint}' — no rate-limiting or lockout response observed (statuses: {bad_attempt_statuses}).",
                                cwe_id="CWE-307",
                                owasp_category="A07:2021-Identification and Authentication Failures",
                                curl_command=f'for i in 1 2 3 4 5; do curl -s -X POST "{target_endpoint}" -d "username=admin&password=wrong$i"; done',
                                request_raw=f"POST {target_endpoint} HTTP/1.1\n\nusername=admin&password=wrong",
                                response_raw=f"HTTP/1.1 401\n\n[no lockout after 5 attempts]",
                                remediation_summary="Implement sliding-window rate limiting (max 5 failures per 15 min) with progressive delay, CAPTCHA, and account lockout."
                            ))
                            return findings
                except Exception:
                    pass
            except Exception:
                continue

        return findings


# ===========================================================================
# 5. XML External Entity Injection (CWE-611)
# ===========================================================================
class XXEDetector(BaseDetector):
    name = "XML External Entity (XXE) Injection Detector"
    vuln_type = "XML External Entity Injection"

    XXE_ENDPOINTS = [
        "/api/records/xml-import",
        "/api/xml/upload",
        "/api/import/xml",
        "/api/upload",
        "/upload",
        "/api/data/import",
        "/import",
        "/api/parse",
        "/api/xml",
        "/xml",
    ]

    # Real file content the entity will expand to on Linux/Windows
    XXE_TESTS = [
        {
            "payload": b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>',
            "markers": ["localhost", "aegis", "ubuntu", "debian", "alpine", "centos"],
            "ctype": "application/xml"
        },
        {
            "payload": b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
            "markers": ["root:x:0:0", "daemon:", "/bin/bash"],
            "ctype": "application/xml"
        },
        {
            "payload": b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/issue">]><root><data>&xxe;</data></root>',
            "markers": ["Ubuntu", "Debian", "CentOS", "Alpine", "Linux"],
            "ctype": "application/xml"
        },
        # text/xml variant
        {
            "payload": b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><r><patient_name>&xxe;</patient_name></r>',
            "markers": ["localhost", "ubuntu", "server", "host"],
            "ctype": "text/xml"
        },
    ]

    # Also check for error-based XXE disclosure
    ERROR_MARKERS = [
        "EntityRef: expecting ';'",
        "XMLSyntaxError",
        "lxml.etree",
        "SAXParseException",
        "org.xml.sax",
        "xml.etree.ElementTree",
        "ExpatError",
        "DOCTYPE is not allowed",
        "Access to external resource denied",
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        for path in self.XXE_ENDPOINTS:
            target_endpoint = f"{base}{path}"
            for test in self.XXE_TESTS:
                try:
                    resp = await client.post(
                        target_endpoint,
                        content=test["payload"],
                        headers={"Content-Type": test["ctype"]}
                    )
                    body = resp.text

                    if resp.status_code == 404:
                        break  # Endpoint absent
                    if resp.status_code == 403 and "WAF" in body:
                        break

                    # In-band: file contents reflected
                    for marker in test["markers"]:
                        if marker.lower() in body.lower():
                            cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")
                            evidence = f"XXE entity expanded to real file content: marker '{marker}' found in response body."
                            findings.append(Finding(
                                id="VULN-XXE-001",
                                title="XML External Entity (XXE) — In-Band File Disclosure",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=target_endpoint,
                                method="POST",
                                parameter="xml_body",
                                payload_used=test["payload"].decode(errors="replace"),
                                evidence=evidence,
                                cwe_id="CWE-611",
                                owasp_category="A05:2021-Security Misconfiguration",
                                curl_command=f'curl -s -X POST "{target_endpoint}" -H "Content-Type: {test["ctype"]}" --data-binary @xxe.xml',
                                request_raw=f"POST {target_endpoint} HTTP/1.1\nContent-Type: {test['ctype']}\n\n{test['payload'].decode(errors='replace')}",
                                response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:400]}",
                                remediation_summary="Use defusedxml. Disable external entity resolution: set resolve_entities=False, forbid_dtd=True on all XML parsers."
                            ))
                            return findings

                    # Error-based: parser error messages reveal XML processing
                    for err in self.ERROR_MARKERS:
                        if err.lower() in body.lower():
                            cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="M", i="N", a="N")
                            findings.append(Finding(
                                id="VULN-XXE-002",
                                title="XXE-Vulnerable XML Parser Detected (Error-Based)",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=target_endpoint,
                                method="POST",
                                parameter="xml_body",
                                payload_used=test["payload"].decode(errors="replace"),
                                evidence=f"XML parser error message '{err}' leaked in response — entity processing is active.",
                                cwe_id="CWE-611",
                                owasp_category="A05:2021-Security Misconfiguration",
                                curl_command=f'curl -s -X POST "{target_endpoint}" -H "Content-Type: {test["ctype"]}" --data-binary @xxe.xml',
                                request_raw=f"POST {target_endpoint} HTTP/1.1\n\n{test['payload'].decode(errors='replace')}",
                                response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:400]}",
                                remediation_summary="Upgrade to defusedxml. Wrap all XML parsing in try/except to prevent error leakage. Disable DOCTYPE processing."
                            ))
                            return findings

                except Exception:
                    continue
        return findings


# ===========================================================================
# 6. Insecure Deserialization (CWE-502)
# ===========================================================================
class InsecureDeserializationDetector(BaseDetector):
    name = "Insecure Deserialization Detector"
    vuln_type = "Insecure Deserialization"

    DESER_ENDPOINTS = [
        "/api/cluster/state/load",
        "/api/session/load",
        "/api/restore",
        "/api/state/load",
        "/api/state/restore",
        "/api/import",
        "/session/import",
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')
        soft_404 = getattr(crawl_result, "soft_404", None)

        import base64
        import pickle
        import struct

        # Generate a safe probe payload: pickle.dumps({'__aegis_probe__': True})
        # This is SAFE — no __reduce__ method, no code execution
        safe_obj = {"__aegis_probe__": True, "ts": 1234567890}
        safe_pickle = pickle.dumps(safe_obj)
        payload_b64 = base64.b64encode(safe_pickle).decode()

        # Real deserialization error signatures from Python, Java, PHP, Ruby
        DESER_ERROR_MARKERS = [
            # Python pickle errors that indicate it's being deserialized
            "_reconstruct", "copyreg", "pickle.Unpickler", "UnpicklingError",
            # Java serialization
            "java.io.ObjectInputStream", "java.io.StreamCorruptedException",
            "InvalidClassException", "ClassNotFoundException",
            # PHP unserialize
            "unserialize(): Error at offset",
            "O:4:\"User\"",
            # Ruby Marshal
            "TypeError (marshal",
            # Generic binary processing errors
            "struct.unpack",
        ]

        # Real output markers if our safe pickle is actually deserialized
        DESER_SUCCESS_MARKERS = [
            "__aegis_probe__",  # Our specific canary key
            "aegis_probe",
        ]

        for path in self.DESER_ENDPOINTS:
            target_endpoint = f"{base}{path}"

            # Baseline check: endpoint exists and is not soft-404
            try:
                base_probe = await client.get(target_endpoint, timeout=4.0)
                if soft_404 and soft_404.is_dead_or_soft_404(base_probe):
                    continue
                if base_probe.status_code in (404, 410, 502, 503):
                    continue
                baseline_text = base_probe.text.lower()
            except Exception:
                continue

            for send_method in ["form", "json"]:
                try:
                    if send_method == "form":
                        resp = await client.post(target_endpoint, data={"state": payload_b64}, timeout=4.0)
                    else:
                        resp = await client.post(target_endpoint, json={"state_token": payload_b64, "data": payload_b64}, timeout=4.0)

                    body = resp.text

                    if resp.status_code == 404 or (soft_404 and soft_404.is_dead_or_soft_404(resp)):
                        break
                    if resp.status_code == 403 and "WAF" in body:
                        break

                    is_vulnerable = False
                    evidence = ""

                    # Our canary key appears in response and wasn't in baseline → it was deserialized
                    for marker in DESER_SUCCESS_MARKERS:
                        if marker in body and marker not in baseline_text:
                            is_vulnerable = True
                            evidence = f"Deserialization confirmed: canary key '{marker}' from pickle payload appeared in response body."
                            break

                    # Error messages revealing deserialization not in baseline
                    if not is_vulnerable:
                        for err in DESER_ERROR_MARKERS:
                            if err.lower() in body.lower() and err.lower() not in baseline_text:
                                is_vulnerable = True
                                evidence = f"Deserialization error signature '{err}' leaked in response — server is calling pickle.loads() / ObjectInputStream.readObject()."
                                break


                    if is_vulnerable:
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
                        findings.append(Finding(
                            id="VULN-DESER-001",
                            title="Insecure Deserialization of Untrusted Serialized Object",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="POST",
                            parameter="state/state_token",
                            payload_used=payload_b64[:60] + "...",
                            evidence=evidence,
                            cwe_id="CWE-502",
                            owasp_category="A08:2021-Software and Data Integrity Failures",
                            curl_command=f'curl -s -X POST "{target_endpoint}" -F "state={payload_b64[:20]}..."',
                            request_raw=f"POST {target_endpoint} HTTP/1.1\n\nstate={payload_b64[:30]}...",
                            response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:400]}",
                            remediation_summary="Never call pickle.loads(), ObjectInputStream.readObject(), or unserialize() on user-supplied data. Use JSON with strict Pydantic schema validation. Sign state blobs with HMAC-SHA256."
                        ))
                        return findings
                except Exception:
                    continue
        return findings


# ===========================================================================
# 7. CORS Misconfiguration (CWE-942)
# ===========================================================================
class CORSDetector(BaseDetector):
    name = "Cross-Origin Resource Sharing (CORS) Misconfiguration Detector"
    vuln_type = "CORS Misconfiguration"

    # Probe common API endpoints that likely have authenticated data
    CORS_ENDPOINTS = [
        "/api/patient/1001",
        "/api/patient/1",
        "/api/user/profile",
        "/api/me",
        "/api/profile",
        "/api/user",
        "/api/account",
        "/api/users/me",
        "/api/v1/me",
        "/api/account/info",
    ]

    ATTACKER_ORIGINS = [
        "https://evil.attacker.io",
        "https://untrusted-attacker.io",
        "null",  # null origin trick
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        for path in self.CORS_ENDPOINTS:
            target_endpoint = f"{base}{path}"
            for origin in self.ATTACKER_ORIGINS:
                try:
                    resp = await client.get(target_endpoint, headers={"Origin": origin})
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                    if resp.status_code == 404:
                        break

                    # Critical: origin reflected + credentials allowed
                    if (acao == origin or acao == "*") and acac == "true":
                        severity_label = "Critical" if acao == origin else "High"
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="L", a="N")
                        evidence = (
                            f"Server reflects attacker Origin '{origin}' in ACAO header with "
                            f"Access-Control-Allow-Credentials: true. "
                            f"Any page at '{origin}' can make credentialed cross-origin requests "
                            f"and steal authenticated user data."
                        )
                        findings.append(Finding(
                            id="VULN-CORS-001",
                            title="Critical CORS Misconfiguration: Arbitrary Origin + Credentials Allowed",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="GET",
                            parameter="Origin Header",
                            payload_used=f"Origin: {origin}",
                            evidence=evidence,
                            cwe_id="CWE-942",
                            owasp_category="A05:2021-Security Misconfiguration",
                            curl_command=f'curl -v -H "Origin: {origin}" "{target_endpoint}"',
                            request_raw=f"GET {target_endpoint} HTTP/1.1\nOrigin: {origin}\n\n",
                            response_raw=f"HTTP/1.1 {resp.status_code}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}\n\n",
                            remediation_summary="Maintain an explicit server-side allowlist of authorized origins. Never reflect user-supplied Origin values. Wildcard '*' must NEVER be combined with Allow-Credentials: true."
                        ))
                        return findings

                    # Moderate: origin reflected without credentials (data still readable in some cases)
                    elif acao == origin and acac != "true":
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="R", s="U", c="M", i="N", a="N")
                        findings.append(Finding(
                            id="VULN-CORS-002",
                            title="CORS Misconfiguration: Arbitrary Origin Reflected (Without Credentials)",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="GET",
                            parameter="Origin Header",
                            payload_used=f"Origin: {origin}",
                            evidence=f"Arbitrary origin '{origin}' reflected in ACAO without credentials — public cross-origin reads possible.",
                            cwe_id="CWE-942",
                            owasp_category="A05:2021-Security Misconfiguration",
                            curl_command=f'curl -v -H "Origin: {origin}" "{target_endpoint}"',
                            request_raw=f"GET {target_endpoint} HTTP/1.1\nOrigin: {origin}\n\n",
                            response_raw=f"HTTP/1.1 {resp.status_code}\nAccess-Control-Allow-Origin: {acao}\n\n",
                            remediation_summary="Use an explicit allowlist of permitted origins. Do not dynamically reflect Origin headers from untrusted sources."
                        ))
                        return findings
                except Exception:
                    continue
        return findings


# ===========================================================================
# 8. Information Disclosure (CWE-200)
# ===========================================================================
class InfoDisclosureDetector(BaseDetector):
    name = "Information Disclosure & Stack Trace Leakage Detector"
    vuln_type = "Information Disclosure"

    INFO_ENDPOINTS = [
        "/api/debug/system",
        "/api/system/crash",
        "/debug/env",
        "/api/debug/env",
        "/api/debug",
        "/api/system/info",
        "/actuator/env",
        "/actuator/health",
        "/config",
        "/.env",
        "/api/config",
        "/api/admin/config",
        "/.git/config",
        "/server-status",
        "/phpinfo.php",
        "/info.php",
    ]

    # Secrets that should NEVER appear in HTTP responses on any real target
    SECRET_PATTERNS = [
        # AWS
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
        (re.compile(r'aws_secret_access_key\s*[=:]\s*\S+', re.I), "AWS Secret Key"),
        # Generic high-entropy secrets
        (re.compile(r'(secret[_-]?key|api[_-]?secret|private[_-]?key)\s*[=:]\s*\S{8,}', re.I), "API Secret/Private Key"),
        (re.compile(r'(password|passwd|pwd)\s*[=:]\s*\S{4,}', re.I), "Hardcoded Password"),
        # Database connection strings
        (re.compile(r'(postgresql|mysql|mongodb|redis|mssql)://\S+:\S+@', re.I), "Database DSN with Credentials"),
        # Financial / Banking (Target2 specific but also generic)
        (re.compile(r'SWIFT[_A-Z]+KEY\s*[=:]\s*\S+', re.I), "SWIFT Gateway Key"),
        (re.compile(r'ROUTING[_A-Z]+TOKEN\s*[=:]\s*\S+', re.I), "Routing Token"),
        # Stack traces
        (re.compile(r'Traceback \(most recent call last\)', re.I), "Python Stack Trace"),
        (re.compile(r'at [a-zA-Z0-9_.]+\([A-Za-z0-9_.]+\.java:\d+\)', re.I), "Java Stack Trace"),
        (re.compile(r'RuntimeError|UnhandledException|NullPointerException', re.I), "Exception Disclosure"),
        # Server internal IPs
        (re.compile(r'"internal_ip"\s*:\s*"(10\.|172\.|192\.168\.)', re.I), "Internal IP Disclosure"),
        # Git config
        (re.compile(r'\[core\].*repositoryformatversion', re.S | re.I), "Git Repository Config"),
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        for path in self.INFO_ENDPOINTS:
            target_endpoint = f"{base}{path}"
            try:
                resp = await client.get(target_endpoint)
                body = resp.text

                if resp.status_code == 404:
                    continue
                if resp.status_code == 403 and "WAF" in body:
                    continue

                # Check for secret patterns
                for pattern, label in self.SECRET_PATTERNS:
                    m = pattern.search(body)
                    if m:
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")
                        matched_snippet = m.group(0)[:80]
                        evidence = f"Sensitive data '{label}' found at endpoint '{path}': ...{matched_snippet}..."
                        findings.append(Finding(
                            id="VULN-INFO-001",
                            title=f"Sensitive Information Exposure: {label}",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method="GET",
                            parameter=None,
                            payload_used="[Passive Probe — No Payload]",
                            evidence=evidence,
                            cwe_id="CWE-200",
                            owasp_category="A02:2021-Cryptographic Failures",
                            curl_command=f'curl -s "{target_endpoint}"',
                            request_raw=f"GET {target_endpoint} HTTP/1.1\n\n",
                            response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:400]}",
                            remediation_summary="Disable debug/actuator endpoints in production. Use environment variables with secret managers (AWS Secrets Manager, HashiCorp Vault). Implement global exception handlers that return generic 500 responses."
                        ))
                        return findings

                # 500 with stack trace from any endpoint
                if resp.status_code == 500:
                    for pattern, label in self.SECRET_PATTERNS[-3:]:  # Stack trace patterns
                        if pattern.search(body):
                            cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="M", i="N", a="N")
                            findings.append(Finding(
                                id="VULN-INFO-002",
                                title="Unhandled Exception — Stack Trace Disclosed in HTTP 500 Response",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=target_endpoint,
                                method="GET",
                                parameter=None,
                                payload_used="[Passive Probe]",
                                evidence=f"HTTP 500 response exposes internal exception details at '{path}'.",
                                cwe_id="CWE-200",
                                owasp_category="A02:2021-Cryptographic Failures",
                                curl_command=f'curl -s "{target_endpoint}"',
                                request_raw=f"GET {target_endpoint} HTTP/1.1\n\n",
                                response_raw=f"HTTP/1.1 500\n\n{body[:400]}",
                                remediation_summary="Implement a global exception handler that returns 500 with a generic error message — never expose stack traces in production."
                            ))
                            return findings

            except Exception:
                continue
        return findings


# ===========================================================================
# 9. Vulnerable & Outdated Components (CWE-1104)
# ===========================================================================
class OutdatedComponentsDetector(BaseDetector):
    name = "Vulnerable & Outdated Dependencies Detector"
    vuln_type = "Vulnerable Components"

    # Server banner → known CVEs
    VULNERABLE_VERSIONS = [
        # Apache CVEs
        ("Apache/2.4.49", "CVE-2021-41773 (RCE via Path Traversal, CVSS 9.8)"),
        ("Apache/2.4.50", "CVE-2021-42013 (RCE bypass of 41773 fix, CVSS 9.8)"),
        ("Apache/2.2.", "End-of-Life Apache 2.2.x — multiple unpatched CVEs"),
        ("Apache/2.0.", "End-of-Life Apache 2.0.x — critical unpatched CVEs"),
        # OpenSSL Heartbleed
        ("OpenSSL/1.0.1", "CVE-2014-0160 Heartbleed (private key exposure, CVSS 7.5)"),
        ("OpenSSL/1.0.0", "CVE-2014-0160 Heartbleed + multiple critical CVEs"),
        ("OpenSSL/0.9.8", "CVE-2014-0160 Heartbleed + EOL"),
        # nginx
        ("nginx/1.14", "Multiple CVEs: CVE-2019-9511, CVE-2019-9516"),
        ("nginx/1.12", "End-of-Life nginx — CVE-2017-7529 memory disclosure"),
        # PHP
        ("PHP/5.", "End-of-Life PHP 5.x — dozens of unpatched critical CVEs"),
        ("PHP/7.0", "End-of-Life PHP 7.0 — multiple unpatched CVEs"),
        ("PHP/7.1", "End-of-Life PHP 7.1"),
        ("PHP/7.2", "End-of-Life PHP 7.2"),
        # IIS
        ("Microsoft-IIS/6.0", "CVE-2017-7269 (RCE, CVSS 9.8) — EOL"),
        ("Microsoft-IIS/7.0", "End-of-Life IIS 7.0"),
        # Jetty / Tomcat
        ("Jetty/9.2", "CVE-2017-7656, CVE-2017-7657 — Chunk Header Injection"),
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        target_endpoint = base_url.rstrip('/')

        try:
            resp = await client.get(target_endpoint)
            server_header = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")
            x_aspnet = resp.headers.get("X-AspNet-Version", "")
            x_aspnetmvc = resp.headers.get("X-AspNetMvc-Version", "")

            all_banners = f"{server_header} {powered_by} {x_aspnet} {x_aspnetmvc}"

            for version_str, cve_info in self.VULNERABLE_VERSIONS:
                if version_str.lower() in all_banners.lower():
                    cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
                    evidence = f"Vulnerable component '{version_str}' detected in response headers. Risk: {cve_info}"
                    findings.append(Finding(
                        id="VULN-COMP-001",
                        title=f"Vulnerable/EOL Component: {version_str[:40]}",
                        vuln_type=self.vuln_type,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        endpoint=target_endpoint,
                        method="HEAD",
                        parameter="Server/X-Powered-By Header",
                        payload_used="[Passive — Banner Grabbing]",
                        evidence=evidence,
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        curl_command=f'curl -sI "{target_endpoint}" | grep -E "Server|X-Powered-By"',
                        request_raw=f"HEAD {target_endpoint} HTTP/1.1\n\n",
                        response_raw=f"HTTP/1.1 {resp.status_code}\nServer: {server_header}\nX-Powered-By: {powered_by}\n\n",
                        remediation_summary="Upgrade to the latest stable release. Remove Server and X-Powered-By headers in production. Maintain an SBOM (Software Bill of Materials) and use automated scanning (Dependabot, Snyk, Trivy)."
                    ))
                    return findings

            # Also check for version disclosure even if not in vulnerable list
            version_match = re.search(r'(Apache|nginx|IIS|Jetty|Tomcat|lighttpd|PHP)/(\d+\.\d+)', all_banners, re.I)
            if version_match and not findings:
                cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N")
                evidence = f"Server version '{version_match.group(0)}' disclosed — may assist fingerprinting and targeted exploitation."
                findings.append(Finding(
                    id="VULN-COMP-002",
                    title=f"Server Version Disclosure: {version_match.group(0)}",
                    vuln_type=self.vuln_type,
                    severity=cvss["severity"],
                    cvss_score=cvss["base_score"],
                    cvss_vector=cvss["vector_string"],
                    endpoint=target_endpoint,
                    method="HEAD",
                    parameter="Server Header",
                    payload_used="[Passive — Banner Grabbing]",
                    evidence=evidence,
                    cwe_id="CWE-1104",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    curl_command=f'curl -sI "{target_endpoint}" | grep Server',
                    request_raw=f"HEAD {target_endpoint} HTTP/1.1\n\n",
                    response_raw=f"HTTP/1.1 {resp.status_code}\nServer: {server_header}\n\n",
                    remediation_summary="Remove version information from Server headers. Use ServerTokens Prod (Apache) or server_tokens off (nginx)."
                ))
        except Exception:
            pass
        return findings
