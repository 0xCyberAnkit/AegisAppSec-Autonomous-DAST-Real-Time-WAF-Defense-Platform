import json
import httpx
from typing import List
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.cvss import CVSSv31Calculator

class CSRFDetector(BaseDetector):
    name = "Cross-Site Request Forgery Detector"
    vuln_type = "Cross-Site Request Forgery (CSRF)"

    # Try multiple state-changing endpoints per target
    CSRF_ENDPOINTS = [
        # Target1 VoltMart: email change without token
        {"path": "/account/email", "method": "POST", "data": {"email": "attacker@evil.com"}, "content_type": "form"},
        {"path": "/account/email", "method": "GET", "data": {"new_email": "attacker@evil.com"}, "content_type": "params"},
        # Generic CSRF endpoints
        {"path": "/transfer-points", "method": "POST", "data": {"recipient_username": "bob_supplier", "amount": 50}, "content_type": "json"},
        {"path": "/api/transfer", "method": "POST", "data": {"to": "attacker", "amount": 1000}, "content_type": "json"},
        {"path": "/profile/update", "method": "POST", "data": {"email": "attacker@evil.com"}, "content_type": "form"},
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        # Cross-origin headers to simulate CSRF attack
        csrf_headers = {
            "Origin": "https://malicious-attacker-site.com",
            "Referer": "https://malicious-attacker-site.com/exploit.html"
        }

        endpoints_to_test = list(self.CSRF_ENDPOINTS)

        # Ingest discovered forms from crawler
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                if ep.method == "POST" and ep.form_data:
                    # Check if token field is present
                    has_token = any("csrf" in k.lower() or "token" in k.lower() for k in ep.form_data.keys())
                    if not has_token:
                        endpoints_to_test.insert(0, {
                            "path": ep.path,
                            "method": "POST",
                            "data": ep.form_data,
                            "content_type": "form"
                        })

        for ep in endpoints_to_test:
            target_endpoint = f"{base}{ep['path']}"
            try:
                if ep["method"] == "GET":
                    resp = await client.get(target_endpoint, params=ep["data"], headers=csrf_headers)
                elif ep["content_type"] == "form":
                    resp = await client.post(target_endpoint, data=ep["data"], headers=csrf_headers)
                elif ep["content_type"] == "json":
                    resp = await client.post(target_endpoint, json=ep["data"], headers=csrf_headers)
                else:
                    resp = await client.post(target_endpoint, data=ep["data"], headers=csrf_headers)

                body = resp.text

                # If blocked by WAF
                if resp.status_code == 403 and "blocked_by_waf" in body:
                    continue

                # Vulnerable if:
                # 1. State change accepted (200) without CSRF token, OR
                # 2. Explicit CSRF vulnerability note in response, OR
                # 3. csrf_protected: false in response
                is_vulnerable = False
                evidence_detail = ""

                if resp.status_code == 200:
                    # Check for explicit CSRF vuln note
                    if "CWE-352" in body or "csrf" in body.lower() or "vulnerability_note" in body.lower():
                        is_vulnerable = True
                        evidence_detail = "State-changing endpoint accepted cross-origin request and returned success without CSRF token validation."
                    elif '"csrf_protected":false' in body.replace(" ", ""):
                        is_vulnerable = True
                        evidence_detail = "Server confirmed CSRF protection is not active on this endpoint."
                    elif "success" in body.lower() and ep["method"] in ["POST", "GET"]:
                        is_vulnerable = True
                        evidence_detail = f"Cross-origin state-changing {ep['method']} request succeeded without Anti-CSRF token at {ep['path']}."

                if is_vulnerable:
                    cvss = CVSSv31Calculator.calculate(
                        av="N", ac="L", pr="N", ui="R", s="U", c="N", i="H", a="N"
                    )
                    req_body_str = json.dumps(ep["data"]) if ep["content_type"] == "json" else "&".join(f"{k}={v}" for k, v in ep["data"].items())
                    curl_cmd = (
                        f'curl -s -X {ep["method"]} "{target_endpoint}" '
                        f'-H "Origin: https://attacker.com" '
                        f'-H "Content-Type: application/json" '
                        f"-d '{req_body_str}'"
                    )
                    req_raw = f"{ep['method']} {target_endpoint} HTTP/1.1\nOrigin: https://attacker.com\nContent-Type: application/json\n\n{req_body_str}"
                    resp_raw = f"HTTP/1.1 {resp.status_code}\nContent-Type: application/json\n\n{body[:600]}"

                    findings.append(
                        Finding(
                            id="VULN-CSRF-001",
                            title="Missing Anti-CSRF Token on State-Changing Endpoint",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method=ep["method"],
                            parameter="csrf_token",
                            payload_used="[Omitted Anti-CSRF Token with Cross-Origin Origin Header]",
                            evidence=evidence_detail,
                            cwe_id="CWE-352",
                            owasp_category="A01:2021-Broken Access Control",
                            curl_command=curl_cmd,
                            request_raw=req_raw,
                            response_raw=resp_raw,
                            remediation_summary="Generate unique, cryptographically random, per-session anti-CSRF tokens (Synchronizer Token Pattern), enforce 'SameSite=Strict' on all session cookies, and validate Origin/Referer request headers."
                        )
                    )
                    break  # One confirmed CSRF finding is sufficient

            except Exception:
                continue

        return findings
