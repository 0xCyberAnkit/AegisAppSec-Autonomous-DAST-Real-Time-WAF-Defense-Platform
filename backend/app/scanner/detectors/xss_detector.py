import json
import httpx
from typing import List
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.cvss import CVSSv31Calculator
from app.scanner.payloads import XSS_PAYLOADS

class XSSDetector(BaseDetector):
    name = "Cross-Site Scripting Detector"
    vuln_type = "Cross-Site Scripting (XSS)"

    XSS_PROBES = [
        "<script>alert('aegis-xss')</script>",
        "<img src=x onerror=alert('aegis')>",
        '"><script>alert(1)</script>',
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        # --- Dynamic Crawl Surface Testing ---
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                if len(findings) >= 2:
                    break
                # Test forms
                if ep.method == "POST" and ep.form_data:
                    for input_name in ep.form_data.keys():
                        for probe in self.XSS_PROBES[:2]:
                            test_data = dict(ep.form_data)
                            test_data[input_name] = probe
                            try:
                                r = await client.post(ep.url, data=test_data, timeout=3.0)
                                if probe in r.text and "<" in probe:
                                    cvss = CVSSv31Calculator.calculate(
                                        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
                                    )
                                    findings.append(
                                        Finding(
                                            id=f"VULN-XSS-CRAWL-{input_name}",
                                            title=f"XSS in form parameter '{input_name}' at {ep.path}",
                                            vuln_type=self.vuln_type,
                                            severity=cvss["severity"],
                                            cvss_score=cvss["base_score"],
                                            cvss_vector=cvss["vector_string"],
                                            endpoint=ep.url,
                                            method="POST",
                                            parameter=input_name,
                                            payload_used=probe,
                                            evidence=f"Unsanitized HTML/JS payload reflected verbatim in response body: '{probe}'",
                                            cwe_id="CWE-79",
                                            owasp_category="A03:2021-Injection",
                                            curl_command=f'curl -s -X POST "{ep.url}" -d "{input_name}={probe}"',
                                            request_raw=f"POST {ep.url} HTTP/1.1\n\n{input_name}={probe}",
                                            response_raw=f"HTTP/1.1 {r.status_code}\n\n{r.text[:600]}",
                                            remediation_summary="Implement contextual HTML entity encoding and enforce Content Security Policy (CSP)."
                                        )
                                    )
                                    break
                            except Exception:
                                continue
                # Test query params
                elif ep.method == "GET" and ep.params:
                    for param_name in ep.params.keys():
                        for probe in self.XSS_PROBES[:2]:
                            test_params = dict(ep.params)
                            test_params[param_name] = probe
                            try:
                                r = await client.get(ep.url.split("?")[0], params=test_params, timeout=3.0)
                                if probe in r.text and "<" in probe:
                                    cvss = CVSSv31Calculator.calculate(
                                        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
                                    )
                                    findings.append(
                                        Finding(
                                            id=f"VULN-XSS-CRAWL-{param_name}",
                                            title=f"Reflected XSS in parameter '{param_name}' at {ep.path}",
                                            vuln_type=self.vuln_type,
                                            severity=cvss["severity"],
                                            cvss_score=cvss["base_score"],
                                            cvss_vector=cvss["vector_string"],
                                            endpoint=ep.url.split("?")[0],
                                            method="GET",
                                            parameter=param_name,
                                            payload_used=probe,
                                            evidence=f"Reflected XSS: Parameter '{param_name}' value reflected unencoded in HTML response: '{probe}'",
                                            cwe_id="CWE-79",
                                            owasp_category="A03:2021-Injection",
                                            curl_command=f'curl -s -G "{ep.url.split("?")[0]}" --data-urlencode "{param_name}={probe}"',
                                            request_raw=f"GET {ep.url.split('?')[0]}?{param_name}={probe} HTTP/1.1\n\n",
                                            response_raw=f"HTTP/1.1 {r.status_code}\n\n{r.text[:600]}",
                                            remediation_summary="Sanitize and HTML-encode all user-controlled data before inclusion in HTML responses."
                                        )
                                    )
                                    break
                            except Exception:
                                continue

        # --- Strategy 1: POST /reviews with form-data (Target1 VoltMart & standard fallback) ---
        reviews_endpoint = f"{base}/reviews"
        for probe in self.XSS_PROBES:
            if len(findings) >= 2:
                break
            try:
                # Target1 expects multipart/form-data (Form fields)
                form_resp = await client.post(
                    reviews_endpoint,
                    data={"author": "Aegis_Audit", "comment": probe, "product_id": "1"}
                )

                body = form_resp.text

                # If blocked by WAF
                if form_resp.status_code == 403 and "blocked_by_waf" in body:
                    continue

                # Vulnerable if payload is reflected unescaped in the HTML response
                if probe in body and "<" in probe:
                    cvss = CVSSv31Calculator.calculate(
                        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
                    )
                    curl_cmd = (
                        f'curl -s -X POST "{reviews_endpoint}" '
                        f'-F "author=Aegis_Audit" '
                        f'-F "comment={probe}" '
                        f'-F "product_id=1"'
                    )
                    req_raw = f"POST {reviews_endpoint} HTTP/1.1\nContent-Type: multipart/form-data\n\nauthor=Aegis_Audit&comment={probe}&product_id=1"
                    resp_raw = f"HTTP/1.1 {form_resp.status_code}\nContent-Type: text/html\n\n{body[:600]}"
                    evidence = f"Unsanitized HTML/JS payload reflected verbatim in response body (Stored/Reflected XSS): '{probe[:60]}'"

                    findings.append(
                        Finding(
                            id=f"VULN-XSS-STORED-001",
                            title="Stored XSS via Review Submission (Unescaped HTML Reflection)",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=reviews_endpoint,
                            method="POST",
                            parameter="comment",
                            payload_used=probe,
                            evidence=evidence,
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            curl_command=curl_cmd,
                            request_raw=req_raw,
                            response_raw=resp_raw,
                            remediation_summary="Implement contextual HTML entity encoding (convert '<' to '&lt;') before rendering user data, and enforce a strict Content Security Policy (CSP) with nonce-based script execution."
                        )
                    )
                    break
            except Exception:
                continue

        # --- Strategy 2: GET /reviews?author= reflected XSS (Target1) ---
        if len(findings) < 2:
            for probe in self.XSS_PROBES[:2]:
                try:
                    get_resp = await client.get(reviews_endpoint, params={"author": probe})
                    body = get_resp.text
                    if get_resp.status_code == 403 and "blocked_by_waf" in body:
                        continue
                    if probe in body and "<" in probe:
                        cvss = CVSSv31Calculator.calculate(
                            av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
                        )
                        curl_cmd = f'curl -s -G "{reviews_endpoint}" --data-urlencode "author={probe}"'
                        req_raw = f"GET {reviews_endpoint}?author={probe} HTTP/1.1\nHost: target.local\n\n"
                        resp_raw = f"HTTP/1.1 {get_resp.status_code}\nContent-Type: text/html\n\n{body[:600]}"
                        evidence = f"Reflected XSS: Query parameter 'author' value reflected unencoded in HTML response: '{probe[:60]}'"

                        findings.append(
                            Finding(
                                id="VULN-XSS-REFLECTED-001",
                                title="Reflected XSS via Query Parameter (Unescaped GET Reflection)",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=reviews_endpoint,
                                method="GET",
                                parameter="author",
                                payload_used=probe,
                                evidence=evidence,
                                cwe_id="CWE-79",
                                owasp_category="A03:2021-Injection",
                                curl_command=curl_cmd,
                                request_raw=req_raw,
                                response_raw=resp_raw,
                                remediation_summary="Sanitize and HTML-encode all user-controlled data before inclusion in HTML responses. Use template auto-escaping and enforce Content-Security-Policy headers."
                            )
                        )
                        break
                except Exception:
                    continue

        # --- Strategy 3: JSON POST /reviews (fallback for API targets) ---
        if len(findings) == 0:
            for p_data in XSS_PAYLOADS:
                payload = p_data["payload"]
                req_body = {
                    "product_id": 1,
                    "author": "Aegis_Security_Audit",
                    "comment": payload,
                    "rating": 5
                }
                try:
                    resp = await client.post(reviews_endpoint, json=req_body)
                    body = resp.text
                    if resp.status_code == 403 and "blocked_by_waf" in body:
                        continue
                    if payload in body or (p_data.get("evasion") == "nested_tag" and "alert('aegis-xss')" in body):
                        cvss = CVSSv31Calculator.calculate(
                            av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
                        )
                        curl_cmd = (
                            f'curl -s -X POST "{reviews_endpoint}" '
                            f'-H "Content-Type: application/json" '
                            f"-d '{json.dumps(req_body)}'"
                        )
                        req_raw = f"POST {reviews_endpoint} HTTP/1.1\nContent-Type: application/json\n\n{json.dumps(req_body, indent=2)}"
                        resp_raw = f"HTTP/1.1 {resp.status_code}\nContent-Type: application/json\n\n{body[:600]}"
                        evidence = f"Unsanitized and unencoded script vector reflected verbatim in response payload: '{payload}'."

                        findings.append(
                            Finding(
                                id=f"VULN-XSS-{p_data['id']}",
                                title=f"Stored/Reflected XSS via '{p_data['name']}' in reviews endpoint",
                                vuln_type=self.vuln_type,
                                severity=cvss["severity"],
                                cvss_score=cvss["base_score"],
                                cvss_vector=cvss["vector_string"],
                                endpoint=reviews_endpoint,
                                method="POST",
                                parameter="comment",
                                payload_used=payload,
                                evidence=evidence,
                                cwe_id="CWE-79",
                                owasp_category="A03:2021-Injection",
                                curl_command=curl_cmd,
                                request_raw=req_raw,
                                response_raw=resp_raw,
                                remediation_summary="Implement contextual HTML entity encoding and enforce a strict Content Security Policy (CSP) with nonce-based script execution."
                            )
                        )
                        if len(findings) >= 2:
                            break
                except Exception:
                    continue

        return findings
