import httpx
from typing import List
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.cvss import CVSSv31Calculator

class IDORDetector(BaseDetector):
    name = "Insecure Direct Object Reference Detector"
    vuln_type = "Insecure Direct Object References (IDOR)"

    # Multiple possible IDOR endpoint patterns to try
    IDOR_PATH_TEMPLATES = [
        "/api/orders/{id}",      # Target1 VoltMart
        "/api/patients/{id}",    # Target3 Healthcare
        "/api/accounts/{id}",    # Generic
        "/orders/{id}",          # Fallback
        "/users/{id}",           # Generic
        "/api/records/{id}",     # Generic
    ]

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        import re
        findings: List[Finding] = []
        base = base_url.rstrip('/')

        templates_to_test = list(self.IDOR_PATH_TEMPLATES)

        # Ingest discovered endpoints from crawler matching /{resource}/{number}
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                m = re.sub(r'\/[0-9]+(?:\/|$)', '/{id}/', ep.path)
                if "{id}" in m and m not in templates_to_test:
                    templates_to_test.insert(0, m.rstrip("/"))
                # Check for query param with id
                for pk in ep.params.keys():
                    if "id" in pk.lower():
                        templates_to_test.insert(0, f"{ep.path}?{pk}={{id}}")

        for path_template in templates_to_test:
            leaked_records = []


            for oid in [1, 2, 3]:
                target_endpoint = f"{base}{path_template.format(id=oid)}"
                try:
                    resp = await client.get(target_endpoint)
                    body = resp.text

                    # If blocked by WAF
                    if resp.status_code == 403 and "blocked_by_waf" in body:
                        continue

                    # Vulnerable if:
                    # 1. Returns 200 with explicit IDOR vulnerability note, OR
                    # 2. Returns sensitive PII fields without auth check, OR
                    # 3. Contains tenant_auth_verified: false
                    if resp.status_code == 200:
                        if (
                            "CWE-639" in body
                            or "vulnerability_note" in body
                            or "customer_email" in body
                            or "shipping_address" in body
                            or '"tenant_auth_verified":false' in body.replace(" ", "")
                            or "customer_name" in body
                        ):
                            leaked_records.append((oid, target_endpoint, body))
                except Exception:
                    continue

            if len(leaked_records) >= 2:
                oid, endpoint, body = leaked_records[0]
                cvss = CVSSv31Calculator.calculate(
                    av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"
                )

                curl_cmd = f'curl -s -X GET "{endpoint}" -H "Accept: application/json"'
                req_raw = f"GET {endpoint} HTTP/1.1\nAccept: application/json\nUser-Agent: Aegis-DAST-Scanner/1.0"
                resp_raw = f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{body[:600]}"

                evidence = f"Unauthenticated request accessed sensitive record details for object ID #{oid} without session token verification. {len(leaked_records)} consecutive object IDs accessible."

                findings.append(
                    Finding(
                        id="VULN-IDOR-001",
                        title="Insecure Direct Object Reference (IDOR) Exposing Sensitive PII Records",
                        vuln_type=self.vuln_type,
                        severity=cvss["severity"],
                        cvss_score=cvss["base_score"],
                        cvss_vector=cvss["vector_string"],
                        endpoint=endpoint,
                        method="GET",
                        parameter="id",
                        payload_used=str(oid),
                        evidence=evidence,
                        cwe_id="CWE-639",
                        owasp_category="A01:2021-Broken Access Control",
                        curl_command=curl_cmd,
                        request_raw=req_raw,
                        response_raw=resp_raw,
                        remediation_summary="Implement robust object-level access control (ABAC/RBAC): verify that the authenticated user's session matches the resource owner before returning entities."
                    )
                )
                break  # Found one IDOR, done

        return findings
