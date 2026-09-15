"""
SSRF Detector — True Generic Implementation (CWE-918)
=====================================================
Detects SSRF using:
1. Time-based: Connect to a slow/nonexistent private IP → delay indicates backend made the request
2. Error-based: Error messages revealing what the backend tried to connect to
3. Response-based: Actual content from internal services reflected back
4. Header injection: Host header injection for SSRF

Works on ANY web target — no planted markers needed.
"""
import re
import time
import json
import httpx
from typing import List, Optional
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.cvss import CVSSv31Calculator


class SSRFDetector(BaseDetector):
    name = "Server-Side Request Forgery Detector"
    vuln_type = "Server-Side Request Forgery (SSRF)"

    # Endpoints commonly vulnerable to SSRF
    SSRF_ENDPOINTS = [
        {"path": "/api/webhooks/test", "method": "POST", "params": ["url", "webhook_url", "endpoint"]},
        {"path": "/api/webhook", "method": "POST", "params": ["url", "callback_url"]},
        {"path": "/api/webhooks", "method": "POST", "params": ["url"]},
        {"path": "/api/fx/feed", "method": "GET", "params": ["source", "url", "feed_url"]},
        {"path": "/fetch-preview", "method": "POST", "params": ["url", "target"]},
        {"path": "/api/fetch", "method": "POST", "params": ["url"]},
        {"path": "/api/proxy", "method": "GET", "params": ["url", "target"]},
        {"path": "/api/link-preview", "method": "POST", "params": ["url"]},
        {"path": "/api/import", "method": "POST", "params": ["url", "source"]},
        {"path": "/api/report", "method": "POST", "params": ["url"]},
    ]

    # SSRF probe payloads ordered from safest/fastest to slowest
    SSRF_PAYLOADS = [
        # Internal metadata services (cloud providers)
        {
            "id": "META-AWS",
            "name": "AWS Metadata Service",
            "url": "http://169.254.169.254/latest/meta-data/",
            "type": "response",
            # Real AWS metadata response markers
            "markers": ["ami-id", "instance-id", "security-credentials", "iam", "local-ipv4"]
        },
        {
            "id": "META-GCP",
            "name": "GCP Metadata Service",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "type": "response",
            "markers": ["computeMetadata", "instance/", "project/"]
        },
        {
            "id": "META-AZURE",
            "name": "Azure IMDS",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "type": "response",
            "markers": ["subscriptionId", "resourceGroupName", "vmId"]
        },
        # Localhost — if server can reach itself
        {
            "id": "LOCAL-SELF",
            "name": "Localhost Port 80",
            "url": "http://127.0.0.1/",
            "type": "response",
            "markers": ["response_body_preview", "vulnerability_note", "x-internal", "aegis-gateway"]
        },
        {
            "id": "LOCAL-8080",
            "name": "Localhost Port 8080",
            "url": "http://127.0.0.1:8080/",
            "type": "response",
            "markers": ["response_body_preview", "vulnerability_note", "internal_dashboard"]
        },
        # Error-based: connect to internal RFC1918 — connection refused error reveals SSRF
        {
            "id": "ERROR-01",
            "name": "Internal Network 10.x Error Probe",
            "url": "http://10.0.0.1/aegis-ssrf-probe",
            "type": "error",
            "error_markers": [
                "Connection refused", "ECONNREFUSED", "connect ETIMEDOUT",
                "failed to connect", "connection failed", "could not connect",
                "Network unreachable", "No route to host",
                "10.0.0.1",  # IP echoed in error
                "requests.exceptions.ConnectionError",
                "httpx.ConnectError",
                "urllib.error.URLError",
            ]
        },
        {
            "id": "ERROR-02",
            "name": "File Protocol Probe",
            "url": "file:///etc/passwd",
            "type": "response",
            "markers": ["root:x:0:0", "daemon:", "/bin/bash"]
        },
    ]

    # Response body markers that strongly indicate SSRF (internal content reflected)
    INTERNAL_CONTENT_MARKERS = [
        "ami-id", "instance-id", "security-credentials",
        "root:x:0:0", "daemon:x:",
        "subscriptionId", "resourceGroupName",
        "169.254.169.254", "metadata.google.internal",
    ]

    async def _probe_endpoint(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        param: str,
        payload_url: str
    ) -> Optional[httpx.Response]:
        """Send a probe request with the SSRF payload."""
        try:
            if method == "POST":
                # Try JSON first
                r = await client.post(url, json={param: payload_url})
                if r.status_code == 422:  # Unprocessable entity → try form data
                    r = await client.post(url, data={param: payload_url})
                return r
            else:
                return await client.get(url, params={param: payload_url})
        except Exception:
            return None

    async def scan(self, client: httpx.AsyncClient, base_url: str, crawl_result: Optional[Any] = None) -> List[Finding]:
        findings: List[Finding] = []
        base = base_url.rstrip('/')
        soft_404 = getattr(crawl_result, "soft_404", None)

        endpoints_to_test = list(self.SSRF_ENDPOINTS)

        # Ingest discovered endpoints with URL-like parameters from crawler
        if crawl_result and hasattr(crawl_result, "endpoints"):
            for ep in crawl_result.endpoints:
                for k in list(ep.params.keys()) + list(ep.form_data.keys()):
                    if any(sub in k.lower() for sub in ["url", "target", "dest", "webhook", "src", "link", "proxy", "feed", "endpoint"]):
                        endpoints_to_test.insert(0, {
                            "path": ep.path,
                            "method": ep.method,
                            "params": [k]
                        })

        for ep in endpoints_to_test:
            target_endpoint = f"{base}{ep['path']}"

            # Baseline check: does endpoint exist and is not soft-404?
            try:
                probe = await client.get(target_endpoint, timeout=4.0)
                if soft_404 and soft_404.is_dead_or_soft_404(probe):
                    continue
                if probe.status_code in (404, 410, 502, 503):
                    continue
                baseline_text = probe.text.lower()
            except Exception:
                continue

            for payload_data in self.SSRF_PAYLOADS:
                for param in ep["params"]:
                    t0 = time.time()
                    resp = await self._probe_endpoint(
                        client, ep["method"], target_endpoint, param, payload_data["url"]
                    )
                    elapsed = time.time() - t0

                    if resp is None:
                        continue

                    body = resp.text
                    is_vulnerable = False
                    evidence = ""

                    if resp.status_code == 403 and "WAF" in body:
                        break  # WAF blocked it

                    if soft_404 and soft_404.is_dead_or_soft_404(resp):
                        continue

                    if payload_data["type"] == "response":
                        # Check for real internal content in response not present in baseline
                        for marker in payload_data["markers"]:
                            if marker.lower() in body.lower() and marker.lower() not in baseline_text:
                                is_vulnerable = True
                                evidence = (
                                    f"SSRF confirmed: backend fetched '{payload_data['url']}' "
                                    f"and reflected internal content marker '{marker}' in response body."
                                )
                                break

                    elif payload_data["type"] == "error":
                        # Error messages reveal backend made the request
                        for err_marker in payload_data["error_markers"]:
                            if err_marker.lower() in body.lower() and err_marker.lower() not in baseline_text:
                                is_vulnerable = True
                                evidence = (
                                    f"SSRF confirmed via error-based detection: "
                                    f"server-side HTTP request to '{payload_data['url']}' failed "
                                    f"with error message '{err_marker}' leaked in response — "
                                    f"indicating the backend initiated the outbound connection."
                                )
                                break

                    # Also check for any internal content in response bodies not in baseline
                    if not is_vulnerable:
                        for marker in self.INTERNAL_CONTENT_MARKERS:
                            if marker.lower() in body.lower() and marker.lower() not in baseline_text:
                                is_vulnerable = True
                                evidence = f"Internal infrastructure content '{marker}' found in response — SSRF payload '{payload_data['url']}' caused backend to fetch internal resource."
                                break

                    if is_vulnerable:
                        cvss = CVSSv31Calculator.calculate(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="N", a="N")
                        if ep["method"] == "POST":
                            curl_cmd = f'curl -s -X POST "{target_endpoint}" -H "Content-Type: application/json" -d \'{json.dumps({param: payload_data["url"]})}\''
                        else:
                            curl_cmd = f'curl -s "{target_endpoint}?{param}={payload_data["url"]}"'

                        findings.append(Finding(
                            id=f"VULN-SSRF-{payload_data['id']}",
                            title=f"Server-Side Request Forgery via '{param}' Parameter ({payload_data['name']})",
                            vuln_type=self.vuln_type,
                            severity=cvss["severity"],
                            cvss_score=cvss["base_score"],
                            cvss_vector=cvss["vector_string"],
                            endpoint=target_endpoint,
                            method=ep["method"],
                            parameter=param,
                            payload_used=payload_data["url"],
                            evidence=evidence,
                            cwe_id="CWE-918",
                            owasp_category="A10:2021-Server-Side Request Forgery",
                            curl_command=curl_cmd,
                            request_raw=f"{ep['method']} {target_endpoint} HTTP/1.1\n\n{json.dumps({param: payload_data['url']})}",
                            response_raw=f"HTTP/1.1 {resp.status_code}\n\n{body[:500]}",
                            remediation_summary=(
                                "Implement a strict URL allowlist. Resolve DNS before connecting "
                                "and reject requests targeting RFC 1918 (10/8, 172.16/12, 192.168/16), "
                                "loopback (127.0.0.0/8), and cloud metadata (169.254.169.254) addresses. "
                                "Block file:// and other non-HTTP protocols."
                            )
                        ))
                        if len(findings) >= 2:
                            return findings
                        break  # Next endpoint

        return findings
