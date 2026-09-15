import re
import urllib.parse
import unicodedata
from typing import Dict, Any, List, Optional, Tuple

class EvasionNormalizer:
    """
    Normalizes incoming request inputs against common evasion tactics:
    - Multiple / Double URL-encoding (%2527 -> %27 -> ')
    - Unicode full-width / homoglyph normalization (NFKC)
    - Null-byte injection (%00)
    - Whitespace obfuscation and inline SQL comments (/**/)
    - Nested tag evasion (<scr<script>ipt>)
    """
    @classmethod
    def normalize(cls, raw_text: str) -> Tuple[str, List[str]]:
        if not raw_text or not isinstance(raw_text, str):
            return "", []

        evasions_detected = []
        normalized = raw_text

        # 1. Null-byte removal
        if "\x00" in normalized or "%00" in normalized:
            evasions_detected.append("null_byte_injection")
            normalized = normalized.replace("\x00", "").replace("%00", "")

        # 2. Recursive URL-decoding (up to 3 rounds to catch double/triple encoding)
        rounds = 0
        while rounds < 3:
            decoded = urllib.parse.unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded
            rounds += 1
        
        if rounds > 1:
            evasions_detected.append("multiple_url_encoding")

        # 3. Unicode normalization (NFKC standard)
        try:
            nfkc = unicodedata.normalize("NFKC", normalized)
            if nfkc != normalized:
                evasions_detected.append("unicode_homoglyph_evasion")
                normalized = nfkc
        except Exception:
            pass

        # 4. Inline comment removal (SQL /**/)
        if "/**/" in normalized:
            evasions_detected.append("inline_comment_obfuscation")
            normalized = re.sub(r'/\*.*?\*/', ' ', normalized)

        # 5. Nested tag collapse
        nested_script = re.sub(r'(?i)<scr(<script>|ipt>)+', '<script>', normalized)
        if nested_script != normalized:
            evasions_detected.append("nested_tag_bypass")
            normalized = nested_script

        return normalized, evasions_detected

class WAFSignatures:
    """
    Heuristic and regex signatures for OWASP Top 10 web application vulnerabilities.
    """
    
    SQLI_RULES = [
        (re.compile(r"(?i)(\bunion\b\s+(all\s+)?\bselect\b)", re.MULTILINE), "SQLI-001: UNION SELECT Data Exfiltration"),
        (re.compile(r"(?i)(['\"]\s*(or|and)\s*['\"]?[0-9a-z]+['\"]?\s*=\s*['\"]?[0-9a-z]+['\"]?|(\bor|\band)\s+['\"]?[0-9a-z]+['\"]?\s*=\s*['\"]?[0-9a-z]+['\"]?)", re.MULTILINE), "SQLI-002: Tautological Boolean Injection"),
        (re.compile(r"(--|#|/\*|;\s*$)", re.MULTILINE), "SQLI-003: SQL Comment Termination Vector"),
        (re.compile(r"(?i)\b(sleep\s*\(\s*[0-9]+\s*\)|benchmark\s*\(|randomblob\s*\()", re.MULTILINE), "SQLI-004: Time-Based Delay Attack"),
        (re.compile(r"(?i)\b(information_schema|sqlite_master|pg_tables|sys\.tables)\b", re.MULTILINE), "SQLI-005: Schema Enumeration Probe"),
        (re.compile(r"(?i)\b(exec\s*\(|sp_executesql|xp_cmdshell)\b", re.MULTILINE), "SQLI-006: Stored Procedure Execution")
    ]

    XSS_RULES = [
        (re.compile(r"(?i)<\s*script[^>]*>", re.MULTILINE), "XSS-001: Raw Script Tag Injection"),
        (re.compile(r"(?i)\b(javascript|vbscript|data):", re.MULTILINE), "XSS-002: Malicious URI Protocol Scheme"),
        (re.compile(r"(?i)\bon(error|load|click|mouseover|submit|focus|blur)\s*=", re.MULTILINE), "XSS-003: Inline DOM Event Handler"),
        (re.compile(r"(?i)<\s*(iframe|svg|object|embed|applet|body|meta)\b[^>]*>", re.MULTILINE), "XSS-004: Active HTML Tag Injection"),
        (re.compile(r"(?i)\b(eval|alert|prompt|confirm)\s*\(", re.MULTILINE), "XSS-005: Dangerous JavaScript Execution Function")
    ]

    SSRF_RULES = [
        (re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|169\.254\.169\.250)", re.MULTILINE), "SSRF-001: Cloud Provider Instance Metadata Access"),
        (re.compile(r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|0x7f000001|2130706433)", re.MULTILINE), "SSRF-002: Loopback Interface Access Attempt"),
        (re.compile(r"(?i)(gopher|dict|file|ldap|ftp)://", re.MULTILINE), "SSRF-003: Unauthorized URL Protocol Smuggling"),
        (re.compile(r"(?i)\b(internal-admin|backend-vault|k8s-api)\b", re.MULTILINE), "SSRF-004: Internal Infrastructure Service Probe")
    ]

    TRAVERSAL_RULES = [
        (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.MULTILINE), "LFI-001: Directory Path Traversal"),
        (re.compile(r"(?i)(/etc/passwd|/windows/system32|boot\.ini)", re.MULTILINE), "LFI-002: Sensitive System File Access")
    ]

    @classmethod
    def inspect(cls, content: str) -> Optional[Dict[str, Any]]:
        """
        Scans normalized content against all signature categories.
        Returns match metadata if triggered, otherwise None.
        """
        if not content:
            return None

        normalized, evasions = EvasionNormalizer.normalize(content)

        # 1. Test SQLi
        for pattern, rule_name in cls.SQLI_RULES:
            if pattern.search(normalized):
                return {
                    "attack_type": "SQL Injection (SQLi)",
                    "rule": rule_name,
                    "evasions": evasions,
                    "confidence": "HIGH",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021-Injection"
                }

        # 2. Test XSS
        for pattern, rule_name in cls.XSS_RULES:
            if pattern.search(normalized):
                return {
                    "attack_type": "Cross-Site Scripting (XSS)",
                    "rule": rule_name,
                    "evasions": evasions,
                    "confidence": "HIGH",
                    "cwe": "CWE-79",
                    "owasp": "A03:2021-Injection"
                }

        # 3. Test SSRF
        for pattern, rule_name in cls.SSRF_RULES:
            if pattern.search(normalized):
                return {
                    "attack_type": "Server-Side Request Forgery (SSRF)",
                    "rule": rule_name,
                    "evasions": evasions,
                    "confidence": "HIGH",
                    "cwe": "CWE-918",
                    "owasp": "A10:2021-Server-Side Request Forgery"
                }

        # 4. Test Traversal
        for pattern, rule_name in cls.TRAVERSAL_RULES:
            if pattern.search(normalized):
                return {
                    "attack_type": "Path Traversal / LFI",
                    "rule": rule_name,
                    "evasions": evasions,
                    "confidence": "HIGH",
                    "cwe": "CWE-22",
                    "owasp": "A01:2021-Broken Access Control"
                }

        return None
