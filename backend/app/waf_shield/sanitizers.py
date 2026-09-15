import html
import re
from urllib.parse import urlparse
import ipaddress
import socket
from typing import Dict, Any

class DefensiveSanitizer:
    """
    Defensive input sanitization and contextual output encoding module.
    Provides sanitization utilities used when WAF mode is set to 'SANITIZE'.
    """

    @staticmethod
    def encode_html(text: str) -> str:
        """Contextual HTML entity encoding for defense against XSS."""
        if not text or not isinstance(text, str):
            return text
        return html.escape(text, quote=True)

    @staticmethod
    def sanitize_sql_param(param: str) -> str:
        """
        Escapes dangerous SQL metacharacters if dynamic queries are used,
        neutralizing quote breaks and inline comment operators.
        """
        if not param or not isinstance(param, str):
            return param
        # Escape single quotes and remove SQL comment symbols
        escaped = param.replace("'", "''")
        escaped = re.sub(r'(--|#|/\*|\*/)', '', escaped)
        return escaped

    @staticmethod
    def is_safe_external_url(url_str: str) -> bool:
        """
        SSRF Defense: Validates that a destination URL is strictly an external,
        routable public HTTP/HTTPS endpoint and not internal/cloud metadata.
        """
        try:
            parsed = urlparse(url_str.strip())
            if parsed.scheme.lower() not in ("http", "https"):
                return False
            
            hostname = parsed.hostname
            if not hostname:
                return False

            if hostname.lower() in ("169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"):
                return False

            # Resolve IP
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)

            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False

            return True
        except Exception:
            return False
