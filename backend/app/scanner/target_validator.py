import ipaddress
import socket
from urllib.parse import urlparse
from app.core.config import settings

class TargetValidationError(Exception):
    pass

class TargetValidator:
    """
    Platform Hardening: Anti-SSRF Scanner Guardrail.
    Validates scan target URLs to ensure that the scanner cannot be coerced
    by external attackers into scanning unauthorized private cloud metadata,
    sensitive internal infrastructure, or local daemon ports.
    """

    METADATA_HOSTS = {
        "169.254.169.254",
        "metadata.google.internal",
        "169.254.169.250",
        "100.100.100.200",  # Alibaba Cloud metadata
    }

    @classmethod
    def validate_target(cls, url: str) -> str:
        """
        Validates target URL. Returns normalized URL string or raises TargetValidationError.
        """
        if not url or not isinstance(url, str):
            raise TargetValidationError("Target URL must be a non-empty string.")

        parsed = urlparse(url.strip())

        # Enforce scheme
        if parsed.scheme.lower() not in ("http", "https"):
            raise TargetValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise TargetValidationError("Invalid URL: Hostname could not be determined.")

        hostname_lower = hostname.lower()

        # Check explicit metadata hosts
        if hostname_lower in cls.METADATA_HOSTS:
            raise TargetValidationError(
                "Security Policy Violation: Scanning cloud metadata services is strictly forbidden."
            )

        # Resolve IP address to detect DNS rebinding or IP evasion (hex, octal, dword)
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            # If DNS resolution fails, let request proceed or warn
            ip_obj = None

        if ip_obj:
            # Check Link-Local / Cloud Metadata subnet (169.254.0.0/16)
            if ip_obj.is_link_local:
                raise TargetValidationError("Security Policy Violation: Link-local addresses cannot be targeted.")

            # Check loopback / private addresses if not allowed
            if (ip_obj.is_loopback or ip_obj.is_private):
                if not settings.ALLOW_LOCAL_TARGETS:
                    raise TargetValidationError(
                        f"Target IP {ip_str} is in a private/loopback range. Private network scanning is disabled."
                    )

        return url.strip()
