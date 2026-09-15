"""Modular vulnerability detectors for OWASP Top 10 and CWE Top 25."""
from app.scanner.detectors.base import BaseDetector, Finding
from app.scanner.detectors.sqli_detector import SQLiDetector
from app.scanner.detectors.xss_detector import XSSDetector
from app.scanner.detectors.ssrf_detector import SSRFDetector
from app.scanner.detectors.csrf_detector import CSRFDetector
from app.scanner.detectors.idor_detector import IDORDetector
from app.scanner.detectors.extended_detectors import (
    CommandInjectionDetector,
    PathTraversalDetector,
    BrokenAuthDetector,
    XXEDetector,
    InsecureDeserializationDetector,
    OpenRedirectDetector,
    CORSDetector,
    InfoDisclosureDetector,
    OutdatedComponentsDetector,
)

__all__ = [
    "BaseDetector",
    "Finding",
    "SQLiDetector",
    "XSSDetector",
    "SSRFDetector",
    "CSRFDetector",
    "IDORDetector",
    "CommandInjectionDetector",
    "PathTraversalDetector",
    "BrokenAuthDetector",
    "XXEDetector",
    "InsecureDeserializationDetector",
    "OpenRedirectDetector",
    "CORSDetector",
    "InfoDisclosureDetector",
    "OutdatedComponentsDetector",
]
