import pytest
from app.waf_shield.signatures import WAFSignatures, EvasionNormalizer
from app.waf_shield.telemetry import waf_telemetry

def test_waf_signature_sqli_detection():
    # Test raw SQLi
    res = WAFSignatures.inspect("' OR '1'='1")
    assert res is not None
    assert res["attack_type"] == "SQL Injection (SQLi)"
    assert res["cwe"] == "CWE-89"

def test_waf_signature_sqli_evasion_comment():
    # Test comment injection evasion
    res = WAFSignatures.inspect("1'/**/OR/**/'1'='1'/**/--")
    assert res is not None
    assert res["attack_type"] == "SQL Injection (SQLi)"
    assert "inline_comment_obfuscation" in res["evasions"]

def test_waf_signature_sqli_double_encoding():
    # Test double URL encoded single quote %2527
    res = WAFSignatures.inspect("%2527%2520OR%25201%253D1%2520--")
    assert res is not None
    assert res["attack_type"] == "SQL Injection (SQLi)"
    assert "multiple_url_encoding" in res["evasions"]

def test_waf_signature_xss_detection():
    res = WAFSignatures.inspect("<script>alert('xss')</script>")
    assert res is not None
    assert res["attack_type"] == "Cross-Site Scripting (XSS)"
    assert res["cwe"] == "CWE-79"

def test_waf_signature_ssrf_detection():
    res = WAFSignatures.inspect("http://169.254.169.254/latest/meta-data/")
    assert res is not None
    assert res["attack_type"] == "Server-Side Request Forgery (SSRF)"
    assert res["cwe"] == "CWE-918"

def test_waf_telemetry_recording():
    waf_telemetry.clear_metrics()
    waf_telemetry.set_mode("BLOCK")
    attack_info = {
        "attack_type": "SQL Injection (SQLi)",
        "rule": "SQLI-001",
        "evasions": ["multiple_url_encoding"],
        "cwe": "CWE-89",
        "owasp": "A03:2021"
    }
    waf_telemetry.record_attack(attack_info, "BLOCKED", "192.168.1.100", "/api/shop/search")
    
    metrics = waf_telemetry.get_metrics()
    assert metrics["total_blocked"] == 1
    assert metrics["evasions_defeated"] == 1
    assert metrics["attack_counters"]["SQL Injection (SQLi)"] == 1
    assert len(metrics["recent_events"]) == 1
