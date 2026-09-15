import pytest
from app.scanner.cvss import CVSSv31Calculator

def test_cvss_critical_sqli():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H should yield Base Score 9.8 (CRITICAL)
    res = CVSSv31Calculator.calculate(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
    )
    assert res["base_score"] == 9.8
    assert res["severity"] == "CRITICAL"
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in res["vector_string"]

def test_cvss_high_ssrf():
    # Scope changed, High confidentiality
    res = CVSSv31Calculator.calculate(
        av="N", ac="L", pr="N", ui="N", s="C", c="H", i="N", a="N"
    )
    assert res["base_score"] >= 8.0
    assert res["severity"] == "HIGH"

def test_cvss_medium_xss():
    # Reflected XSS requiring user interaction
    res = CVSSv31Calculator.calculate(
        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
    )
    assert res["base_score"] >= 6.0
    assert res["severity"] in ("MEDIUM", "HIGH")
