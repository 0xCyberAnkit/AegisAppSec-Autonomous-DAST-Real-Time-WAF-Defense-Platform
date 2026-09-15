import pytest
import httpx
from app.main import app
from app.waf_shield.telemetry import waf_telemetry

@pytest.mark.asyncio
async def test_sqli_vulnerable_when_waf_off():
    waf_telemetry.set_mode("OFF")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/shop/search?q=' OR '1'='1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        # Tautology returns all products
        assert data["count"] >= 5

@pytest.mark.asyncio
async def test_sqli_blocked_when_waf_block_mode():
    waf_telemetry.set_mode("BLOCK")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/shop/search?q=' OR '1'='1")
        assert resp.status_code == 403
        data = resp.json()
        assert data["status"] == "blocked_by_waf"
        assert data["attack_type"] == "SQL Injection (SQLi)"
        assert data["cwe"] == "CWE-89"

@pytest.mark.asyncio
async def test_xss_vulnerable_and_blocked():
    # 1. Vulnerable when WAF is OFF
    waf_telemetry.set_mode("OFF")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {"product_id": 1, "author": "TestAuditor", "comment": "<script>alert('xss')</script>", "rating": 5}
        resp = await client.post("/api/shop/reviews", json=payload)
        assert resp.status_code == 200
        assert "<script>alert('xss')</script>" in resp.text

    # 2. Blocked when WAF is BLOCK
    waf_telemetry.set_mode("BLOCK")
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/shop/reviews", json=payload)
        assert resp.status_code == 403
        data = resp.json()
        assert data["status"] == "blocked_by_waf"
        assert data["attack_type"] == "Cross-Site Scripting (XSS)"

@pytest.mark.asyncio
async def test_ssrf_metadata_leakage_and_blocked():
    # 1. Vulnerable when WAF is OFF
    waf_telemetry.set_mode("OFF")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
        resp = await client.post("/api/shop/fetch-preview", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "vulnerable_ssrf_confirmed"

    # 2. Blocked when WAF is BLOCK
    waf_telemetry.set_mode("BLOCK")
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/shop/fetch-preview", json=payload)
        assert resp.status_code == 403
        data = resp.json()
        assert data["status"] == "blocked_by_waf"
        assert data["attack_type"] == "Server-Side Request Forgery (SSRF)"

@pytest.mark.asyncio
async def test_security_headers_active():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/shop/products")
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Content-Security-Policy" in resp.headers
