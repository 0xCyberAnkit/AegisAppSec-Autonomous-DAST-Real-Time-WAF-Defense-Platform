"""
Integration tests for the 4 autonomous web targets in web_targets/
"""

import pytest
from httpx import AsyncClient, ASGITransport
from web_targets.target1_ecommerce.app import app as app_t1
from web_targets.target2_fintech.app import app as app_t2
from web_targets.target3_healthcare.app import app as app_t3
from web_targets.target4_devops.app import app as app_t4

@pytest.mark.asyncio
async def test_target1_ecommerce():
    transport = ASGITransport(app=app_t1)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # UI Home
        r = await client.get("/")
        assert r.status_code == 200
        assert "VoltMart" in r.text
        assert "CyberDeck" in r.text

        # SQLi
        r_sqli = await client.get("/search?q=' OR '1'='1")
        assert r_sqli.status_code == 200
        data = r_sqli.json()
        assert data["status"] == "success"
        assert len(data["data"]) >= 4

        # IDOR
        r_idor = await client.get("/api/orders/1")
        assert r_idor.status_code == 200
        assert "Marcus Vance" in r_idor.json()["customer_name"]

@pytest.mark.asyncio
async def test_target2_fintech():
    transport = ASGITransport(app=app_t2)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # UI Home
        r = await client.get("/")
        assert r.status_code == 200
        assert "ApexBank" in r.text

        # SSRF (mock loopback or external)
        r_ssrf = await client.get("/api/webhooks/test?url=http://example.com")
        assert r_ssrf.status_code in (200, 500) # Response or connection handled

        # Open Redirect
        r_red = await client.get("/redirect?url=https://example.com", follow_redirects=False)
        assert r_red.status_code == 302
        assert r_red.headers["location"] == "https://example.com"

        # Sensitive Data Exposure
        r_debug = await client.get("/api/debug/system")
        assert r_debug.status_code == 200
        assert "postgresql://" in r_debug.json()["database"]["connection_string"]

@pytest.mark.asyncio
async def test_target3_healthcare():
    transport = ASGITransport(app=app_t3)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # UI Home
        r = await client.get("/")
        assert r.status_code == 200
        assert "PulseHealth" in r.text

        # Path Traversal / LFI
        r_lfi = await client.get("/records/download?file=patient_1001.txt")
        assert r_lfi.status_code == 200
        assert "PATIENT: Jane Doe" in r_lfi.text

        r_lfi_trav = await client.get("/records/download?file=../../../../etc/passwd")
        assert r_lfi_trav.status_code == 200
        assert "root:x:0:0" in r_lfi_trav.text

        # CORS
        r_cors = await client.get("/api/patient/1001", headers={"Origin": "https://evil.corp"})
        assert r_cors.status_code == 200
        assert r_cors.headers["access-control-allow-origin"] == "https://evil.corp"
        assert r_cors.headers["access-control-allow-credentials"] == "true"

@pytest.mark.asyncio
async def test_target4_devops():
    transport = ASGITransport(app=app_t4)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # UI Home
        r = await client.get("/")
        assert r.status_code == 200
        assert "CloudOps" in r.text
        assert "X-Powered-By" in r.headers
        assert "PHP/5.2.4" in r.headers["X-Powered-By"]

        # CMDi
        r_cmdi = await client.get("/api/tools/ping?host=127.0.0.1%20%26%26%20echo%20CMD_TEST")
        assert r_cmdi.status_code == 200
        assert "CMD_TEST" in r_cmdi.json()["output"]
