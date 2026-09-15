import pytest
import time
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_auth_gateway_get():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # GET /auth
        r = await client.get("/auth")
        assert r.status_code == 200
        assert "AUTHENTICATION GATEWAY" in r.text
        assert "SIGN IN" in r.text
        assert "CREATE WORKSPACE" in r.text
        assert "FOR INDIVIDUALS &amp; PENTESTERS" in r.text or "FOR INDIVIDUALS" in r.text
        assert "FOR COMPANIES &amp; TEAMS" in r.text or "FOR COMPANIES" in r.text
        assert "1-CLICK DEMO CREDENTIALS" in r.text

        # GET /auth?mode=register
        r_reg = await client.get("/auth?mode=register")
        assert r_reg.status_code == 200
        assert "id=\"registerForm\"" in r_reg.text

@pytest.mark.asyncio
async def test_auth_login_and_logout():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Valid Admin Login
        login_res = await client.post(
            "/auth",
            data={
                "auth_mode": "login",
                "email": "admin@aegisappsec.io",
                "password": "AegisSec2026!#"
            },
            follow_redirects=False
        )
        assert login_res.status_code in (302, 303)
        assert "/targets" in login_res.headers.get("location", "")
        assert "access_token" in login_res.cookies

        # Invalid Login
        fail_res = await client.post(
            "/auth",
            data={
                "auth_mode": "login",
                "email": "admin@aegisappsec.io",
                "password": "CompletelyWrongPassword"
            },
            follow_redirects=False
        )
        assert fail_res.status_code == 401
        assert "Invalid email or security passphrase" in fail_res.text

        # Logout
        logout_res = await client.get("/logout", follow_redirects=False)
        assert logout_res.status_code in (302, 303)
        assert "/auth?mode=login" in logout_res.headers.get("location", "")

@pytest.mark.asyncio
async def test_auth_register_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unique_email = f"lead_{int(time.time())}@defensecorp.sec"
        
        # Successful Registration
        reg_res = await client.post(
            "/auth",
            data={
                "auth_mode": "register",
                "name": "Alex Vance",
                "email": unique_email,
                "password": "SecurePassword123!#",
                "org": "Cyber Defense Inc"
            },
            follow_redirects=False
        )
        assert reg_res.status_code in (302, 303)
        assert "/targets" in reg_res.headers.get("location", "")
        assert "access_token" in reg_res.cookies

        # Duplicate Registration
        dup_res = await client.post(
            "/auth",
            data={
                "auth_mode": "register",
                "name": "Alex Vance",
                "email": unique_email,
                "password": "SecurePassword123!#",
                "org": "Cyber Defense Inc"
            },
            follow_redirects=False
        )
        assert dup_res.status_code == 400
        assert "already exists" in dup_res.text
