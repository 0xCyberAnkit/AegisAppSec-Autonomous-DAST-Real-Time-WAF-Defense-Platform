import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_html_and_all_js_assets():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Main Platform Landing Page (AegisAppSec)
        resp = await client.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert "AegisAppSec" in html
        assert "Autonomous DAST Scanner" in html

        # 1b. Separate HTML Pages
        services_resp = await client.get("/services")
        assert services_resp.status_code == 200
        assert "Virtual Patch" in services_resp.text or "WAF" in services_resp.text

        auth_resp = await client.get("/auth")
        assert auth_resp.status_code == 200
        assert "AUTHENTICATION" in auth_resp.text or "SIGN IN" in auth_resp.text or "Security Console" in auth_resp.text

        # Authenticated access to protected console pages
        from app.core.auth import create_access_token
        token = create_access_token({"sub": "1", "email": "admin@aegisappsec.io", "role": "admin"})
        client.cookies.set("access_token", token)

        team_resp = await client.get("/team")
        assert team_resp.status_code == 200
        assert "Team" in team_resp.text or "RBAC" in team_resp.text

        report_resp = await client.get("/report")
        assert report_resp.status_code == 200
        assert "Report" in report_resp.text

        targets_resp = await client.get("/targets")
        assert targets_resp.status_code == 200
        assert "Targets" in targets_resp.text or "TARGET" in targets_resp.text

        # 2. All JavaScript modules
        required_scripts = [
            "app.js",
            "auth.js",
            "auth_page.js",
            "targets.js",
            "history.js",
            "compliance.js",
            "team.js",
            "waf_rules.js",
            "reports_page.js",
            "apikeys.js",
            "scanner.js",
            "vulnerabilities.js",
            "poc_viewer.js",
            "waf_monitor.js",
            "storefront.js",
            "remediation.js"
        ]

        for script in required_scripts:
            js_resp = await client.get(f"/js/{script}")
            assert js_resp.status_code == 200, f"Failed to fetch /js/{script}"
            assert len(js_resp.text) > 50, f"Script /js/{script} is unexpectedly empty"

        # 3. CSS Stylesheet
        css_resp = await client.get("/css/styles.css")
        assert css_resp.status_code == 200
        assert "iam-profile-card" in css_resp.text
        assert "test-result-box" in css_resp.text
        assert "@media print" in css_resp.text
