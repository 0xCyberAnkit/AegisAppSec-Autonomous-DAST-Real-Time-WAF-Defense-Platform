import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.auth import create_access_token

@pytest.mark.asyncio
async def test_all_separate_html_pages():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Homepage / Platform (via / and /home)
        r_home = await client.get("/")
        assert r_home.status_code == 200
        assert "Aegis" in r_home.text
        assert "Autonomous security from scratch" in r_home.text
        assert "FIND. PROVE. FIX. DEFEND." in r_home.text

        r_home_alias = await client.get("/home")
        assert r_home_alias.status_code == 200
        assert "Aegis" in r_home_alias.text

        # Verify Public Navbar contains all public routes including /services
        assert 'href="http://test/home"' in r_home.text or 'href="http://test/"' in r_home.text
        assert 'href="http://test/scanner"' in r_home.text
        assert 'href="http://test/services"' in r_home.text
        assert 'href="http://test/pricing"' in r_home.text
        assert 'href="http://test/about"' in r_home.text
        assert 'href="http://test/contact"' in r_home.text
        assert 'Sign In' in r_home.text
        assert 'Sign Up Free' in r_home.text

        # Verify Public Command Palette on /home hides all private inner console pages
        assert 'data-url="http://test/targets"' not in r_home.text
        assert 'data-url="http://test/history"' not in r_home.text
        assert 'data-url="http://test/compliance"' not in r_home.text
        assert 'data-url="http://test/team"' not in r_home.text
        assert 'data-url="http://test/apikeys"' not in r_home.text
        assert 'data-url="http://test/report"' not in r_home.text
        assert 'data-url="http://test/storefront"' not in r_home.text

        # Verify Public Command Palette contains public routes
        assert 'data-url="http://test/services"' in r_home.text
        assert 'data-url="http://test/scanner"' in r_home.text
        assert 'data-url="http://test/pricing"' in r_home.text
        assert 'data-url="http://test/about"' in r_home.text
        assert 'data-url="http://test/contact"' in r_home.text

        # 2. Scanner Console & Detailed User Guide (Public)
        r_scanner = await client.get("/scanner")
        assert r_scanner.status_code == 200
        assert "AUTONOMOUS" in r_scanner.text
        assert "DAST ENGINE" in r_scanner.text
        assert "sk-donut-svg" in r_scanner.text
        assert "How to Use the AegisAppSec Autonomous DAST Engine" in r_scanner.text
        assert "Multi-Vector Fuzzing Detectors" in r_scanner.text

        # 2b. Pricing Page (Individuals & Companies - Public)
        r_pricing = await client.get("/pricing")
        assert r_pricing.status_code == 200
        assert "INDIVIDUALS" in r_pricing.text
        assert "COMPANIES" in r_pricing.text
        assert "Pentester Pro" in r_pricing.text
        assert "Enterprise Shield" in r_pricing.text

        # 3. Services & WAF Sandbox (Public)
        r_services = await client.get("/services")
        assert r_services.status_code == 200
        assert "APPLICATION SECURITY SUITE" in r_services.text
        assert "Autonomous DAST" in r_services.text
        assert "Interactive WAF Rule Engine" in r_services.text

        # 4. About Us & Architecture (Public)
        r_about = await client.get("/about")
        assert r_about.status_code == 200
        assert "ABOUT THE PLATFORM" in r_about.text
        assert "THE AEGISAPPSEC ADVANTAGE" in r_about.text

        # 5. Contact Page (GET & POST - Public)
        r_contact = await client.get("/contact")
        assert r_contact.status_code == 200
        assert "Contact" in r_contact.text

        r_contact_post = await client.post("/contact", data={"name": "Marcus Kane", "email": "marcus@sec.io"})
        assert r_contact_post.status_code == 200

        # 6. Auth Gateway (GET & POST - Public)
        r_auth = await client.get("/auth?mode=login")
        assert r_auth.status_code == 200
        assert "Security Console Access" in r_auth.text
        assert "SIGN IN" in r_auth.text

        # 7. Private Inner Pages Access Gate: Must redirect when unauthenticated
        private_pages = [
            "/scanner-console", "/targets", "/history", "/compliance", "/team",
            "/apikeys", "/report", "/storefront", "/waf", "/platform-hardening",
            "/virtual-patching"
        ]
        for page_route in private_pages:
            r_page = await client.get(page_route)
            assert r_page.status_code == 303, f"Unauthenticated {page_route} returned {r_page.status_code}, expected 303 redirect"
            assert "/auth?mode=login" in r_page.headers["location"]

        # 8. Authenticated Access: Setting valid access_token cookie unlocks private pages
        token = create_access_token({"sub": "1", "email": "admin@aegisappsec.io", "role": "admin"})
        client.cookies.set("access_token", token)

        for page_route in private_pages:
            r_auth_page = await client.get(page_route)
            assert r_auth_page.status_code == 200, f"Authenticated {page_route} returned {r_auth_page.status_code}"
            assert "Aegis" in r_auth_page.text

        # 9. Authenticated Command Palette & Navbar include all private console pages
        r_auth_targets = await client.get("/targets")
        assert 'data-url="http://test/targets"' in r_auth_targets.text
        assert 'data-url="http://test/compliance"' in r_auth_targets.text
        assert 'data-url="http://test/waf"' in r_auth_targets.text
        assert 'data-url="http://test/platform-hardening"' in r_auth_targets.text
        assert 'data-url="http://test/virtual-patching"' in r_auth_targets.text
        assert 'Sign Out' in r_auth_targets.text
        assert 'sk-nav-console' in r_auth_targets.text
        assert 'href="http://test/scanner-console"' in r_auth_targets.text
        assert 'href="http://test/targets"' in r_auth_targets.text
        assert 'href="http://test/history"' in r_auth_targets.text
        assert 'href="http://test/compliance"' in r_auth_targets.text
        assert 'href="http://test/waf"' in r_auth_targets.text
        assert 'href="http://test/platform-hardening"' in r_auth_targets.text
        assert 'href="http://test/virtual-patching"' in r_auth_targets.text
        assert 'href="http://test/team"' in r_auth_targets.text
        assert 'href="http://test/apikeys"' in r_auth_targets.text
        assert 'href="http://test/report"' in r_auth_targets.text
        assert 'href="http://test/storefront"' in r_auth_targets.text

@pytest.mark.asyncio
async def test_static_assets():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Style CSS
        r_css = await client.get("/static/css/style.css")
        assert r_css.status_code == 200
        assert len(r_css.text) > 1000

        # Main JS
        r_js = await client.get("/static/js/main.js")
        assert r_js.status_code == 200
        assert len(r_js.text) > 1000

        # Emblem image
        r_img = await client.get("/static/img/aegis_emblem.png")
        assert r_img.status_code == 200

@pytest.mark.asyncio
async def test_web_supporting_apis():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Metrics
        r_met = await client.get("/api/metrics")
        assert r_met.status_code == 200
        assert "endpoints_discovered" in r_met.json()["data"]

        # Vulnerabilities
        r_vulns = await client.get("/api/vulnerabilities")
        assert r_vulns.status_code == 200
        assert r_vulns.json()["count"] >= 5

        # Scan simulation
        r_sim = await client.post("/api/scan/simulate", json={"target_url": "https://example.com"})
        assert r_sim.status_code == 200
        assert len(r_sim.json()["events"]) >= 5
