import httpx
import time

def main():
    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0)

    # 1. Test Dashboard HTML
    r1 = client.get("/")
    print(f"[1] Dashboard HTML: HTTP {r1.status_code} ({len(r1.text)} bytes)")
    assert "AEGIS // APPSEC" in r1.text

    # 2. Set WAF mode to OFF
    r_mode = client.post("/api/waf/mode", json={"mode": "OFF"})
    print(f"[2] Set WAF OFF: {r_mode.json()}")

    # 3. Start DAST Scan against testbed
    r_scan = client.post("/api/scanner/start", json={"target_url": "http://127.0.0.1:8000/api/shop"})
    print(f"[3] Started DAST Scan: {r_scan.json()}")

    # 4. Wait for scan pipeline completion
    status = {}
    for i in range(20):
        time.sleep(1)
        status = client.get("/api/scanner/status").json()
        print(f"    Progress: {status.get('progress')}% | Status: {status.get('status')}")
        if status.get("status") in ("COMPLETED", "FAILED"):
            break

    findings = status.get("findings", [])
    print(f"[4] Scan Finished! Discovered {len(findings)} confirmed vulnerabilities:")
    for f in findings:
        print(f"    -> [{f.get('severity')}] {f.get('title')} (CVSS {f.get('cvss_score')}) | CWE: {f.get('cwe_id')}")

    assert len(findings) >= 4, f"Expected at least 4 findings, got {len(findings)}"

    # 5. Test WAF BLOCK mode
    client.post("/api/waf/mode", json={"mode": "BLOCK"})
    r_sqli_blocked = client.get("/api/shop/search?q=' OR '1'='1")
    print(f"[5] SQLi attack under WAF BLOCK mode: HTTP {r_sqli_blocked.status_code} - {r_sqli_blocked.json().get('status')}")
    assert r_sqli_blocked.status_code == 403

    # 6. Verify WAF Telemetry
    telemetry = client.get("/api/waf/metrics").json()
    print(f"[6] WAF Blocked count: {telemetry.get('total_blocked')} | Threat Level: {telemetry.get('active_threat_level')}")
    assert telemetry.get("total_blocked") >= 1

    # 7. Test Executive Reports (HTML, Markdown, CSV)
    r_html = client.get("/api/reports/export/html")
    print(f"[7] Executive HTML Report: HTTP {r_html.status_code} ({len(r_html.text)} bytes)")
    assert "Executive Security Audit Report" in r_html.text

    r_md = client.get("/api/reports/export/markdown")
    print(f"[8] Markdown Report Export: HTTP {r_md.status_code} ({len(r_md.text)} bytes)")
    assert "Vulnerability Findings" in r_md.text

    r_csv = client.get("/api/reports/export/csv")
    print(f"[9] CSV Findings Export: HTTP {r_csv.status_code} ({len(r_csv.text)} bytes)")
    assert "CVSS_Score" in r_csv.text

    # 10. Test Enterprise Auth & Demo Switcher
    r_auth = client.post("/api/auth/demo-login", json={"role": "admin"})
    print(f"[10] Auth Persona Switch: HTTP {r_auth.status_code} - Role: {r_auth.json().get('user', {}).get('role')}")
    assert r_auth.status_code == 200

    # 11. Test WAF Virtual Patching Studio
    r_sim = client.post("/api/waf/custom-rules/test", json={"payload": "1' UNION SELECT user, pass FROM accounts--"})
    print(f"[11] Virtual Patch Simulation: HTTP {r_sim.status_code} - Blocked: {r_sim.json().get('is_blocked')}")
    assert r_sim.status_code == 200

    # 12. Test Team & RBAC
    r_team = client.get("/api/team/members")
    print(f"[12] Team Roster: HTTP {r_team.status_code} - Active Members: {r_team.json().get('count')}")
    assert r_team.status_code == 200

    # 13. Test Compliance
    r_comp = client.get("/api/compliance/summary")
    print(f"[13] Compliance Scorecard: HTTP {r_comp.status_code} - Score: {r_comp.json().get('overall_score_percentage')}%")
    assert r_comp.status_code == 200

    print("\n============================================================")
    print("  SUCCESS: ALL 13 ENTERPRISE PIPELINE CHECKS PASSED!")
    print("============================================================")

if __name__ == "__main__":
    main()
