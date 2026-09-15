"""
ApexBank Treasury & Corporate Banking API - Target 2
Port: 8002
Vulnerabilities Demonstrated:
- Server-Side Request Forgery (SSRF / CWE-918) in /api/webhooks/test and /api/fx/feed
- Broken Authentication & Fixed Sessions (CWE-287) in /api/login
- Unvalidated Open Redirect (CWE-601) in /redirect
- Sensitive Data Exposure / Info Disclosure (CWE-200) in /api/debug/system
"""

import urllib.request
import os
import json
from pathlib import Path
from fastapi import FastAPI, Request, Form, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="ApexBank Treasury Portal (Target 2)", version="2.1.0")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Mock financial data
ACCOUNTS = {
    "ACC-9041": {"owner": "Global Logistics Corp", "balance": 4250900.50, "currency": "USD", "tier": "Institutional"},
    "ACC-1102": {"owner": "Apex Corporate Treasury", "balance": 18450200.00, "currency": "EUR", "tier": "Tier-1 Primary"}
}

FX_RATES = {
    "USD/EUR": 0.92,
    "USD/GBP": 0.79,
    "USD/JPY": 154.20,
    "BTC/USD": 68450.00
}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, session_token: str = Cookie(None)):
    user = None
    if session_token == "apex_session_master_admin":
        user = {"username": "admin", "role": "Treasury Director", "auth_level": "LEVEL-5"}
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "accounts": ACCOUNTS,
            "fx_rates": FX_RATES,
            "user": user
        }
    )

# 1. Server-Side Request Forgery (SSRF / CWE-918)
@app.post("/api/webhooks/test")
@app.get("/api/webhooks/test")
async def test_webhook(url: str = "http://127.0.0.1:8000/api/shop"):
    """
    Vulnerable Webhook Dispatch:
    Dispatches HTTP GET to arbitrary URL without loopback / cloud-metadata (169.254.169.254) filtering.
    """
    try:
        req = urllib.request.Request(
            url.strip(),
            headers={"User-Agent": "ApexBank-FinTech-Webhook-Dispatcher/2.1"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            status = resp.status
            headers = dict(resp.headers)
            return {
                "status": "success",
                "target_url": url,
                "http_status": status,
                "response_headers": headers,
                "response_body_preview": content[:2000],
                "vulnerability_note": "CWE-918 SSRF: Unrestricted outbound dispatch to internal/cloud addresses."
            }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "target_url": url,
                "message": str(e),
                "vulnerability_note": "SSRF probe attempted. Note server error or internal connection refused."
            }
        )

@app.get("/api/fx/feed")
async def fetch_external_fx_feed(source: str = "http://169.254.169.254/latest/meta-data/"):
    """SSRF vector targeting cloud metadata or internal network."""
    return await test_webhook(url=source)

# 2. Broken Authentication & Predictable Sessions (CWE-287)
@app.post("/api/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    """
    Vulnerable Login:
    Accepts hardcoded admin:admin credentials and sets non-random session cookie.
    """
    if username == "admin" and password == "admin":
        # Fixed, predictable session token
        response.set_cookie(key="session_token", value="apex_session_master_admin", httponly=False)
        return {
            "status": "success",
            "message": "Authenticated as Treasury Director",
            "session_token": "apex_session_master_admin",
            "role": "admin",
            "vulnerability_note": "CWE-287: Default administrative credentials & predictable session token."
        }
    return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid banking credentials."})

# 3. Unvalidated Open Redirect (CWE-601)
@app.get("/redirect")
async def open_redirect(url: str = "https://evil-phishing-site.com"):
    """
    Vulnerable Open Redirect:
    Redirects user to arbitrary destination URL without whitelist validation.
    """
    return RedirectResponse(url=url, status_code=302)

# 4. Sensitive Data Exposure / Information Disclosure (CWE-200)
@app.get("/api/debug/system")
async def get_system_debug_info():
    """
    Vulnerable Debug endpoint:
    Leaks environment variables, server architecture, and mock database credentials.
    """
    return {
        "status": "debug_dump",
        "service": "ApexBank Core Treasury API",
        "internal_ip": "10.240.12.89",
        "database": {
            "connection_string": "postgresql://apex_admin:SuperSecretBankKey2026!@10.240.12.95:5432/apex_treasury_prod",
            "pool_size": 20,
            "ssl_mode": "prefer"
        },
        "api_secrets": {
            "SWIFT_GATEWAY_KEY": "swift_live_sec_998141209341",
            "FEDWIRE_ROUTING_TOKEN": "fedwire_tok_99182319084"
        },
        "vulnerability_note": "CWE-200: Sensitive cryptographic secrets & database connection strings exposed."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8002, reload=True)
