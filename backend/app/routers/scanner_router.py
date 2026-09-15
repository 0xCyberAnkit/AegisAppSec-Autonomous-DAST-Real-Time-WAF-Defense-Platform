from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.scanner.engine import scanner_engine
from app.scanner.crawler import DASTSpider
from app.scanner.target_validator import TargetValidator, TargetValidationError
from app.core.config import settings
from app.core.security import verify_api_key
from app.core.rate_limiter import check_rate_limit
import httpx

router = APIRouter(prefix="/api/scanner", tags=["DAST Scanner Engine"])

class CrawlRequest(BaseModel):
    target_url: str = settings.DEFAULT_TARGET_URL
    max_depth: Optional[int] = 3
    max_pages: Optional[int] = 30

@router.post("/crawl", dependencies=[Depends(check_rate_limit)])
async def trigger_crawl(payload: CrawlRequest, api_key: str = Depends(verify_api_key)):
    """Triggers autonomous DAST spider attack surface mapping for a target URL."""
    try:
        validated_url = TargetValidator.validate_target(payload.target_url)
    except TargetValidationError as e:
        raise HTTPException(status_code=400, detail=f"Target Validation Rejected: {str(e)}")

    async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
        spider = DASTSpider(max_depth=payload.max_depth or 3, max_pages=payload.max_pages or 30)
        result = await spider.crawl(client, validated_url)
        return {
            "status": "success",
            "target_url": validated_url,
            "endpoints_count": len(result.endpoints),
            "pages_visited": result.total_pages_visited,
            "duration_seconds": result.duration_seconds,
            "endpoints": [e.dict() for e in result.endpoints]
        }

class StartScanRequest(BaseModel):
    target_url: str = settings.DEFAULT_TARGET_URL
    modules: Optional[List[str]] = [
        "sqli", "xss", "cmdi", "ssrf", "csrf", "idor",
        "path_traversal", "open_redirect", "broken_auth", "misconfig",
        "cors", "xxe", "deserialization", "info_disclosure", "outdated_components"
    ]


@router.post("/start", dependencies=[Depends(check_rate_limit)])
async def start_scan(payload: StartScanRequest, api_key: str = Depends(verify_api_key)):
    """Initiates an autonomous DAST vulnerability scan."""
    result = await scanner_engine.start_scan(
        target_url=payload.target_url,
        enabled_modules=payload.modules
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result

@router.get("/status")
async def get_scan_status():
    """Retrieves current scan progress, telemetry, and findings."""
    return scanner_engine.get_summary()

@router.get("/findings")
async def get_findings():
    """Retrieves list of discovered vulnerabilities."""
    return {"findings": [f.dict() for f in scanner_engine.findings]}

@router.get("/modules")
async def list_scanner_modules():
    """Returns list of all available OWASP Top 10 vulnerability detectors."""
    return {
        "modules": [
            {"id": "sqli", "name": "SQL Injection (SQLi)", "cwe": "CWE-89", "owasp": "A03:2021", "severity": "CRITICAL"},
            {"id": "xss", "name": "Cross-Site Scripting (XSS)", "cwe": "CWE-79", "owasp": "A03:2021", "severity": "HIGH"},
            {"id": "cmdi", "name": "OS Command Injection (CMDi)", "cwe": "CWE-78", "owasp": "A03:2021", "severity": "CRITICAL"},
            {"id": "ssrf", "name": "Server-Side Request Forgery (SSRF)", "cwe": "CWE-918", "owasp": "A10:2021", "severity": "HIGH"},
            {"id": "csrf", "name": "Cross-Site Request Forgery (CSRF)", "cwe": "CWE-352", "owasp": "A01:2021", "severity": "MEDIUM"},
            {"id": "idor", "name": "Insecure Direct Object Reference (IDOR)", "cwe": "CWE-639", "owasp": "A01:2021", "severity": "HIGH"},
            {"id": "path_traversal", "name": "Path Traversal / Local File Inclusion (LFI)", "cwe": "CWE-22", "owasp": "A01:2021", "severity": "HIGH"},
            {"id": "open_redirect", "name": "Unvalidated Redirects (Open Redirect)", "cwe": "CWE-601", "owasp": "A01:2021", "severity": "MEDIUM"},
            {"id": "broken_auth", "name": "Broken Authentication & Session Flaws", "cwe": "CWE-287", "owasp": "A07:2021", "severity": "HIGH"},
            {"id": "misconfig", "name": "Security Misconfiguration & Missing Headers", "cwe": "CWE-16", "owasp": "A05:2021", "severity": "LOW"},
            {"id": "cors", "name": "CORS Misconfiguration & Origin Trust Flaws", "cwe": "CWE-942", "owasp": "A05:2021", "severity": "MEDIUM"},
            {"id": "xxe", "name": "XML External Entity Injection (XXE)", "cwe": "CWE-611", "owasp": "A05:2021", "severity": "HIGH"},
            {"id": "deserialization", "name": "Insecure Deserialization (Object Injection)", "cwe": "CWE-502", "owasp": "A08:2021", "severity": "HIGH"},
            {"id": "info_disclosure", "name": "Sensitive Data Exposure & Info Leaks", "cwe": "CWE-200", "owasp": "A02:2021", "severity": "MEDIUM"},
            {"id": "outdated_components", "name": "Vulnerable & Outdated Dependencies", "cwe": "CWE-1104", "owasp": "A06:2021", "severity": "MEDIUM"}
        ]
    }

@router.websocket("/ws")
async def websocket_scanner_feed(websocket: WebSocket):
    """Real-time WebSocket feed for live scanner matrix, logs, and findings."""
    await websocket.accept()
    scanner_engine.register_ws(websocket)
    try:
        # Send initial summary immediately upon connect
        await websocket.send_json({"type": "init", "data": scanner_engine.get_summary()})
        while True:
            # Keep connection alive; client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        scanner_engine.unregister_ws(websocket)
    except Exception:
        scanner_engine.unregister_ws(websocket)
