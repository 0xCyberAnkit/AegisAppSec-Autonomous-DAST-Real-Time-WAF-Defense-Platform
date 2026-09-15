from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any

from app.waf_shield.telemetry import waf_telemetry
from app.core.security import verify_api_key
from app.core.rate_limiter import check_rate_limit

router = APIRouter(prefix="/api/waf", tags=["Aegis-Shield WAF Control"])

class ModeChangeRequest(BaseModel):
    mode: str  # OFF, DETECT, BLOCK, SANITIZE

@router.get("/metrics")
async def get_waf_metrics():
    """Returns live telemetry, blocked attacks, and active defense status."""
    return waf_telemetry.get_metrics()

@router.post("/mode", dependencies=[Depends(check_rate_limit)])
async def update_waf_mode(payload: ModeChangeRequest, api_key: str = Depends(verify_api_key)):
    """Switches WAF operational mode (OFF / DETECT / BLOCK / SANITIZE)."""
    valid = {"OFF", "DETECT", "BLOCK", "SANITIZE"}
    mode_upper = payload.mode.upper()
    if mode_upper not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid WAF mode '{payload.mode}'. Must be one of {valid}")
    
    applied_mode = waf_telemetry.set_mode(mode_upper)
    return {
        "status": "success",
        "message": f"Aegis-Shield WAF mode successfully changed to {applied_mode}.",
        "mode": applied_mode
    }

@router.post("/clear", dependencies=[Depends(check_rate_limit)])
async def clear_waf_metrics(api_key: str = Depends(verify_api_key)):
    """Clears WAF telemetry counters and event history."""
    waf_telemetry.clear_metrics()
    return {"status": "success", "message": "WAF telemetry metrics reset."}

@router.get("/rules")
async def get_waf_rules():
    """Lists all active heuristic and regex inspection rules in Aegis-Shield."""
    return {
        "rules": [
            {"id": "SQLI-001", "name": "UNION SELECT Data Exfiltration", "category": "SQLi", "action": "Block/Sanitize"},
            {"id": "SQLI-002", "name": "Tautological Boolean Injection", "category": "SQLi", "action": "Block/Sanitize"},
            {"id": "SQLI-003", "name": "SQL Comment Termination Vector", "category": "SQLi", "action": "Block/Sanitize"},
            {"id": "SQLI-004", "name": "Time-Based Delay Attack", "category": "SQLi", "action": "Block/Sanitize"},
            {"id": "XSS-001", "name": "Raw Script Tag Injection", "category": "XSS", "action": "Block/Sanitize"},
            {"id": "XSS-002", "name": "Malicious URI Protocol Scheme", "category": "XSS", "action": "Block/Sanitize"},
            {"id": "XSS-003", "name": "Inline DOM Event Handler", "category": "XSS", "action": "Block/Sanitize"},
            {"id": "XSS-004", "name": "Active HTML Tag Injection", "category": "XSS", "action": "Block/Sanitize"},
            {"id": "SSRF-001", "name": "Cloud Instance Metadata Access", "category": "SSRF", "action": "Block"},
            {"id": "SSRF-002", "name": "Loopback Interface Access Attempt", "category": "SSRF", "action": "Block"},
            {"id": "LFI-001", "name": "Directory Path Traversal", "category": "Path Traversal", "action": "Block"},
            {"id": "EVASION-01", "name": "Recursive URL Multi-Decoding", "category": "Evasion Defense", "action": "Normalize & Inspect"},
            {"id": "EVASION-02", "name": "Unicode Homoglyph Normalization (NFKC)", "category": "Evasion Defense", "action": "Normalize & Inspect"},
            {"id": "EVASION-03", "name": "Null-Byte Injection Stripping", "category": "Evasion Defense", "action": "Normalize & Inspect"}
        ]
    }
