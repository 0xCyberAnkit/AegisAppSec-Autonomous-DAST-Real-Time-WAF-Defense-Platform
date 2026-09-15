from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
import re
import datetime

from app.db.session import get_db
from app.db import models
from app.core.auth import get_current_user_optional

router = APIRouter(prefix="/api/waf/custom-rules", tags=["WAF Virtual Patching Studio"])

class CreateCustomRuleRequest(BaseModel):
    name: str
    pattern: str
    action: str = "BLOCK" # BLOCK, DETECT, SANITIZE
    description: Optional[str] = None

class TestPayloadRequest(BaseModel):
    payload: str
    target_field: Optional[str] = "Query Parameter"

DEFAULT_PRESET_RULES = [
    {
        "name": "Virtual Patch // SQLi Sleep & Benchmark Injection",
        "pattern": r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+\s*,|waitfor\s+delay)",
        "action": "BLOCK",
        "description": "Zero-day mitigation against blind time-based database extraction probes."
    },
    {
        "name": "Virtual Patch // SSRF AWS IMDSv2 & Alibaba Metadata",
        "pattern": r"(?i)(169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal)",
        "action": "BLOCK",
        "description": "Virtual patch intercepting cloud instance metadata exfiltration."
    },
    {
        "name": "Virtual Patch // DOM XSS SVG OnLoad & Fetch Hijack",
        "pattern": r"(?i)(<svg[^>]*onload\s*=|fetch\s*\(\s*['\"]https?://)",
        "action": "SANITIZE",
        "description": "Emergency filter neutralizing SVG and outbound credential theft scripts."
    }
]

def ensure_default_rules(db: Session):
    existing = db.query(models.WafCustomRule).count()
    if existing == 0:
        for r in DEFAULT_PRESET_RULES:
            rule = models.WafCustomRule(
                name=r["name"],
                pattern=r["pattern"],
                action=r["action"],
                description=r["description"],
                is_active=True
            )
            db.add(rule)
        db.commit()

@router.get("")
async def list_custom_rules(db: Session = Depends(get_db)):
    """Lists all active and configured custom virtual patch rules."""
    ensure_default_rules(db)
    rules = db.query(models.WafCustomRule).order_by(models.WafCustomRule.id.desc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "pattern": r.pattern,
            "action": r.action,
            "description": r.description or "",
            "is_active": r.is_active,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in rules
    ]

@router.post("")
async def create_custom_rule(
    payload: CreateCustomRuleRequest,
    db: Session = Depends(get_db),
    current_user: Optional[models.User] = Depends(get_current_user_optional)
):
    """Creates and deploys a new virtual patch regex rule into the live WAF inspection engine."""
    # Validate regex
    try:
        re.compile(payload.pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid Regular Expression syntax: {str(e)}")
        
    rule = models.WafCustomRule(
        user_id=current_user.id if current_user else None,
        name=payload.name,
        pattern=payload.pattern,
        action=payload.action.upper(),
        description=payload.description or f"Custom virtual patch created {datetime.date.today()}",
        is_active=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {
        "status": "success",
        "message": f"Virtual patch '{rule.name}' successfully deployed to live WAF inspection filter.",
        "rule": {
            "id": rule.id,
            "name": rule.name,
            "pattern": rule.pattern,
            "action": rule.action,
            "description": rule.description,
            "is_active": rule.is_active
        }
    }

@router.patch("/{rule_id}/toggle")
async def toggle_custom_rule(rule_id: int, db: Session = Depends(get_db)):
    """Toggles a virtual patch rule between ACTIVE and INACTIVE."""
    rule = db.query(models.WafCustomRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")
    rule.is_active = not rule.is_active
    db.commit()
    return {
        "status": "success",
        "message": f"Rule '{rule.name}' status toggled to {'ACTIVE' if rule.is_active else 'INACTIVE'}.",
        "is_active": rule.is_active
    }

@router.delete("/{rule_id}")
async def delete_custom_rule(rule_id: int, db: Session = Depends(get_db)):
    """Deletes a custom virtual patch rule."""
    rule = db.query(models.WafCustomRule).filter_by(id=rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")
    db.delete(rule)
    db.commit()
    return {"status": "success", "message": f"Rule #{rule_id} removed."}

@router.post("/test")
async def test_virtual_patch(payload: TestPayloadRequest, db: Session = Depends(get_db)):
    """Simulates a payload against all active virtual patches without sending real traffic."""
    ensure_default_rules(db)
    rules = db.query(models.WafCustomRule).filter_by(is_active=True).all()
    
    matches = []
    text = payload.payload or ""
    for r in rules:
        try:
            compiled = re.compile(r.pattern, re.IGNORECASE)
            match = compiled.search(text)
            if match:
                matches.append({
                    "rule_id": r.id,
                    "rule_name": r.name,
                    "action": r.action,
                    "matched_substring": match.group(0),
                    "match_span": match.span()
                })
        except Exception:
            continue
            
    return {
        "tested_payload": text,
        "is_blocked": any(m["action"] == "BLOCK" for m in matches),
        "match_count": len(matches),
        "matches": matches,
        "recommendation": "Blocked by Virtual Patch" if matches else "Payload Passed - No Rule Triggered"
    }
