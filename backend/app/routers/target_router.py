import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db import models
from app.core.auth import get_current_user_optional
from app.governance.domain_verifier import DomainVerifier

router = APIRouter(prefix="/api/targets", tags=["Target Governance & Verification"])

class CreateTargetRequest(BaseModel):
    name: str
    domain: str
    base_url: str
    verification_method: Optional[str] = "HTTP_WELL_KNOWN" # HTTP_WELL_KNOWN, HTML_META, DNS_TXT

PRE_SEEDED_LOCAL_TARGETS = [
    {"name": "VoltMart Tech E-Commerce Store", "domain": "127.0.0.1:8001", "base_url": "http://127.0.0.1:8001"},
    {"name": "ApexBank Treasury & FX API", "domain": "127.0.0.1:8002", "base_url": "http://127.0.0.1:8002"},
    {"name": "PulseHealth Hospital EHR System", "domain": "127.0.0.1:8003", "base_url": "http://127.0.0.1:8003"},
    {"name": "CloudOps Infrastructure Console", "domain": "127.0.0.1:8004", "base_url": "http://127.0.0.1:8004"},
]

@router.get("")
def list_targets(db: Session = Depends(get_db)):
    """Lists all registered targets with verification status."""
    # Ensure local test targets exist
    existing_domains = {t.domain for t in db.query(models.Target.domain).all()}
    added_any = False
    for pt in PRE_SEEDED_LOCAL_TARGETS:
        if pt["domain"] not in existing_domains:
            new_t = models.Target(
                name=pt["name"],
                domain=pt["domain"],
                base_url=pt["base_url"],
                verification_method="HTTP_WELL_KNOWN",
                verification_token=DomainVerifier.generate_token(),
                is_verified=True,
                verified_at=datetime.datetime.utcnow()
            )
            db.add(new_t)
            added_any = True
    if added_any:
        db.commit()

    targets = db.query(models.Target).order_by(models.Target.id.asc()).all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "domain": t.domain,
            "base_url": t.base_url,
            "verification_method": t.verification_method,
            "verification_token": t.verification_token,
            "is_verified": t.is_verified,
            "verified_at": t.verified_at.isoformat() if t.verified_at else None,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "scans_count": len(t.scans)
        }
        for t in targets
    ]

@router.post("")
def register_target(
    req: CreateTargetRequest,
    user: Optional[dict] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """Registers a new target domain and generates a cryptographic verification token."""
    # Clean domain and base_url
    domain_clean = req.domain.strip().lower()
    if "://" in domain_clean:
        domain_clean = domain_clean.split("://")[1]
    domain_clean = domain_clean.split("/")[0].strip()

    base_url_clean = req.base_url.strip()
    if not (base_url_clean.startswith("http://") or base_url_clean.startswith("https://")):
        base_url_clean = "https://" + base_url_clean

    token = DomainVerifier.generate_token()
    user_id = int(user.get("sub")) if user else None

    # Auto-verify localhost/127.0.0.1 testbeds
    is_auto_verified = (
        domain_clean.startswith("127.0.0.1") or
        domain_clean.startswith("localhost") or
        domain_clean in ("127.0.0.1:8000", "localhost:8000", "127.0.0.1", "localhost")
    )

    target = models.Target(
        user_id=user_id,
        name=req.name.strip(),
        domain=domain_clean,
        base_url=base_url_clean,
        verification_method=req.verification_method or "HTTP_WELL_KNOWN",
        verification_token=token,
        is_verified=is_auto_verified,
        verified_at=datetime.datetime.utcnow() if is_auto_verified else None
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    return {
        "status": "success",
        "message": "Target registered. Please complete domain verification." if not is_auto_verified else "Local benchmark target automatically verified.",
        "target": {
            "id": target.id,
            "name": target.name,
            "domain": target.domain,
            "base_url": target.base_url,
            "verification_method": target.verification_method,
            "verification_token": target.verification_token,
            "is_verified": target.is_verified,
            "instructions": _get_instructions(target.verification_method, target.domain, target.verification_token)
        }
    }

@router.post("/{target_id}/verify")
async def verify_target_domain(
    target_id: int, 
    force: bool = False,
    db: Session = Depends(get_db)
):
    """Runs active domain verification check (HTTP / Meta / DNS) with optional SecOps override."""
    target = db.query(models.Target).filter_by(id=target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    if force:
        target.is_verified = True
        target.verified_at = datetime.datetime.utcnow()
        db.commit()
        return {
            "status": "success",
            "is_verified": True,
            "message": f"Domain '{target.domain}' successfully authorized via Enterprise Security Administrator Override."
        }

    is_valid, reason = await DomainVerifier.verify_target(
        domain=target.domain,
        base_url=target.base_url,
        method=target.verification_method,
        expected_token=target.verification_token
    )

    if is_valid:
        target.is_verified = True
        target.verified_at = datetime.datetime.utcnow()
        db.commit()
        return {
            "status": "success",
            "is_verified": True,
            "message": reason
        }
    else:
        return {
            "status": "failed",
            "is_verified": False,
            "message": reason,
            "instructions": _get_instructions(target.verification_method, target.domain, target.verification_token)
        }

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    """Removes a target and its associated scan records."""
    target = db.query(models.Target).filter_by(id=target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    db.delete(target)
    db.commit()
    return {"status": "success", "message": f"Target '{target.name}' deleted."}

def _get_instructions(method: str, domain: str, token: str) -> dict:
    if method == "HTTP_WELL_KNOWN":
        return {
            "method": "HTTP File Upload",
            "file_url": f"http://{domain}/.well-known/aegis-verification.txt",
            "required_content": token,
            "help": f"Create a text file containing '{token}' and host it at /.well-known/aegis-verification.txt"
        }
    elif method == "HTML_META":
        return {
            "method": "HTML Meta Tag",
            "tag": f'<meta name="aegis-verification" content="{token}">',
            "help": "Add this <meta> tag inside the <head> section of your website's home page."
        }
    else:
        return {
            "method": "DNS TXT Record",
            "record_type": "TXT",
            "host": f"@{domain}",
            "value": f"aegis-verification={token}",
            "help": f"Add a DNS TXT record for {domain} with the value aegis-verification={token}"
        }
