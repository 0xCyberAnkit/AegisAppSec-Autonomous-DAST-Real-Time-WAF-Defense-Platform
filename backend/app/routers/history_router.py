from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db import models

router = APIRouter(prefix="/api/history", tags=["Scan History & Vulnerability Regression"])

class StatusUpdateRequest(BaseModel):
    status: str # OPEN, RESOLVED, FALSE_POSITIVE

@router.get("/scans")
def get_scan_history(target_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Returns past historical scan runs."""
    query = db.query(models.ScanRun)
    if target_id:
        query = query.filter(models.ScanRun.target_id == target_id)
    
    scans = query.order_by(models.ScanRun.started_at.desc()).limit(50).all()
    return [
        {
            "id": s.id,
            "target_id": s.target_id,
            "target_name": s.target.name if s.target else "Ad-hoc Target",
            "target_url": s.target_url,
            "status": s.status,
            "triggered_by": s.triggered_by,
            "findings_count": s.findings_count,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "low_count": s.low_count,
            "avg_cvss": s.avg_cvss,
            "duration_seconds": s.duration_seconds,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]

@router.get("/scans/{scan_id}")
def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Returns details and all findings for a specific scan run."""
    scan = db.query(models.ScanRun).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found.")

    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "target_name": scan.target.name if scan.target else "Ad-hoc Target",
        "target_url": scan.target_url,
        "status": scan.status,
        "findings_count": scan.findings_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "avg_cvss": scan.avg_cvss,
        "duration_seconds": scan.duration_seconds,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings": [
            {
                "id": f.id,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "title": f.title,
                "cwe_id": f.cwe_id,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "endpoint": f.endpoint,
                "parameter": f.parameter,
                "poc_curl": f.poc_curl,
                "status": f.status,
                "created_at": f.created_at.isoformat() if f.created_at else None
            }
            for f in scan.findings
        ]
    }

@router.get("/diff")
def compare_scans(base_scan_id: str, target_scan_id: str, db: Session = Depends(get_db)):
    """Compares two scans to identify resolved vulnerabilities, persistent flaws, and new regressions."""
    base_scan = db.query(models.ScanRun).filter_by(id=base_scan_id).first()
    target_scan = db.query(models.ScanRun).filter_by(id=target_scan_id).first()

    if not base_scan or not target_scan:
        raise HTTPException(status_code=404, detail="One or both scan runs not found.")

    base_keys = {f"{f.cwe_id}::{f.endpoint}::{f.parameter}": f for f in base_scan.findings}
    target_keys = {f"{f.cwe_id}::{f.endpoint}::{f.parameter}": f for f in target_scan.findings}

    # Fixed: in base but not in target
    fixed_keys = set(base_keys.keys()) - set(target_keys.keys())
    # New: in target but not in base
    new_keys = set(target_keys.keys()) - set(base_keys.keys())
    # Persistent: in both
    persistent_keys = set(base_keys.keys()) & set(target_keys.keys())

    return {
        "base_scan_id": base_scan_id,
        "target_scan_id": target_scan_id,
        "base_scan_name": base_scan.triggered_by or base_scan.id,
        "target_scan_name": target_scan.triggered_by or target_scan.id,
        "base_target_url": base_scan.target_url,
        "target_target_url": target_scan.target_url,
        "metrics": {
            "fixed_count": len(fixed_keys),
            "new_count": len(new_keys),
            "persistent_count": len(persistent_keys),
            "base_total": len(base_keys),
            "target_total": len(target_keys)
        },
        "fixed_vulnerabilities": [
            {
                "title": base_keys[k].title,
                "severity": base_keys[k].severity,
                "cwe_id": base_keys[k].cwe_id,
                "cvss_score": base_keys[k].cvss_score,
                "vuln_type": base_keys[k].vuln_type,
                "endpoint": base_keys[k].endpoint,
                "parameter": base_keys[k].parameter
            }
            for k in fixed_keys
        ],
        "new_regressions": [
            {
                "title": target_keys[k].title,
                "severity": target_keys[k].severity,
                "cwe_id": target_keys[k].cwe_id,
                "cvss_score": target_keys[k].cvss_score,
                "vuln_type": target_keys[k].vuln_type,
                "endpoint": target_keys[k].endpoint,
                "parameter": target_keys[k].parameter
            }
            for k in new_keys
        ],
        "persistent_vulnerabilities": [
            {
                "title": target_keys[k].title,
                "severity": target_keys[k].severity,
                "cwe_id": target_keys[k].cwe_id,
                "cvss_score": target_keys[k].cvss_score,
                "vuln_type": target_keys[k].vuln_type,
                "endpoint": target_keys[k].endpoint,
                "parameter": target_keys[k].parameter
            }
            for k in persistent_keys
        ]
    }

@router.patch("/findings/{finding_id}/status")
def update_finding_status(finding_id: int, req: StatusUpdateRequest, db: Session = Depends(get_db)):
    """Updates vulnerability status (OPEN, RESOLVED, FALSE_POSITIVE)."""
    finding = db.query(models.FindingRecord).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    
    finding.status = req.status.upper()
    db.commit()
    return {"status": "success", "finding_id": finding_id, "new_status": finding.status}
