import asyncio
import datetime
import time
import httpx
from app.worker.celery_app import celery_app
from app.db.session import SessionLocal
from app.db import models
from app.scanner.engine import scanner_engine

async def _run_scan_and_persist(scan_id: str, target_url: str, enabled_modules: list):
    """Core logic that executes the DAST scan and writes results to MySQL/SQLite."""
    start_time = time.time()
    db = SessionLocal()
    
    # 1. Update status to RUNNING
    scan_run = db.query(models.ScanRun).filter_by(id=scan_id).first()
    if scan_run:
        scan_run.status = "RUNNING"
        scan_run.started_at = datetime.datetime.utcnow()
        db.commit()

    try:
        # 2. Run the DAST Engine
        findings = await scanner_engine.start_scan(target_url=target_url, enabled_modules=enabled_modules)
        duration = round(time.time() - start_time, 2)

        # 3. Process findings & compute metrics
        crit_c = sum(1 for f in findings if f.severity == "CRITICAL")
        high_c = sum(1 for f in findings if f.severity == "HIGH")
        med_c = sum(1 for f in findings if f.severity == "MEDIUM")
        low_c = sum(1 for f in findings if f.severity == "LOW")
        avg_cvss = round(sum(f.cvss_score for f in findings) / len(findings), 1) if findings else 0.0

        # 4. Save findings to DB
        scan_run = db.query(models.ScanRun).filter_by(id=scan_id).first()
        if scan_run:
            scan_run.status = "COMPLETED"
            scan_run.completed_at = datetime.datetime.utcnow()
            scan_run.findings_count = len(findings)
            scan_run.critical_count = crit_c
            scan_run.high_count = high_c
            scan_run.medium_count = med_c
            scan_run.low_count = low_c
            scan_run.avg_cvss = avg_cvss
            scan_run.duration_seconds = duration

            for f in findings:
                finding_rec = models.FindingRecord(
                    scan_id=scan_id,
                    target_id=scan_run.target_id,
                    vuln_type=f.vuln_type,
                    severity=f.severity,
                    title=f.title,
                    cwe_id=f.cwe_id,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    endpoint=f.endpoint,
                    parameter=f.parameter,
                    poc_curl=f.poc_curl,
                    status="OPEN"
                )
                db.add(finding_rec)

            db.commit()

        # 5. Dispatch Webhook Alerts (Slack/Teams/SIEM)
        webhooks = db.query(models.WebhookRecord).filter_by(is_active=True).all()
        for wh in webhooks:
            await _dispatch_webhook_alert(wh.url, scan_id, target_url, len(findings), crit_c, high_c)

    except Exception as e:
        print(f"[Aegis Worker Error] Scan {scan_id} failed: {e}")
        scan_run = db.query(models.ScanRun).filter_by(id=scan_id).first()
        if scan_run:
            scan_run.status = "FAILED"
            scan_run.completed_at = datetime.datetime.utcnow()
            db.commit()
    finally:
        db.close()

async def _dispatch_webhook_alert(url: str, scan_id: str, target: str, total_vulns: int, crit: int, high: int):
    """Sends JSON notification payload to configured webhook."""
    payload = {
        "event": "scan_completed",
        "scanner": "AegisAppSec Autonomous DAST",
        "scan_id": scan_id,
        "target_url": target,
        "total_vulnerabilities": total_vulns,
        "critical_count": crit,
        "high_count": high,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action_required": crit > 0 or high > 0
    }
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            await client.post(url, json=payload)
    except Exception as e:
        print(f"[Aegis Webhook] Notice: Webhook delivery to {url} returned: {e}")

@celery_app.task(name="app.worker.tasks.run_dast_scan_task")
def run_dast_scan_task(scan_id: str, target_url: str, enabled_modules: list):
    """Celery worker task entry point."""
    asyncio.run(_run_scan_and_persist(scan_id, target_url, enabled_modules))
    return {"status": "success", "scan_id": scan_id}

def dispatch_scan_job(scan_id: str, target_url: str, enabled_modules: list):
    """Smart dispatcher: Enqueues to Celery worker if available; falls back to in-process async task."""
    try:
        # Attempt Celery task queuing
        run_dast_scan_task.delay(scan_id, target_url, enabled_modules)
        print(f"[Aegis Dispatcher] Scan {scan_id} queued to Celery distributed worker.")
    except Exception as e:
        # Fallback to local background asyncio task
        print(f"[Aegis Dispatcher] Redis/Celery offline ({e}). Running via async worker fallback.")
        asyncio.create_task(_run_scan_and_persist(scan_id, target_url, enabled_modules))
