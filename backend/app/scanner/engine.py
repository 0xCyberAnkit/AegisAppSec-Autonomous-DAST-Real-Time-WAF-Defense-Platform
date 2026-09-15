import asyncio
import time
import uuid
from typing import Dict, Any, List, Optional
import httpx

from app.scanner.target_validator import TargetValidator, TargetValidationError
from app.scanner.detectors.base import Finding
from app.scanner.crawler import DASTSpider, CrawlResult
from app.scanner.detectors import (
    SQLiDetector,
    XSSDetector,
    SSRFDetector,
    CSRFDetector,
    IDORDetector,
    CommandInjectionDetector,
    PathTraversalDetector,
    BrokenAuthDetector,
    XXEDetector,
    InsecureDeserializationDetector,
    OpenRedirectDetector,
    CORSDetector,
    InfoDisclosureDetector,
    OutdatedComponentsDetector,
)

class DASTScannerEngine:
    """
    Autonomous DAST Vulnerability Scanner Engine.
    Executes concurrent probes against target endpoints, performs differential analysis,
    and aggregates CVSS v3.1 scored findings.
    """

    def __init__(self):
        self.active_scan_id: Optional[str] = None
        self.status: str = "IDLE"  # IDLE, RUNNING, COMPLETED, FAILED
        self.progress: int = 0
        self.target_url: str = ""
        self.findings: List[Finding] = []
        self.crawl_result: Optional[CrawlResult] = None
        self.logs: List[Dict[str, Any]] = []
        self.start_time: float = 0
        self.end_time: float = 0
        self.stats: Dict[str, Any] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0
        }
        self._lock = asyncio.Lock()
        self._websocket_subscribers = set()

    def register_ws(self, ws):
        self._websocket_subscribers.add(ws)

    def unregister_ws(self, ws):
        self._websocket_subscribers.discard(ws)

    async def _broadcast(self, event_type: str, data: Any):
        dead = []
        for ws in self._websocket_subscribers:
            try:
                await ws.send_json({"type": event_type, "data": data})
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websocket_subscribers.discard(ws)

    def log(self, message: str, level: str = "INFO"):
        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message
        }
        self.logs.append(entry)

    async def start_scan(self, target_url: str, enabled_modules: Optional[List[str]] = None) -> Dict[str, Any]:
        async with self._lock:
            if self.status == "RUNNING":
                return {"status": "error", "message": "Another scan is currently in progress."}

            # 1. Platform Hardening Check: Validate target against SSRF / unauthorized subnets
            try:
                validated_url = TargetValidator.validate_target(target_url)
            except TargetValidationError as e:
                return {"status": "error", "message": f"Target Validation Rejected: {str(e)}"}

            scan_id = f"SCAN-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
            self.active_scan_id = scan_id
            self.status = "RUNNING"
            self.progress = 5
            self.target_url = validated_url
            self.findings = []
            self.crawl_result = None
            self.logs = []
            self.start_time = time.time()
            self.end_time = 0
            self.stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

            self.log(f"Initialized DAST Scan job {scan_id} for target: {validated_url}", "START")
            self.log("Platform Hardening Check: Target verified against Anti-SSRF guardrails.", "SEC")

            # Run asynchronously in background task
            asyncio.create_task(self._execute_scan_pipeline(validated_url, enabled_modules))

            return {
                "status": "started",
                "scan_id": scan_id,
                "target_url": validated_url,
                "message": "DAST scan initiated successfully."
            }

    async def _execute_scan_pipeline(self, target_url: str, enabled_modules: Optional[List[str]]):
        detectors = [
            ("sqli", SQLiDetector()),
            ("xss", XSSDetector()),
            ("cmdi", CommandInjectionDetector()),
            ("ssrf", SSRFDetector()),
            ("csrf", CSRFDetector()),
            ("idor", IDORDetector()),
            ("path_traversal", PathTraversalDetector()),
            ("open_redirect", OpenRedirectDetector()),
            ("broken_auth", BrokenAuthDetector()),
            ("cors", CORSDetector()),
            ("xxe", XXEDetector()),
            ("deserialization", InsecureDeserializationDetector()),
            ("info_disclosure", InfoDisclosureDetector()),
            ("outdated_components", OutdatedComponentsDetector()),
        ]

        if enabled_modules:
            detectors = [d for d in detectors if d[0] in enabled_modules]

        total_steps = len(detectors)
        current_step = 0

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            # Connectivity & Fingerprinting test
            try:
                self.log(f"Probing target connectivity and base headers...", "INFO")
                test_resp = await client.get(f"{target_url.rstrip('/')}")
                self.log(f"Target reachable (HTTP {test_resp.status_code}). Server: {test_resp.headers.get('Server', 'Aegis-Gateway')}", "SUCCESS")
                self.progress = 10
                await self._broadcast("progress", {"progress": self.progress, "status": self.status})
            except Exception as e:
                self.log(f"Target connectivity probe failed: {str(e)}", "ERROR")
                self.status = "FAILED"
                await self._broadcast("status_change", {"status": self.status})
                return

            # 2. Autonomous DAST Spider & Attack Surface Mapping
            self.log("Activating Autonomous DAST Spider: Crawling links, forms, scripts & API routes...", "PHASE")
            await self._broadcast("log", {"level": "PHASE", "message": "Spider active: Mapping application attack surface..."})
            spider = DASTSpider(max_depth=3, max_pages=30)
            try:
                self.crawl_result = await spider.crawl(client, target_url)
                ep_count = len(self.crawl_result.endpoints)
                self.log(
                    f"Spider completed: Discovered {ep_count} attack surface endpoints across {self.crawl_result.total_pages_visited} pages in {self.crawl_result.duration_seconds}s.",
                    "SUCCESS"
                )
                await self._broadcast("crawler_completed", {
                    "endpoints_count": ep_count,
                    "pages_visited": self.crawl_result.total_pages_visited,
                    "duration_seconds": self.crawl_result.duration_seconds,
                    "endpoints": [e.dict() for e in self.crawl_result.endpoints[:30]]
                })
            except Exception as e:
                self.log(f"Notice: Spider encountered an issue during crawl: {str(e)}", "WARN")
                self.crawl_result = None

            self.progress = 20
            await self._broadcast("progress", {"progress": self.progress, "status": self.status})

            for mod_key, detector in detectors:
                current_step += 1
                self.log(f"Activating detector: [{detector.name}] ...", "PHASE")
                await self._broadcast("log", {"level": "PHASE", "message": f"Running {detector.name}..."})

                try:
                    results = await detector.scan(client, target_url, self.crawl_result)
                    for f in results:
                        self.findings.append(f)
                        sev = f.severity.lower()
                        if sev in self.stats:
                            self.stats[sev] += 1
                        self.stats["total"] += 1
                        self.log(f"CONFIRMED VULNERABILITY: [{f.severity}] {f.title} (CVSS {f.cvss_score})", "ALERT")
                        await self._broadcast("vuln_found", f.dict())

                except Exception as e:
                    self.log(f"Error during {detector.name} probe: {str(e)}", "WARN")

                self.progress = 15 + int((current_step / total_steps) * 80)
                await self._broadcast("progress", {"progress": self.progress, "status": self.status})
                await asyncio.sleep(0.3)

        self.progress = 100
        self.status = "COMPLETED"
        self.end_time = time.time()
        duration = round(self.end_time - self.start_time, 2)
        self.log(f"DAST Scan {self.active_scan_id} finished in {duration:.2f}s. Discovered {len(self.findings)} findings.", "FINISH")
        
        # Persist to database
        try:
            from app.db.session import SessionLocal
            from app.db import models
            import datetime
            db = SessionLocal()
            target_rec = db.query(models.Target).filter(models.Target.base_url.like(f"%{target_url.split('/api')[0]}%")).first()
            target_id = target_rec.id if target_rec else None

            scan_run = models.ScanRun(
                id=self.active_scan_id,
                target_id=target_id,
                status="COMPLETED",
                triggered_by="Manual / Engine",
                target_url=target_url,
                findings_count=len(self.findings),
                critical_count=self.stats.get("critical", 0),
                high_count=self.stats.get("high", 0),
                medium_count=self.stats.get("medium", 0),
                low_count=self.stats.get("low", 0),
                avg_cvss=round(sum(f.cvss_score for f in self.findings) / len(self.findings), 1) if self.findings else 0.0,
                duration_seconds=duration,
                started_at=datetime.datetime.utcfromtimestamp(self.start_time),
                completed_at=datetime.datetime.utcfromtimestamp(self.end_time)
            )
            db.add(scan_run)

            for f in self.findings:
                finding_rec = models.FindingRecord(
                    scan_id=self.active_scan_id,
                    target_id=target_id,
                    vuln_type=f.vuln_type,
                    severity=f.severity,
                    title=f.title,
                    cwe_id=f.cwe_id,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    endpoint=f.endpoint,
                    parameter=f.parameter,
                    poc_curl=getattr(f, "curl_command", getattr(f, "poc_curl", "")),
                    status="OPEN"
                )
                db.add(finding_rec)

            db.commit()
            db.close()
        except Exception as e:
            print(f"[Aegis Engine] Notice: Could not persist scan to DB: {e}")

        await self._broadcast("scan_completed", self.get_summary())

    def get_summary(self) -> Dict[str, Any]:
        return {
            "scan_id": self.active_scan_id,
            "status": self.status,
            "progress": self.progress,
            "target_url": self.target_url,
            "duration_seconds": round((self.end_time - self.start_time) if self.end_time else (time.time() - self.start_time), 2) if self.start_time else 0,
            "findings_count": len(self.findings),
            "endpoints_discovered": len(self.crawl_result.endpoints) if self.crawl_result else 0,
            "discovered_endpoints": [e.dict() for e in self.crawl_result.endpoints] if self.crawl_result else [],
            "stats": self.stats,
            "findings": [f.dict() for f in self.findings],
            "logs": self.logs[-40:]
        }

scanner_engine = DASTScannerEngine()
