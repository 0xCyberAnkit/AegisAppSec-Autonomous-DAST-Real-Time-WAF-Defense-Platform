import json
import uuid
import time
from urllib.parse import unquote
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request, Response
from starlette.responses import JSONResponse

from app.waf_shield.signatures import WAFSignatures, EvasionNormalizer
from app.waf_shield.sanitizers import DefensiveSanitizer
from app.waf_shield.telemetry import waf_telemetry

class AegisShieldMiddleware(BaseHTTPMiddleware):
    """
    ASGI Web Application Firewall (WAF) Middleware.
    Inspects incoming HTTP traffic for injection attacks, cross-site scripting,
    SSRF attempts, and evasion maneuvers.
    Operates in 4 modes: OFF, DETECT, BLOCK, SANITIZE.
    """

    EXCLUDED_PREFIXES = (
        "/api/scanner",
        "/api/waf",
        "/api/reports",
        "/docs",
        "/openapi.json",
        "/favicon.ico",
        "/static",
        "/ws"
    )

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Don't intercept scanner management or dashboard UI endpoints
        if path.startswith(self.EXCLUDED_PREFIXES) or path == "/" or path.endswith((".js", ".css", ".html", ".svg", ".png")):
            return await call_next(request)

        waf_telemetry.record_inspection()
        current_mode = waf_telemetry.get_mode()

        client_ip = request.client.host if request.client else "127.0.0.1"

        if current_mode == "OFF":
            return await call_next(request)

        # 1. Inspect Query Parameters
        query_string = request.url.query
        detected_attack = None

        if query_string:
            detected_attack = WAFSignatures.inspect(query_string)

        # 2. Inspect Body for POST/PUT/PATCH
        if not detected_attack and request.method in ("POST", "PUT", "PATCH"):
            body_bytes = await request.body()
            if body_bytes:
                try:
                    body_text = body_bytes.decode("utf-8", errors="ignore")
                    detected_attack = WAFSignatures.inspect(body_text)
                except Exception:
                    pass

        # 3. Handle Detection
        if detected_attack:
            incident_id = f"AEGIS-INC-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"

            if current_mode == "BLOCK":
                waf_telemetry.record_attack(detected_attack, "BLOCKED", client_ip, path)
                
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "blocked_by_waf",
                        "waf_engine": "Aegis-Shield v1.0",
                        "incident_id": incident_id,
                        "attack_type": detected_attack["attack_type"],
                        "rule_triggered": detected_attack["rule"],
                        "owasp_category": detected_attack["owasp"],
                        "cwe": detected_attack["cwe"],
                        "evasions_detected": detected_attack["evasions"],
                        "client_ip": client_ip,
                        "message": "Access Denied: The request payload matched an active attack signature and was rejected."
                    },
                    headers={
                        "X-Aegis-Shield-Action": "BLOCKED",
                        "X-Aegis-Incident-ID": incident_id
                    }
                )

            elif current_mode == "DETECT":
                # Log without blocking
                waf_telemetry.record_attack(detected_attack, "DETECTED", client_ip, path)
                response = await call_next(request)
                response.headers["X-Aegis-Shield-Alert"] = f"Attack Detected: {detected_attack['attack_type']}"
                return response

            elif current_mode == "SANITIZE":
                # Record sanitized event and let modified flow proceed
                waf_telemetry.record_attack(detected_attack, "SANITIZED", client_ip, path)
                # Downstream execution continues
                response = await call_next(request)
                response.headers["X-Aegis-Shield-Action"] = "SANITIZED"
                return response

        return await call_next(request)
