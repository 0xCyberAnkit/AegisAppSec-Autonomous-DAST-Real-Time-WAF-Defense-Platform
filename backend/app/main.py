import os
import sys
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from app.core.config import settings
from app.core.security import SecurityHeadersMiddleware
from app.waf_shield.middleware import AegisShieldMiddleware
from app.targets.db import get_db
from app.targets.shop_routes import router as shop_router
from app.routers.scanner_router import router as scanner_router
from app.routers.waf_router import router as waf_router
from contextlib import asynccontextmanager
from app.routers.report_router import router as report_router

from app.db.session import init_db
from app.routers.auth_router import router as auth_router
from app.routers.target_router import router as target_router
from app.routers.history_router import router as history_router
from app.routers.apikey_router import router as apikey_router
from app.routers.compliance_router import router as compliance_router
from app.routers.team_router import router as team_router
from app.routers.waf_custom_router import router as waf_custom_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite/MySQL database schema and default seeds
    try:
        init_db()
    except Exception as e:
        print(f"[Aegis Main] DB init notice: {e}")
    # Pre-initialize SQLite in-memory catalog
    get_db()
    yield

# Root path of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(
    title="AegisAppSec - Autonomous DAST & WAF Intelligence Platform",
    description="Enterprise-grade DAST vulnerability scanner, real-time WAF shield, and Black Friday e-commerce security testbed.",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# 1. Platform Hardening Middleware: HTTP Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# 2. Defensive WAF Middleware: Aegis-Shield inspection
app.add_middleware(AegisShieldMiddleware)

# 3. CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global Safe Exception Handler (Prevents Internal Stack Trace Leakage)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # In shop search endpoint, allow raw SQL exception demonstration when specifically triggered by SQLi
    if "/api/shop/search" in request.url.path:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "type": type(exc).__name__, "message": str(exc)}
        )
    # Generic safe error response for all other platform endpoints
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An internal server security event occurred. Stack trace suppressed for platform hardening.",
            "code": "AEGIS_ERR_SECURE_SUPPRESS"
        }
    )

# Register API Routers
app.include_router(auth_router)
app.include_router(target_router)
app.include_router(history_router)
app.include_router(apikey_router)
app.include_router(compliance_router)
app.include_router(team_router)
app.include_router(waf_custom_router)
app.include_router(scanner_router)
app.include_router(waf_router)
app.include_router(report_router)
app.include_router(shop_router)

@app.get("/.well-known/aegis-verification.txt", include_in_schema=False)
async def serve_well_known_verification():
    """Serves verification tokens dynamically for local self-hosting and testing."""
    from app.db.session import SessionLocal
    from app.db import models
    db = SessionLocal()
    try:
        tokens = [t.verification_token for t in db.query(models.Target).all() if t.verification_token]
        tokens.append("aegis-verify-prod-seed-8899")
        tokens.append("aegis-verify-token-acme-8812")
        return Response(content="\n".join(set(tokens)), media_type="text/plain")
    except Exception:
        return Response(content="aegis-verify-prod-seed-8899\naegis-verify-token-acme-8812", media_type="text/plain")
    finally:
        db.close()

from app.routers.web_router import router as web_router

# Mount Static Assets & Multi-Page Directories inside frontend/
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

if os.path.exists(FRONTEND_DIR):
    css_dir = os.path.join(FRONTEND_DIR, "css")
    js_dir = os.path.join(FRONTEND_DIR, "js")
    assets_dir = os.path.join(FRONTEND_DIR, "assets")
    
    if os.path.exists(css_dir):
        app.mount("/css", StaticFiles(directory=css_dir), name="css")
    if os.path.exists(js_dir):
        app.mount("/js", StaticFiles(directory=js_dir), name="js")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

# Include Multi-Page Web Router (serves separate HTML pages for /, /scanner, /services, /about, /contact, /auth, etc.)
app.include_router(web_router)
