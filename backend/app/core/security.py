from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response, HTTPException, status, Security
from fastapi.security import APIKeyHeader
from app.core.config import settings

api_key_header = APIKeyHeader(name="X-Aegis-Key", auto_error=False)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Platform Hardening Middleware:
    Applies enterprise-grade HTTP security headers to all responses to protect
    AegisAppSec from being targeted by Clickjacking, MIME-confusion, Cross-Site Scripting,
    and information disclosure.
    """
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # HTTP Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Anti-Clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # MIME-Type Sniffing Protection
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Cross-Site Scripting Filter Protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Strict Content Security Policy (allows local assets, fonts, icons)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https: blob:; "
            "connect-src 'self' ws://127.0.0.1:* ws://localhost:* http://127.0.0.1:* http://localhost:*; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()"
        
        # Server Cloaking (Hides backend framework identity from fingerprinting)
        response.headers["Server"] = "Aegis-Gateway/Hardened"
        
        return response

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verifies API key if required by configuration."""
    if settings.REQUIRE_API_KEY:
        if not api_key or api_key != settings.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Aegis Security API Key (X-Aegis-Key)",
                headers={"WWW-Authenticate": "ApiKey"}
            )
    return api_key
