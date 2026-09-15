import os
from pydantic import BaseModel
from typing import List

class Settings(BaseModel):
    APP_NAME: str = "AegisAppSec"
    APP_VERSION: str = "1.0.0"
    HOST: str = os.getenv("AEGIS_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("AEGIS_PORT", "8000"))
    
    # Platform Self-Defense & Hardening Configs
    SECRET_KEY: str = os.getenv("AEGIS_SECRET_KEY", "aegis-enterprise-hardened-session-token-2026")
    API_KEY: str = os.getenv("AEGIS_API_KEY", "aegis-sec-key-alpha-99")
    REQUIRE_API_KEY: bool = os.getenv("AEGIS_REQUIRE_API_KEY", "false").lower() == "true"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ]
    
    # DAST Scanner Boundaries & SSRF Guardrails
    SCANNER_MAX_CONCURRENCY: int = 15
    SCANNER_TIMEOUT_SECONDS: float = 6.0
    SCANNER_MAX_REDIRECTS: int = 3
    SCANNER_MAX_BODY_SIZE: int = 1_048_576  # 1 MB max response body to defeat response bomb DoS
    
    # Safety: In production, external scanners must NEVER probe private subnets (prevents scanner SSRF abuse)
    # When testing locally against the integrated testbed (127.0.0.1 / localhost), we allow local testing.
    ALLOW_LOCAL_TARGETS: bool = True
    BLOCKED_IP_RANGES: List[str] = [
        "169.254.169.254", # Cloud metadata
        "metadata.google.internal",
        "169.254.169.250",
    ]
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 120
    
    # Default Target Base URL
    DEFAULT_TARGET_URL: str = "http://127.0.0.1:8000/api/shop"

settings = Settings()
