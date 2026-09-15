import uvicorn
import os
import sys

# Ensure backend directory is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from app.core.config import settings

if __name__ == "__main__":
    print(f"============================================================")
    print(f"  AEGIS APPSEC // Autonomous DAST & WAF Platform v{settings.APP_VERSION}")
    print(f"============================================================")
    print(f"  [+] Server running at: http://{settings.HOST}:{settings.PORT}")
    print(f"  [+] Cyber Dashboard:   http://{settings.HOST}:{settings.PORT}/")
    print(f"  [+] API Docs:          http://{settings.HOST}:{settings.PORT}/docs")
    print(f"  [+] E-Commerce Target: http://{settings.HOST}:{settings.PORT}/api/shop")
    print(f"  [+] Platform Hardening: Active (Anti-SSRF, CSP, Rate Limit)")
    print(f"============================================================\n")
    
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info"
    )
