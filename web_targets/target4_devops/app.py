"""
CloudOps Container & Cluster Infrastructure Console - Target 4
Port: 8004
Vulnerabilities Demonstrated:
- OS Command Injection (CMDi / CWE-78) in /api/tools/ping and /api/tools/traceroute
- Insecure Deserialization (CWE-502) in /api/cluster/state/load
- Vulnerable & Outdated Dependencies / Components (CWE-1104) via legacy server banners
- Information Disclosure / Stack Trace Leakage (CWE-200) in /api/system/crash
"""

import os
import subprocess
import pickle
import base64
from pathlib import Path
from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="CloudOps Cluster Console (Target 4)", version="4.0.1")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Inject legacy/outdated server banner middleware (CWE-1104)
@app.middleware("http")
async def outdated_banner_middleware(request: Request, call_next):
    response = await call_next(request)
    # VULNERABILITY: Emulates vulnerable legacy server stack (Apache 2.2.8 / PHP 5.2.4)
    response.headers["Server"] = "Apache/2.2.8 (Ubuntu) PHP/5.2.4 OpenSSL/0.9.8g"
    response.headers["X-Powered-By"] = "PHP/5.2.4-2ubuntu5.27"
    return response

NODES = [
    {"name": "k8s-master-01", "ip": "10.0.1.10", "status": "Ready", "cpu": "34%", "mem": "5.2 GB / 16 GB"},
    {"name": "k8s-worker-01", "ip": "10.0.1.11", "status": "Ready", "cpu": "78%", "mem": "14.1 GB / 32 GB"},
    {"name": "k8s-worker-02", "ip": "10.0.1.12", "status": "Degraded", "cpu": "92%", "mem": "31.8 GB / 32 GB"}
]

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"nodes": NODES}
    )

# 1. OS Command Injection (CMDi / CWE-78)
@app.post("/api/tools/ping")
@app.get("/api/tools/ping")
async def run_network_ping(host: str = "127.0.0.1"):
    """
    Vulnerable Ping Utility:
    Directly concatenates user parameter into shell command without sanitization.
    Permits RCE via operators: &&, ;, |, `id`, $(whoami).
    """
    try:
        # Cross-platform ping parameter (1 packet)
        param = "-n 1" if os.name == "nt" else "-c 1"
        cmd = f"ping {param} {host}"
        
        # VULNERABILITY: shell=True executes arbitrary chained commands
        output = subprocess.getoutput(cmd)
        
        return {
            "status": "success",
            "host": host,
            "executed_command": cmd,
            "output": output,
            "vulnerability_note": "CWE-78 CMDi: Command chaining executed with process shell privileges."
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@app.get("/api/tools/traceroute")
async def run_traceroute(host: str = "127.0.0.1"):
    """Traceroute vector vulnerable to command injection."""
    return await run_network_ping(host=host)

# 2. Insecure Deserialization (CWE-502)
@app.post("/api/cluster/state/load")
async def load_cluster_state(state: str = Form(...)):
    """
    Vulnerable Deserialization:
    Accepts base64-encoded Python pickle payload and executes pickle.loads() directly.
    """
    try:
        raw_bytes = base64.b64decode(state.strip())
        # VULNERABILITY: Arbitrary object instantiation & code execution via pickle.loads()
        obj = pickle.loads(raw_bytes)
        
        return {
            "status": "success",
            "message": "Cluster snapshot loaded successfully into runtime memory.",
            "type": str(type(obj)),
            "content_repr": repr(obj),
            "vulnerability_note": "CWE-502: Insecure Deserialization of untrusted bytecode stream."
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": f"Deserialization Fault: {str(e)}"})

# 3. Information Disclosure (CWE-200)
@app.get("/api/system/crash")
async def simulate_system_crash():
    """Vulnerable endpoint deliberately throwing unhandled exception dumping raw stack trace."""
    raise RuntimeError("CloudOps Kernel Panic: Internal cluster driver memory corruption at 0x7FFF0042B")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8004, reload=True)
