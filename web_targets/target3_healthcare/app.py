"""
PulseHealth Hospital Information System (EHR) - Target 3
Port: 8003
Vulnerabilities Demonstrated:
- Path Traversal / Local File Inclusion (LFI / CWE-22) in /records/download
- XML External Entity Injection (XXE / CWE-611) in /api/records/xml-import
- CORS Misconfiguration & Origin Trust Flaws (CWE-942) in /api/patient/{id}
- Security Misconfiguration (CWE-16) via missing HTTP headers & verbose diagnostics
"""

import os
import xml.etree.ElementTree as ET
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="PulseHealth EHR Portal (Target 3)", version="3.0.4")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Mock clinical records directory
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Pre-seed patient chart text file
sample_chart = DATA_DIR / "patient_1001.txt"
if not sample_chart.exists():
    sample_chart.write_text(
        "PATIENT: Jane Doe | DOB: 1984-07-12 | MRN: 994012\n"
        "DIAGNOSIS: Acute Viral Bronchitis, Hypertension Stage 1\n"
        "MEDICATIONS: Lisinopril 10mg PO Daily, Albuterol Inhaler\n"
        "ATTENDING PHYSICIAN: Dr. Robert Mercer, MD (Cardiology)\n"
        "CONFIDENTIAL MEDICAL RECORD - HIPAA PROTECTED"
    )

PATIENTS = {
    "1001": {"name": "Jane Doe", "dob": "1984-07-12", "condition": "Acute Bronchitis", "blood_type": "O-Positive"},
    "1002": {"name": "John Smith", "dob": "1972-03-24", "condition": "Type 2 Diabetes", "blood_type": "A-Positive"},
    "1003": {"name": "Elena Rostova", "dob": "1991-11-05", "condition": "Post-Op Recovery", "blood_type": "B-Negative"}
}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"patients": PATIENTS}
    )

# 1. Path Traversal / LFI (CWE-22)
@app.get("/records/download")
async def download_record(file: str = "patient_1001.txt"):
    """
    Vulnerable File Download:
    Directly opens file parameter relative to DATA_DIR without path normalization or basename stripping.
    Permits directory traversal attacks (e.g. file=../../app.py or file=../../../../etc/passwd).
    """
    try:
        # Check for classic system file traversals (cross-platform testing)
        if "etc/passwd" in file or "etc\\passwd" in file:
            return Response(content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\npulsehealth:x:1000:1000::/home/pulse:/bin/bash\n", media_type="text/plain")
        if "win.ini" in file.lower():
            return Response(content="[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n", media_type="text/plain")

        # VULNERABILITY: Insecure path resolution without validation
        candidates = [
            DATA_DIR / file,
            BASE_DIR / file,
            Path(file)
        ]
        for p in candidates:
            try:
                resolved = p.resolve()
                if resolved.exists() and resolved.is_file():
                    content = resolved.read_text(encoding='utf-8', errors='ignore')
                    return Response(content=content, media_type="text/plain")
            except Exception:
                continue

        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": f"Clinical document '{file}' could not be located on storage node."}
        )
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

# 2. XML External Entity Injection (XXE / CWE-611)
@app.post("/api/records/xml-import")
async def import_clinical_xml(request: Request):
    """
    Vulnerable XML Parser:
    Parses clinical lab reports with XML entity processing enabled.
    """
    try:
        body = await request.body()
        xml_str = body.decode('utf-8', errors='ignore')
        
        # VULNERABILITY: Inspect for external entity simulation or DTD resolution
        if "<!ENTITY" in xml_str or "SYSTEM" in xml_str:
            # Emulate external entity resolution / arbitrary file disclosure
            simulated_leak = "[XXE LEAK: Simulated /etc/passwd disclosure: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin]"
            return JSONResponse(content={
                "status": "success",
                "imported_records": 1,
                "parsed_patient_summary": simulated_leak,
                "vulnerability_note": "CWE-611 XXE: XML External Entity parsed and resolved external data stream."
            })
        
        # Standard XML parse
        root = ET.fromstring(xml_str)
        patient_name = root.findtext(".//patient_name") or root.findtext(".//name") or "Unspecified Patient"
        test_result = root.findtext(".//result") or "Normal Diagnostic Baseline"
        
        return {
            "status": "success",
            "imported_patient": patient_name,
            "test_result": test_result
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": f"XML Parser Error: {str(e)}"})

# 3. CORS Misconfiguration (CWE-942)
@app.get("/api/patient/{patient_id}")
async def get_patient_data(patient_id: str, request: Request):
    """
    Vulnerable CORS Endpoint:
    Returns Access-Control-Allow-Origin: * with Allow-Credentials: true or echoes untrusted Origin.
    """
    patient = PATIENTS.get(patient_id, {"name": "Unknown", "condition": "N/A"})
    origin = request.headers.get("Origin", "*")
    
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*"
    }
    return JSONResponse(
        content={
            "patient_id": patient_id,
            "profile": patient,
            "vulnerability_note": "CWE-942: Insecure CORS policy reflects untrusted origin with credentials enabled."
        },
        headers=headers
    )

@app.options("/api/patient/{patient_id}")
async def cors_preflight(request: Request):
    origin = request.headers.get("Origin", "*")
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8003, reload=True)
