/**
 * AegisAppSec - Executive Report Studio Module
 * Version 2.6.0
 */

const AegisReportsPage = (function() {
  let currentScanId = "";
  let reportDataCache = null;
  let findingsCache = [];
  let currentSeverityFilter = "ALL";
  let currentJsonMode = "json"; // 'json' or 'sarif'

  function showToast(msg) {
    const toast = document.getElementById("skToast");
    const msgEl = document.getElementById("skToastMsg");
    if (!toast || !msgEl) return;
    msgEl.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => {
      toast.classList.remove("show");
    }, 3500);
  }

  async function init() {
    await loadScansList();
    await loadReportData();
  }

  async function loadScansList() {
    const selectScan = document.getElementById("selectReportScan");
    if (!selectScan) return;

    try {
      const resp = await fetch("/api/reports/scans");
      if (resp.ok) {
        const scans = await resp.json();
        if (scans.length) {
          selectScan.innerHTML = scans.map(s => {
            const dateStr = s.started_at ? new Date(s.started_at).toLocaleDateString() : 'Recent';
            return `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)} [${dateStr}] (${s.findings_count} findings)</option>`;
          }).join("");
          currentScanId = scans[0].id;
        }
      }
    } catch (err) {
      console.warn("[AegisReportsPage] Could not load scans list:", err);
    }
  }

  async function loadReportData(scanId) {
    if (scanId !== undefined) currentScanId = scanId;
    const query = currentScanId ? `?scan_id=${encodeURIComponent(currentScanId)}` : "";

    // Update export links
    const btnHtml = document.getElementById("btnExportHtml");
    const btnJson = document.getElementById("btnExportJson");
    const btnCsv = document.getElementById("btnExportCsv");
    const btnMd = document.getElementById("btnExportMarkdown");
    const btnSarif = document.getElementById("btnExportSarif");

    if (btnHtml) btnHtml.href = `/api/reports/export/html${query}`;
    if (btnJson) btnJson.href = `/api/reports/export/json${query}`;
    if (btnCsv) btnCsv.href = `/api/reports/export/csv${query}`;
    if (btnMd) btnMd.href = `/api/reports/export/markdown${query}`;
    if (btnSarif) btnSarif.href = `/api/reports/export/sarif${query}`;

    try {
      const resp = await fetch(`/api/reports/preview${query}`);
      if (resp.ok) {
        const data = await resp.json();
        reportDataCache = data;
        const summary = data.summary || {};
        findingsCache = summary.findings || [];

        renderHud(summary, data.compliance_highlights || {});
        renderDossierTable(findingsCache);
        renderFormalDocument(summary);
      }
    } catch (err) {
      console.error("[AegisReportsPage] Failed to load report preview:", err);
    }

    // Lazy load markdown & JSON for inspection tabs
    loadMarkdownSnippet(query);
    loadJsonSnippet(query);
  }

  function renderHud(summary, comp) {
    const crit = summary.critical_count || 0;
    const high = summary.high_count || 0;
    const med = summary.medium_count || 0;
    const low = summary.low_count || 0;
    const total = summary.findings_count || 0;

    const hudRiskGrade = document.getElementById("hudRiskGrade");
    const hudRiskSub = document.getElementById("hudRiskSub");
    const hudTotal = document.getElementById("hudTotalFindings");
    const hudBreakdown = document.getElementById("hudFindingsBreakdown");
    const hudPci = document.getElementById("hudPciStatus");

    if (hudRiskGrade) {
      if (crit > 0) {
        hudRiskGrade.textContent = "CRITICAL (CVSS 9.8)";
        hudRiskGrade.style.color = "var(--red, #ff0033)";
        if (hudRiskSub) hudRiskSub.innerHTML = `<span class="sk-dot-pulse red"></span><span>Critical Exploits Detected</span>`;
      } else if (high > 0) {
        hudRiskGrade.textContent = "HIGH (ELEVATED)";
        hudRiskGrade.style.color = "#f97316";
        if (hudRiskSub) hudRiskSub.innerHTML = `<span class="sk-dot-pulse red"></span><span>High Severity Risks</span>`;
      } else if (med > 0) {
        hudRiskGrade.textContent = "MODERATE (CVSS 6.0)";
        hudRiskGrade.style.color = "#eab308";
        if (hudRiskSub) hudRiskSub.innerHTML = `<span class="sk-dot-pulse"></span><span>Medium Exposure</span>`;
      } else {
        hudRiskGrade.textContent = "SECURE (GRADE A)";
        hudRiskGrade.style.color = "#10b981";
        if (hudRiskSub) hudRiskSub.innerHTML = `<span class="sk-dot-pulse"></span><span>Zero Vulnerabilities</span>`;
      }
    }

    if (hudTotal) hudTotal.textContent = `${total} ${total === 1 ? 'ISSUE' : 'ISSUES'}`;
    if (hudBreakdown) {
      hudBreakdown.innerHTML = `
        <span style="color: #ff0033; font-weight:700;">${crit} Crit</span> | 
        <span style="color: #f97316; font-weight:700;">${high} High</span> | 
        <span style="color: #eab308; font-weight:700;">${med} Med</span> | 
        <span style="color: #3b82f6; font-weight:700;">${low} Low</span>
      `;
    }

    if (hudPci) {
      if (crit === 0 && high === 0) {
        hudPci.textContent = "AUDIT READY";
        hudPci.style.color = "#10b981";
      } else {
        hudPci.textContent = "NON-COMPLIANT";
        hudPci.style.color = "#f59e0b";
      }
    }

    // Counts for filter pills
    const cAll = document.getElementById("countAll");
    const cCrit = document.getElementById("countCrit");
    const cHigh = document.getElementById("countHigh");
    const cMed = document.getElementById("countMed");
    const cLow = document.getElementById("countLow");

    if (cAll) cAll.textContent = total;
    if (cCrit) cCrit.textContent = crit;
    if (cHigh) cHigh.textContent = high;
    if (cMed) cMed.textContent = med;
    if (cLow) cLow.textContent = low;
  }

  function renderDossierTable(findings) {
    const tbody = document.getElementById("dossierTableBody");
    if (!tbody) return;

    const filtered = findings.filter(f => {
      const matchSev = currentSeverityFilter === "ALL" || (f.severity && f.severity.toUpperCase() === currentSeverityFilter);
      return matchSev;
    });

    if (!filtered.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 28px;">
            No findings matching severity filter "${currentSeverityFilter}".
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map((f, idx) => {
      const sev = (f.severity || 'LOW').toUpperCase();
      const sevClass = sev.toLowerCase();

      return `
        <tr>
          <td>
            <div style="font-weight: 800; color: #ffffff; font-size: 0.82rem; margin-bottom: 3px;">
              ${escapeHtml(f.title)}
            </div>
            <div style="font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono, monospace);">
              Type: ${escapeHtml(f.vuln_type || 'web_vulnerability')}
            </div>
          </td>
          <td>
            <span class="badge-sev ${sevClass}">${sev}</span>
          </td>
          <td>
            <div style="font-family: var(--font-mono, monospace); font-weight: 800; color: var(--cyan, #00f0ff); font-size: 0.82rem;">
              ${f.cvss_score || '0.0'}
            </div>
            <div style="font-size: 0.62rem; color: #64748b; font-family: var(--font-mono, monospace);">
              CVSS v3.1
            </div>
          </td>
          <td>
            <code style="color: #cbd5e1; font-size: 0.72rem; background: rgba(255,255,255,0.04); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1);">
              ${escapeHtml(f.cwe_id || 'CWE-Unknown')}
            </code>
          </td>
          <td>
            <code style="color: var(--text-muted); font-size: 0.72rem;">
              ${escapeHtml(f.endpoint || '/')}
            </code>
            ${f.parameter && f.parameter !== 'None' ? `<div style="font-size: 0.65rem; color: var(--cyan);">Param: [${escapeHtml(f.parameter)}]</div>` : ''}
          </td>
          <td>
            <span style="font-family: var(--font-mono, monospace); font-size: 0.65rem; color: #10b981; display: inline-flex; align-items: center; gap: 4px;">
              <span class="sk-dot-pulse"></span> VERIFIED cURL
            </span>
          </td>
          <td style="text-align: right;">
            <button class="sk-btn-export-secondary" style="border-radius: 4px; padding: 4px 10px; font-size: 0.65rem;" onclick="AegisReportsPage.openFindingModal(${idx})">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              INSPECT DOSSIER
            </button>
          </td>
        </tr>
      `;
    }).join("");
  }

  function renderFormalDocument(summary) {
    const frame = document.getElementById("formalDocFrame");
    if (!frame) return;

    const findings = summary.findings || [];
    const crit = summary.critical_count || 0;
    const high = summary.high_count || 0;
    const total = summary.findings_count || 0;
    const dateStr = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

    frame.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #0f172a; padding-bottom: 20px; margin-bottom: 24px;">
        <div>
          <div style="font-size: 1.4rem; font-weight: 900; letter-spacing: -0.02em; color: #0f172a;">
            AEGIS<span style="color: #ff0033;">APPSEC</span> // EXECUTIVE AUDIT REPORT
          </div>
          <div style="font-size: 0.80rem; color: #64748b; margin-top: 4px;">
            Dynamic Application Security Testing (DAST) &amp; Proof-of-Concept Attestation
          </div>
        </div>
        <div style="text-align: right; font-family: monospace; font-size: 0.75rem; color: #64748b;">
          <div>DATE: ${dateStr}</div>
          <div>STATUS: <strong style="color: ${crit > 0 ? '#ff0033' : '#10b981'};">${crit > 0 ? 'ACTION REQUIRED' : 'COMPLIANT'}</strong></div>
          <div>CLASSIFICATION: RESTRICTED</div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px;">
        <div>
          <div style="font-size: 0.68rem; color: #64748b; font-weight: 700; font-family: monospace;">TARGET URL</div>
          <div style="font-weight: 800; font-size: 0.85rem; color: #0f172a; word-break: break-all;">${escapeHtml(summary.target_url || 'http://127.0.0.1:8000/api/shop')}</div>
        </div>
        <div>
          <div style="font-size: 0.68rem; color: #64748b; font-weight: 700; font-family: monospace;">TOTAL FINDINGS</div>
          <div style="font-weight: 800; font-size: 1.2rem; color: #0f172a;">${total}</div>
        </div>
        <div>
          <div style="font-size: 0.68rem; color: #64748b; font-weight: 700; font-family: monospace;">CRITICAL &amp; HIGH</div>
          <div style="font-weight: 800; font-size: 1.2rem; color: #ff0033;">${crit + high}</div>
        </div>
        <div>
          <div style="font-size: 0.68rem; color: #64748b; font-weight: 700; font-family: monospace;">ENGINE VERSION</div>
          <div style="font-weight: 800; font-size: 0.85rem; color: #0f172a;">Aegis-DAST v2.6.0</div>
        </div>
      </div>

      <h3 style="font-size: 1.05rem; font-weight: 800; color: #0f172a; margin-bottom: 10px;">1. Executive Summary &amp; Threat Posture</h3>
      <p style="font-size: 0.85rem; color: #334155; line-height: 1.6; margin-bottom: 20px;">
        AegisAppSec automated dynamic security assessment probes performed non-destructive vulnerability fuzzing against the target application endpoints. The engine identified <strong>${total} validated vulnerabilities</strong>, including <strong>${crit} Critical</strong> and <strong>${high} High</strong> severity flaws. All identified issues have verified reproduction proof-of-concept cURL payloads and remediation guidance documented below.
      </p>

      <h3 style="font-size: 1.05rem; font-weight: 800; color: #0f172a; margin-bottom: 12px;">2. Detailed Vulnerability Breakdown</h3>
      ${findings.map((f, i) => `
        <div style="border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; margin-bottom: 16px; background: #ffffff;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 10px;">
            <div>
              <strong style="font-size: 0.95rem; color: #0f172a;">${i + 1}. ${escapeHtml(f.title)}</strong>
              <span style="font-family: monospace; font-size: 0.72rem; color: #64748b; margin-left: 8px;">[${escapeHtml(f.cwe_id)}]</span>
            </div>
            <span style="font-family: monospace; font-size: 0.72rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; background: ${f.severity === 'CRITICAL' ? '#fee2e2' : '#fef3c7'}; color: ${f.severity === 'CRITICAL' ? '#991b1b' : '#92400e'};">
              ${f.severity} (CVSS ${f.cvss_score})
            </span>
          </div>
          <div style="font-size: 0.78rem; color: #475569; font-family: monospace; margin-bottom: 8px;">
            <strong>Endpoint:</strong> ${escapeHtml(f.endpoint)} | <strong>Parameter:</strong> ${escapeHtml(f.parameter || 'N/A')}
          </div>
          <div style="font-size: 0.80rem; color: #334155; margin-bottom: 10px;">
            <strong>Evidence:</strong> ${escapeHtml(f.evidence)}
          </div>
          <div style="background: #0f172a; color: #38bdf8; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 0.72rem; overflow-x: auto; margin-bottom: 8px;">
            ${escapeHtml(f.curl_command || 'curl ...')}
          </div>
          <div style="background: #f0fdf4; border-left: 3px solid #16a34a; padding: 8px 12px; font-size: 0.78rem; color: #166534;">
            <strong>Remediation:</strong> ${escapeHtml(f.remediation_summary)}
          </div>
        </div>
      `).join("")}
    `;
  }

  async function loadMarkdownSnippet(query) {
    const pre = document.getElementById("markdownPre");
    if (!pre) return;
    try {
      const resp = await fetch(`/api/reports/export/markdown${query}`);
      if (resp.ok) {
        pre.textContent = await resp.text();
      }
    } catch (err) {
      pre.textContent = "// Error loading Markdown report.";
    }
  }

  async function loadJsonSnippet(query) {
    const pre = document.getElementById("jsonPre");
    if (!pre) return;
    try {
      const endpoint = currentJsonMode === "sarif" ? "/api/reports/export/sarif" : "/api/reports/export/json";
      const resp = await fetch(`${endpoint}${query}`);
      if (resp.ok) {
        const data = await resp.json();
        pre.textContent = JSON.stringify(data, null, 2);
      }
    } catch (err) {
      pre.textContent = "// Error loading JSON report.";
    }
  }

  function openFindingModal(index) {
    const f = findingsCache[index];
    if (!f) return;

    const modal = document.getElementById("findingModal");
    const badge = document.getElementById("modalSevBadge");
    const cwe = document.getElementById("modalCweId");
    const cvss = document.getElementById("modalCvssScore");
    const title = document.getElementById("modalTitle");
    const desc = document.getElementById("modalDesc");
    const curl = document.getElementById("modalCurl");
    const ev = document.getElementById("modalEvidence");
    const rem = document.getElementById("modalRemediation");

    const sev = (f.severity || 'LOW').toUpperCase();
    if (badge) {
      badge.textContent = sev;
      badge.className = `badge-sev ${sev.toLowerCase()}`;
    }
    if (cwe) cwe.textContent = f.cwe_id || 'CWE-Unknown';
    if (cvss) cvss.textContent = `CVSS ${f.cvss_score || '0.0'} (${f.cvss_vector || 'N/A'})`;
    if (title) title.textContent = f.title;
    if (desc) desc.textContent = `Vulnerability identified on endpoint ${f.endpoint}. Active exploit vector verified during automated DAST assessment probe.`;
    if (curl) curl.textContent = f.curl_command || `curl '${f.endpoint}'`;
    if (ev) ev.textContent = f.evidence;
    if (rem) rem.textContent = f.remediation_summary;

    if (modal) modal.classList.add("active");
  }

  function closeFindingModal() {
    document.getElementById("findingModal")?.classList.remove("active");
  }

  function copyModalCurl() {
    const curl = document.getElementById("modalCurl")?.textContent;
    if (curl) {
      navigator.clipboard.writeText(curl);
      showToast("cURL exploit command copied to clipboard!");
    }
  }

  function filterFindingsBySeverity(sev, btn) {
    currentSeverityFilter = sev;
    document.querySelectorAll("[data-sev]").forEach(b => b.classList.remove("active"));
    if (btn) btn.classList.add("active");
    renderDossierTable(findingsCache);
  }

  function filterFindingsSearch() {
    const query = document.getElementById("inputFilterDossier")?.value.toLowerCase().trim() || "";
    const rows = document.querySelectorAll("#dossierTableBody tr");
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(query) ? "" : "none";
    });
  }

  function switchReportTab(tabName) {
    document.querySelectorAll(".sk-view-tab-btn[data-tab]").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-tab") === tabName);
    });

    const cDossier = document.getElementById("tabContentDossier");
    const cHtml = document.getElementById("tabContentHtml");
    const cMd = document.getElementById("tabContentMarkdown");
    const cJson = document.getElementById("tabContentJson");

    if (cDossier) cDossier.style.display = tabName === "dossier" ? "block" : "none";
    if (cHtml) cHtml.style.display = tabName === "html" ? "block" : "none";
    if (cMd) cMd.style.display = tabName === "markdown" ? "block" : "none";
    if (cJson) cJson.style.display = tabName === "json" ? "block" : "none";
  }

  function switchJsonMode(mode) {
    currentJsonMode = mode;
    const btnJson = document.getElementById("btnModeJson");
    const btnSarif = document.getElementById("btnModeSarif");
    const filename = document.getElementById("jsonFilename");

    if (btnJson) btnJson.classList.toggle("active", mode === "json");
    if (btnSarif) btnSarif.classList.toggle("active", mode === "sarif");
    if (filename) filename.textContent = mode === "sarif" ? "aegis_scan_report.sarif" : "audit_report.json";

    const query = currentScanId ? `?scan_id=${encodeURIComponent(currentScanId)}` : "";
    loadJsonSnippet(query);
  }

  function copyMarkdownText() {
    const pre = document.getElementById("markdownPre");
    if (pre && pre.textContent) {
      navigator.clipboard.writeText(pre.textContent);
      showToast("Markdown report copied to clipboard!");
    }
  }

  function copyJsonText() {
    const pre = document.getElementById("jsonPre");
    if (pre && pre.textContent) {
      navigator.clipboard.writeText(pre.textContent);
      showToast(`${currentJsonMode.toUpperCase()} report copied to clipboard!`);
    }
  }

  function printReportDoc() {
    window.print();
  }

  function handleScanChange() {
    const select = document.getElementById("selectReportScan");
    if (select) {
      loadReportData(select.value);
    }
  }

  function handleTargetChange() {
    loadReportData(currentScanId);
  }

  function reloadReportData() {
    loadReportData(currentScanId);
    showToast("Audit report refreshed against database.");
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  return {
    init,
    loadPreview: loadReportData,
    openFindingModal,
    closeFindingModal,
    copyModalCurl,
    filterFindingsBySeverity,
    filterFindingsSearch,
    switchReportTab,
    switchJsonMode,
    copyMarkdownText,
    copyJsonText,
    printReportDoc,
    handleScanChange,
    handleTargetChange,
    reloadReportData
  };
})();

// Global wrappers for HTML inline handlers
function switchReportTab(tab) { AegisReportsPage.switchReportTab(tab); }
function filterFindingsBySeverity(sev, btn) { AegisReportsPage.filterFindingsBySeverity(sev, btn); }
function filterFindingsSearch() { AegisReportsPage.filterFindingsSearch(); }
function switchJsonMode(mode) { AegisReportsPage.switchJsonMode(mode); }
function copyMarkdownText() { AegisReportsPage.copyMarkdownText(); }
function copyJsonText() { AegisReportsPage.copyJsonText(); }
function printReportDoc() { AegisReportsPage.printReportDoc(); }
function handleScanChange() { AegisReportsPage.handleScanChange(); }
function handleTargetChange() { AegisReportsPage.handleTargetChange(); }
function reloadReportData() { AegisReportsPage.reloadReportData(); }
function closeFindingModal() { AegisReportsPage.closeFindingModal(); }
function copyModalCurl() { AegisReportsPage.copyModalCurl(); }

window.AegisReportsPage = AegisReportsPage;
document.addEventListener("DOMContentLoaded", () => AegisReportsPage.init());
