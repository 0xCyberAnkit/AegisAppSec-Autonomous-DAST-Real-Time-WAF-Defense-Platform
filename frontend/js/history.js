/**
 * AegisAppSec - Scan History & Regression Diff Tracker Module
 */

const HistoryManager = {
  scans: [],

  init() {
    this.bindEvents();
    this.loadScans();
  },

  async loadScans() {
    try {
      const res = await fetch("/api/history/scans");
      if (res.ok) {
        this.scans = await res.json();
        this.renderHistoryTable();
        this.populateDiffSelectors();
      }
    } catch (err) {
      console.warn("Could not load scan history:", err);
    }
  },

  renderHistoryTable() {
    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;

    if (!this.scans.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">
            No historical scans found yet. Launch a DAST scan to record security metrics.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = this.scans.map(s => {
      const statusPill = s.status === "COMPLETED"
        ? `<span class="badge-status verified">COMPLETED</span>`
        : (s.status === "RUNNING" ? `<span class="badge-status running">RUNNING</span>` : `<span class="badge-status pending">${s.status}</span>`);

      const dateStr = s.started_at ? new Date(s.started_at).toLocaleString() : "Unknown";

      return `
        <tr>
          <td style="font-family: monospace; font-size: 11px; color: var(--neon-cyan);"><strong>${s.id}</strong></td>
          <td>
            <div>${s.target_name}</div>
            <div style="font-size: 10px; color: var(--text-muted); font-family: monospace;">${s.target_url}</div>
          </td>
          <td>${statusPill}</td>
          <td>
            <div style="display: flex; gap: 4px; font-size: 11px;">
              ${s.critical_count ? `<span class="badge-sev critical">${s.critical_count} Crit</span>` : ''}
              ${s.high_count ? `<span class="badge-sev high">${s.high_count} High</span>` : ''}
              ${s.medium_count ? `<span class="badge-sev medium">${s.medium_count} Med</span>` : ''}
              ${s.findings_count === 0 ? '<span style="color: var(--neon-green);">0 Vulns</span>' : ''}
            </div>
          </td>
          <td style="font-size: 12px; font-weight: 700; color: ${s.avg_cvss >= 7.0 ? 'var(--neon-red)' : 'var(--neon-yellow)'};">${s.avg_cvss || 0.0}</td>
          <td style="font-size: 11px; color: var(--text-muted);">${dateStr} (${s.duration_seconds || 0}s)</td>
          <td>
            <button class="cyber-btn sm btn-view-history-detail" data-id="${s.id}">View Audit</button>
          </td>
        </tr>
      `;
    }).join("");

    tbody.querySelectorAll(".btn-view-history-detail").forEach(b => {
      b.addEventListener("click", async (e) => {
        const id = e.currentTarget.getAttribute("data-id");
        await this.viewScanDetail(id);
      });
    });
  },

  populateDiffSelectors() {
    const selBase = document.getElementById("diff-base-scan");
    const selTarget = document.getElementById("diff-target-scan");
    if (!selBase || !selTarget) return;

    const options = this.scans.map(s => `<option value="${s.id}">${s.id} - ${s.target_name} (${new Date(s.started_at).toLocaleDateString()})</option>`).join("");
    selBase.innerHTML = options;
    selTarget.innerHTML = options;

    if (this.scans.length >= 2) {
      selTarget.selectedIndex = 0;
      selBase.selectedIndex = 1;
    }
  },

  async viewScanDetail(scanId) {
    try {
      const res = await fetch(`/api/history/scans/${scanId}`);
      if (!res.ok) return;
      const data = await res.json();
      
      const modal = document.getElementById("history-detail-modal");
      if (!modal) return;

      document.getElementById("history-modal-title").textContent = `Audit Log: ${data.id}`;
      document.getElementById("history-modal-target").textContent = `${data.target_name} - ${data.target_url}`;
      
      const findingsList = document.getElementById("history-modal-findings");
      findingsList.innerHTML = data.findings.map(f => `
        <div class="vuln-card ${f.severity.toLowerCase()}">
          <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
              <span class="badge-pill ${f.severity.toLowerCase()}">${f.severity}</span>
              <strong style="margin-left: 8px;">${f.title}</strong>
            </div>
            <span class="cvss-pill">CVSS ${f.cvss_score}</span>
          </div>
          <div style="font-size: 11px; font-family: monospace; color: var(--text-muted); margin-top: 6px;">
            Endpoint: ${f.endpoint} | Param: ${f.parameter || 'N/A'} | CWE: ${f.cwe_id}
          </div>
          <div style="margin-top: 8px; display: flex; gap: 8px; align-items: center;">
            <span style="font-size: 11px; color: var(--text-muted);">Status:</span>
            <select class="cyber-select sm select-finding-status" data-id="${f.id}">
              <option value="OPEN" ${f.status === 'OPEN' ? 'selected' : ''}>OPEN</option>
              <option value="RESOLVED" ${f.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
              <option value="FALSE_POSITIVE" ${f.status === 'FALSE_POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option>
            </select>
          </div>
        </div>
      `).join("");

      findingsList.querySelectorAll(".select-finding-status").forEach(sel => {
        sel.addEventListener("change", async (e) => {
          const fid = e.target.getAttribute("data-id");
          await fetch(`/api/history/findings/${fid}/status`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: e.target.value })
          });
        });
      });

      modal.classList.add("active");
    } catch (err) {
      console.warn("Error viewing scan detail:", err);
    }
  },

  async runDiff() {
    const baseId = document.getElementById("diff-base-scan").value;
    const targetId = document.getElementById("diff-target-scan").value;
    const diffContainer = document.getElementById("diff-results-container");

    if (baseId === targetId) {
      diffContainer.innerHTML = `<div style="color: var(--neon-yellow); padding: 12px;">Please select two different scans to calculate regression diff.</div>`;
      return;
    }

    try {
      const res = await fetch(`/api/history/diff?base_scan_id=${baseId}&target_scan_id=${targetId}`);
      const data = await res.json();
      
      diffContainer.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px;">
          <div class="hud-card">
            <div class="hud-title">FIXED VULNERABILITIES</div>
            <div class="hud-val" style="color: var(--neon-green);">${data.metrics.fixed_count}</div>
            <div class="hud-sub">Remediated between scans</div>
          </div>
          <div class="hud-card">
            <div class="hud-title">PERSISTENT FLAWS</div>
            <div class="hud-val" style="color: var(--neon-yellow);">${data.metrics.persistent_count}</div>
            <div class="hud-sub">Still active in target</div>
          </div>
          <div class="hud-card">
            <div class="hud-title">NEW REGRESSIONS</div>
            <div class="hud-val" style="color: var(--neon-red);">${data.metrics.new_count}</div>
            <div class="hud-sub">Introduced recently</div>
          </div>
        </div>

        ${data.fixed_vulnerabilities.length ? `
          <h4 style="color: var(--neon-green); margin-top: 12px;">✓ Verified Fixed Vulnerabilities:</h4>
          ${data.fixed_vulnerabilities.map(v => `<div class="code-box" style="border-left: 3px solid var(--neon-green); margin-bottom: 4px;">[${v.severity}] ${v.title} (${v.cwe_id}) on ${v.endpoint}</div>`).join("")}
        ` : ''}

        ${data.new_regressions.length ? `
          <h4 style="color: var(--neon-red); margin-top: 12px;">⚠️ New Regressions Detected:</h4>
          ${data.new_regressions.map(v => `<div class="code-box" style="border-left: 3px solid var(--neon-red); margin-bottom: 4px;">[${v.severity}] ${v.title} (${v.cwe_id}) on ${v.endpoint}</div>`).join("")}
        ` : ''}
      `;
    } catch (err) {
      diffContainer.innerHTML = `<div style="color: var(--neon-red);">Error calculating diff: ${err.message}</div>`;
    }
  },

  bindEvents() {
    document.getElementById("btn-run-scan-diff")?.addEventListener("click", () => this.runDiff());
    document.getElementById("close-history-modal-btn")?.addEventListener("click", () => {
      document.getElementById("history-detail-modal")?.classList.remove("active");
    });
    document.getElementById("btn-refresh-history")?.addEventListener("click", () => this.loadScans());
  }
};

document.addEventListener("DOMContentLoaded", () => HistoryManager.init());
