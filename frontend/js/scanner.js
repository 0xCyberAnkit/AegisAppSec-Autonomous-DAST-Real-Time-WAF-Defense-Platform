/**
 * AegisAppSec DAST Scanner Controller
 */

window.Scanner = {
  isScanning: false,

  init() {
    const launchBtn = document.getElementById('btn-launch-scan');
    if (launchBtn) {
      launchBtn.addEventListener('click', () => this.startScan());
    }

    const clearLogsBtn = document.getElementById('btn-clear-logs');
    if (clearLogsBtn) {
      clearLogsBtn.addEventListener('click', () => {
        const logsEl = document.getElementById('terminal-logs');
        if (logsEl) logsEl.innerHTML = '';
      });
    }

    const moduleCheckboxes = document.querySelectorAll('.module-checkbox');
    const updateCount = () => {
      const checked = document.querySelectorAll('.module-checkbox:checked');
      const countEl = document.getElementById('index-module-count');
      if (countEl) countEl.textContent = `${checked.length} / ${moduleCheckboxes.length} Detectors`;
    };
    moduleCheckboxes.forEach(cb => cb.addEventListener('change', updateCount));
  },

  async startScan() {
    const targetUrlInput = document.getElementById('scan-target-url');
    const targetUrl = targetUrlInput ? targetUrlInput.value.trim() : 'http://127.0.0.1:8000/api/shop';

    // Collect selected modules
    const modules = [];
    document.querySelectorAll('.module-checkbox:checked').forEach(cb => {
      modules.push(cb.value);
    });

    const launchBtn = document.getElementById('btn-launch-scan');
    if (launchBtn) {
      launchBtn.disabled = true;
      launchBtn.innerHTML = '<span>⏳ Probing Target & Fuzzing Endpoints...</span>';
    }

    this.updateProgress(5);
    this.appendLog({ level: 'START', message: `Launching autonomous scan against: ${targetUrl}` });

    try {
      const resp = await fetch('/api/scanner/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: targetUrl, modules })
      });
      const data = await resp.json();

      if (resp.status !== 200 || data.status === 'error') {
        this.appendLog({ level: 'ALERT', message: `Scan Error: ${data.detail || data.message}` });
        if (launchBtn) {
          launchBtn.disabled = false;
          launchBtn.innerHTML = '<span>🚀 Launch Autonomous DAST Scan</span>';
        }
        this.updateProgress(0);
      } else {
        this.isScanning = true;
        this.appendLog({ level: 'INFO', message: `Job ${data.scan_id} registered. Running concurrent OWASP Top 10 detectors...` });
      }
    } catch (err) {
      this.appendLog({ level: 'ALERT', message: `Network/API connection failure: ${err.message}` });
      if (launchBtn) {
        launchBtn.disabled = false;
        launchBtn.innerHTML = '<span>🚀 Launch Autonomous DAST Scan</span>';
      }
    }
  },

  updateProgress(pct) {
    const bar = document.getElementById('scan-progress-fill');
    const label = document.getElementById('scan-progress-label');
    if (bar) bar.style.width = `${pct}%`;
    if (label) label.textContent = `${pct}%`;
  },

  appendLog(entry) {
    const logsEl = document.getElementById('terminal-logs');
    if (!logsEl) return;

    const time = entry.timestamp || new Date().toLocaleTimeString();
    const row = document.createElement('div');
    row.className = 'log-entry';
    row.innerHTML = `
      <span class="log-time">[${time}]</span>
      <span class="log-level-${entry.level}">[${entry.level}]</span>
      <span class="log-msg">${escapeHtml(entry.message)}</span>
    `;
    logsEl.appendChild(row);
    logsEl.scrollTop = logsEl.scrollHeight;
  },

  handleScanUpdate(data) {
    this.updateProgress(data.progress || 0);

    const launchBtn = document.getElementById('btn-launch-scan');
    if (data.status === 'COMPLETED' || data.status === 'FAILED') {
      this.isScanning = false;
      if (launchBtn) {
        launchBtn.disabled = false;
        launchBtn.innerHTML = '<span>🚀 Launch Autonomous DAST Scan</span>';
      }
      this.appendLog({
        level: 'FINISH',
        message: `Scan pipeline completed in ${data.duration_seconds}s. Total vulnerabilities: ${data.findings_count}`
      });
    }

    if (data.logs && data.logs.length > 0) {
      // Re-hydrate logs if empty
      const logsEl = document.getElementById('terminal-logs');
      if (logsEl && logsEl.children.length === 0) {
        data.logs.forEach(l => this.appendLog(l));
      }
    }
  }
};

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

document.addEventListener('DOMContentLoaded', () => {
  window.Scanner.init();
});
