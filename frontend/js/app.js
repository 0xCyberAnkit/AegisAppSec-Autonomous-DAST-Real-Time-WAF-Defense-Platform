/**
 * AegisAppSec Core Application Controller
 * Handles navigation, global HUD telemetry, WebSocket connections, and mode switches.
 */

const App = {
  state: {
    activeTab: 'scanner',
    wafMode: 'OFF',
    threatLevel: 'LOW',
    stats: {
      totalInspected: 0,
      totalBlocked: 0,
      vulnerabilitiesCount: 0,
      evasionsDefeated: 0
    },
    findings: [],
    logs: [],
    isScanning: false
  },

  init() {
    this.setupTabs();
    this.setupWAFControls();
    this.connectWebSocket();
    this.fetchInitialStatus();
    
    if (window.AegisAuthPage) window.AegisAuthPage.init();
    if (window.AegisTeam) window.AegisTeam.init();
    if (window.AegisWafRules) window.AegisWafRules.init();
    if (window.AegisReportsPage) window.AegisReportsPage.init();

    // Polling fallback every 3 seconds for WAF telemetry
    setInterval(() => this.fetchWAFMetrics(), 3000);
  },

  setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        this.switchTab(targetTab);
      });
    });
  },

  switchTab(tabName) {
    this.state.activeTab = tabName;
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabName);
    });
    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === `tab-${tabName}`);
    });

    if (tabName === 'storefront' && window.Storefront) {
      window.Storefront.loadProducts();
    } else if (tabName === 'remediation' && window.Remediation) {
      window.Remediation.loadGuidance('CWE-89');
    } else if (tabName === 'targets' && window.TargetsManager) {
      window.TargetsManager.loadTargets();
    } else if (tabName === 'history' && window.HistoryManager) {
      window.HistoryManager.loadScans();
    } else if (tabName === 'compliance' && window.ComplianceManager) {
      window.ComplianceManager.loadCompliance();
    } else if (tabName === 'apikeys' && window.ApiKeysManager) {
      window.ApiKeysManager.loadKeys();
    } else if (tabName === 'team' && window.AegisTeam) {
      window.AegisTeam.loadMembers();
      window.AegisTeam.loadRbacMatrix();
    } else if (tabName === 'waf-rules' && window.AegisWafRules) {
      window.AegisWafRules.loadRules();
    } else if (tabName === 'report' && window.AegisReportsPage) {
      window.AegisReportsPage.loadPreview();
    } else if (tabName === 'auth' && window.AegisAuthPage) {
      window.AegisAuthPage.renderProfileCard();
    }
  },

  setupWAFControls() {
    const buttons = document.querySelectorAll('.mode-btn');
    buttons.forEach(btn => {
      btn.addEventListener('click', async () => {
        const newMode = btn.getAttribute('data-mode');
        await this.setWAFMode(newMode);
      });
    });
  },

  async setWAFMode(mode) {
    try {
      const resp = await fetch('/api/waf/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      const data = await resp.json();
      if (data.status === 'success') {
        this.updateWAFModeUI(data.mode);
        if (window.WAFMonitor) window.WAFMonitor.refresh();
      }
    } catch (err) {
      console.error('Failed to change WAF mode:', err);
    }
  },

  updateWAFModeUI(mode) {
    this.state.wafMode = mode;
    const badge = document.getElementById('current-waf-mode-badge');
    if (badge) {
      badge.textContent = mode;
      badge.className = `mode-btn active-${mode.toLowerCase()}`;
    }

    document.querySelectorAll('.mode-btn').forEach(btn => {
      const btnMode = btn.getAttribute('data-mode');
      btn.className = `mode-btn ${btnMode === mode ? `active-${mode.toLowerCase()}` : ''}`;
    });

    // Update Storefront banner if visible
    const storeBanner = document.getElementById('store-waf-banner');
    if (storeBanner) {
      if (mode === 'BLOCK') {
        storeBanner.textContent = '🛡️ WAF ACTIVE: All SQLi, XSS, and SSRF attacks will be rejected with HTTP 403.';
        storeBanner.style.color = 'var(--neon-green)';
        storeBanner.style.borderColor = 'var(--neon-green)';
      } else if (mode === 'OFF') {
        storeBanner.textContent = '⚠️ WAF OFF: Target is in vulnerable mode. Injections will execute!';
        storeBanner.style.color = 'var(--neon-red)';
        storeBanner.style.borderColor = 'var(--neon-red)';
      } else {
        storeBanner.textContent = `🛡️ WAF MODE: ${mode}`;
        storeBanner.style.color = 'var(--neon-amber)';
        storeBanner.style.borderColor = 'var(--neon-amber)';
      }
    }
  },

  async fetchInitialStatus() {
    try {
      const [wafResp, scanResp] = await Promise.all([
        fetch('/api/waf/metrics'),
        fetch('/api/scanner/status')
      ]);
      const wafData = await wafResp.json();
      const scanData = await scanResp.json();

      this.updateWAFModeUI(wafData.mode);
      this.updateHUD(wafData, scanData);
      
      if (scanData.findings && window.Vulnerabilities) {
        window.Vulnerabilities.render(scanData.findings);
      }
    } catch (e) {
      console.warn('Initial status fetch error:', e);
    }
  },

  async fetchWAFMetrics() {
    try {
      const resp = await fetch('/api/waf/metrics');
      const data = await resp.json();
      this.updateHUD(data);
      if (window.WAFMonitor) window.WAFMonitor.update(data);
    } catch (e) {
      // Backend maybe restarting
    }
  },

  updateHUD(wafData, scanData) {
    if (wafData) {
      document.getElementById('hud-inspected').textContent = wafData.total_inspected || 0;
      document.getElementById('hud-blocked').textContent = wafData.total_blocked || 0;
      document.getElementById('hud-threat-level').textContent = wafData.active_threat_level || 'LOW';
      
      const levelEl = document.getElementById('hud-threat-level');
      if (wafData.active_threat_level === 'CRITICAL') levelEl.style.color = 'var(--neon-red)';
      else if (wafData.active_threat_level === 'HIGH') levelEl.style.color = 'var(--neon-amber)';
      else levelEl.style.color = 'var(--neon-green)';
    }

    if (scanData) {
      document.getElementById('hud-vulns-found').textContent = scanData.findings_count || 0;
    }
  },

  connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/scanner/ws`;
    
    try {
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('[Aegis WS] Connected to Scanner Real-time Stream.');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.handleWSEvent(msg);
        } catch (err) {
          console.error('[Aegis WS] Error parsing message:', err);
        }
      };

      ws.onclose = () => {
        setTimeout(() => this.connectWebSocket(), 4000);
      };
    } catch (err) {
      console.warn('WebSocket connection error:', err);
    }
  },

  handleWSEvent(msg) {
    if (msg.type === 'init' || msg.type === 'scan_completed') {
      if (window.Scanner) window.Scanner.handleScanUpdate(msg.data);
      if (window.Vulnerabilities && msg.data.findings) {
        window.Vulnerabilities.render(msg.data.findings);
      }
      this.updateHUD(null, msg.data);
    } else if (msg.type === 'progress') {
      if (window.Scanner) window.Scanner.updateProgress(msg.data.progress);
    } else if (msg.type === 'log') {
      if (window.Scanner) window.Scanner.appendLog(msg.data);
    } else if (msg.type === 'vuln_found') {
      if (window.Vulnerabilities) window.Vulnerabilities.addFinding(msg.data);
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
