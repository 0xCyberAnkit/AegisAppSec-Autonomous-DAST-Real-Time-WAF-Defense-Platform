/**
 * Aegis-Shield WAF Monitor & Real-Time Threat Radar
 */

window.WAFMonitor = {
  init() {
    this.refresh();
    const clearBtn = document.getElementById('btn-clear-waf-metrics');
    if (clearBtn) {
      clearBtn.addEventListener('click', async () => {
        await fetch('/api/waf/clear', { method: 'POST' });
        this.refresh();
      });
    }
  },

  async refresh() {
    try {
      const [metricsResp, rulesResp] = await Promise.all([
        fetch('/api/waf/metrics'),
        fetch('/api/waf/rules')
      ]);
      const metrics = await metricsResp.json();
      const rulesData = await rulesResp.json();

      this.update(metrics);
      this.renderRules(rulesData.rules);
    } catch (e) {
      console.warn('WAF refresh error:', e);
    }
  },

  update(metrics) {
    if (!metrics) return;

    // Update Counter Cards
    const elBlocked = document.getElementById('waf-stat-blocked');
    const elInspected = document.getElementById('waf-stat-inspected');
    const elEvasions = document.getElementById('waf-stat-evasions');
    const elThreat = document.getElementById('waf-stat-threat');

    if (elBlocked) elBlocked.textContent = metrics.total_blocked || 0;
    if (elInspected) elInspected.textContent = metrics.total_inspected || 0;
    if (elEvasions) elEvasions.textContent = metrics.evasions_defeated || 0;
    if (elThreat) elThreat.textContent = metrics.active_threat_level || 'LOW';

    // Update Attack Type Breakdown
    const breakdownEl = document.getElementById('waf-attack-breakdown');
    if (breakdownEl && metrics.attack_counters) {
      breakdownEl.innerHTML = Object.entries(metrics.attack_counters).map(([name, count]) => `
        <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px;">
          <span style="color: var(--text-secondary);">${escapeHtml(name)}</span>
          <span style="font-family: var(--font-mono); font-weight: bold; color: ${count > 0 ? 'var(--neon-cyan)' : 'var(--text-muted)'};">${count}</span>
        </div>
      `).join('');
    }

    // Update Live Events Table
    const tableBody = document.getElementById('waf-events-tbody');
    if (tableBody) {
      const events = metrics.recent_events || [];
      if (events.length === 0) {
        tableBody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
              No attack traffic intercepted yet. Toggle WAF to BLOCK and execute an attack in the CyberMart Store.
            </td>
          </tr>
        `;
      } else {
        tableBody.innerHTML = events.map(evt => {
          const evasionBadge = (evt.evasions && evt.evasions.length > 0)
            ? `<span style="color: var(--neon-purple); font-size: 11px;">[${evt.evasions.join(', ')}]</span>`
            : '<span style="color: var(--text-muted);">None</span>';

          return `
            <tr>
              <td style="color: var(--text-muted);">${evt.timestamp}</td>
              <td style="color: var(--neon-blue);">${escapeHtml(evt.client_ip)}</td>
              <td><code>${escapeHtml(evt.endpoint)}</code></td>
              <td><strong>${escapeHtml(evt.attack_type)}</strong></td>
              <td>${evasionBadge}</td>
              <td><span class="action-tag-${evt.action}">${evt.action}</span></td>
            </tr>
          `;
        }).join('');
      }
    }
  },

  renderRules(rules) {
    const rulesContainer = document.getElementById('waf-rules-list');
    if (!rulesContainer || !rules) return;

    rulesContainer.innerHTML = rules.map(r => `
      <div style="padding: 8px 12px; background: rgba(10, 15, 28, 0.6); border: 1px solid var(--border-subtle); border-radius: 6px; margin-bottom: 8px; font-size: 12px; display: flex; justify-content: space-between; align-items: center;">
        <div>
          <strong style="color: var(--neon-cyan);">${r.id}</strong>: ${escapeHtml(r.name)}
        </div>
        <span style="color: var(--text-muted); font-size: 11px; text-transform: uppercase;">${r.category}</span>
      </div>
    `).join('');
  }
};

document.addEventListener('DOMContentLoaded', () => {
  window.WAFMonitor.init();
});
