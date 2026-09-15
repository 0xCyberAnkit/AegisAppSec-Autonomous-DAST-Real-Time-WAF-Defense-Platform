/**
 * AegisAppSec - WAF Virtual Patching Studio
 * Allows security engineers to create custom regex virtual patches to immediately mitigate 0-days,
 * and test payloads against active rules in a real-time sandbox.
 */

window.AegisWafRules = (function() {
  const API_BASE = '/api/waf/custom-rules';

  async function init() {
    setupEventListeners();
    await loadRules();
  }

  async function loadRules() {
    const tbody = document.getElementById('custom-rules-table-body');
    if (!tbody) return;

    try {
      const resp = await fetch(API_BASE);
      const rules = await resp.json();

      if (!rules || rules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No custom virtual patch rules configured.</td></tr>`;
        return;
      }

      const actionColors = {
        BLOCK: 'var(--neon-red)',
        DETECT: 'var(--neon-amber)',
        SANITIZE: 'var(--neon-cyan)'
      };

      tbody.innerHTML = rules.map(r => `
        <tr>
          <td>
            <div style="font-weight: 700; color: var(--text-primary); font-size: 13px;">${escapeHtml(r.name)}</div>
            <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(r.description || '')}</div>
          </td>
          <td>
            <code class="cyber-code-inline" style="color: var(--neon-cyan);">${escapeHtml(r.pattern)}</code>
          </td>
          <td>
            <span class="badge-status" style="background: rgba(255,255,255,0.05); color: ${actionColors[r.action] || 'var(--text-primary)'}; border: 1px solid ${actionColors[r.action] || 'var(--border-subtle)'};">
              ${escapeHtml(r.action)}
            </span>
          </td>
          <td>
            <button class="cyber-btn ${r.is_active ? 'primary' : 'secondary'} btn-toggle-rule" data-id="${r.id}" style="padding: 4px 10px; font-size: 11px;">
              ${r.is_active ? '[ACTIVE]' : '[INACTIVE]'}
            </button>
          </td>
          <td style="font-size: 11px; color: var(--text-muted);">${r.created_at ? r.created_at.slice(0, 10) : 'Preset'}</td>
          <td>
            <button class="cyber-btn secondary btn-delete-rule" data-id="${r.id}" style="padding: 4px 8px; font-size: 11px; color: var(--neon-red);">
              Delete
            </button>
          </td>
        </tr>
      `).join('');

      // Wire toggles
      document.querySelectorAll('.btn-toggle-rule').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.id;
          await toggleRule(id);
        });
      });

      // Wire deletes
      document.querySelectorAll('.btn-delete-rule').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.id;
          if (confirm(`Remove virtual patch rule #${id}?`)) {
            await deleteRule(id);
          }
        });
      });

    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--neon-red); padding: 20px;">Failed to load virtual patch rules: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function toggleRule(id) {
    try {
      const resp = await fetch(`${API_BASE}/${id}/toggle`, { method: 'PATCH' });
      if (resp.ok) {
        await loadRules();
      }
    } catch (err) {
      alert("Error toggling rule status.");
    }
  }

  async function deleteRule(id) {
    try {
      const resp = await fetch(`${API_BASE}/${id}`, { method: 'DELETE' });
      if (resp.ok) {
        await loadRules();
      }
    } catch (err) {
      alert("Error deleting rule.");
    }
  }

  function setupEventListeners() {
    // New Rule Form
    const createForm = document.getElementById('create-virtual-patch-form');
    if (createForm) {
      createForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('patch-name').value.trim();
        const pattern = document.getElementById('patch-pattern').value.trim();
        const action = document.getElementById('patch-action').value;
        const description = document.getElementById('patch-desc').value.trim();
        const statusEl = document.getElementById('create-patch-status');

        try {
          const resp = await fetch(API_BASE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, pattern, action, description })
          });
          const data = await resp.json();
          if (resp.ok) {
            statusEl.style.color = 'var(--neon-green)';
            statusEl.textContent = data.message;
            createForm.reset();
            setTimeout(() => {
              statusEl.textContent = '';
              loadRules();
            }, 1200);
          } else {
            statusEl.style.color = 'var(--neon-red)';
            statusEl.textContent = data.detail || 'Failed to create virtual patch.';
          }
        } catch (err) {
          statusEl.style.color = 'var(--neon-red)';
          statusEl.textContent = 'Connection error deploying patch.';
        }
      });
    }

    // Payload Test Simulator
    const testBtn = document.getElementById('btn-test-payload');
    if (testBtn) {
      testBtn.addEventListener('click', async () => {
        const payload = document.getElementById('test-payload-input').value;
        const resultBox = document.getElementById('test-payload-result');
        if (!payload) {
          alert("Please enter a test payload string.");
          return;
        }

        try {
          const resp = await fetch(`${API_BASE}/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload })
          });
          const data = await resp.json();

          if (data.is_blocked) {
            resultBox.innerHTML = `
              <div class="test-result-box blocked">
                <div style="font-size: 15px; font-weight: 800; color: var(--neon-red); margin-bottom: 6px;">
                  [INTERCEPTED // HTTP 403 FORBIDDEN]
                </div>
                <div style="font-size: 13px; margin-bottom: 8px;">
                  Payload matched <strong>${data.match_count}</strong> active virtual patch rule(s).
                </div>
                ${data.matches.map(m => `
                  <div style="font-size: 12px; background: rgba(0,0,0,0.4); padding: 8px; border-radius: 4px; margin-bottom: 4px;">
                    <strong>Triggered Rule:</strong> ${escapeHtml(m.rule_name)} (${m.action})<br>
                    <strong>Matched Substring:</strong> <code style="color: var(--neon-red);">${escapeHtml(m.matched_substring)}</code>
                  </div>
                `).join('')}
              </div>
            `;
          } else if (data.match_count > 0) {
            resultBox.innerHTML = `
              <div class="test-result-box sanitized">
                <div style="font-size: 15px; font-weight: 800; color: var(--neon-cyan); margin-bottom: 6px;">
                  [SANITIZED // HTTP 200 PROCESSED]
                </div>
                <div style="font-size: 13px;">Payload sanitized by virtual patch rule.</div>
              </div>
            `;
          } else {
            resultBox.innerHTML = `
              <div class="test-result-box passed">
                <div style="font-size: 15px; font-weight: 800; color: var(--neon-green); margin-bottom: 6px;">
                  [PASSED // NO VIRTUAL PATCH TRIGGERED]
                </div>
                <div style="font-size: 13px; color: var(--text-muted);">
                  The simulated string passed through all active custom regex filters without interception.
                </div>
              </div>
            `;
          }
        } catch (err) {
          resultBox.innerHTML = `<div style="color: var(--neon-red);">Test execution failed.</div>`;
        }
      });
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return {
    init,
    loadRules
  };
})();
