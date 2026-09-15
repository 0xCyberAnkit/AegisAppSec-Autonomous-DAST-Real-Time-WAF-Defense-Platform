/**
 * AegisAppSec - Team & RBAC Governance Manager
 * Handles enterprise collaborator roster, teammate invitations, and RBAC matrix.
 */

window.AegisTeam = (function() {
  const API_BASE = '/api/team';

  async function init() {
    setupEventListeners();
    await loadMembers();
    await loadRbacMatrix();
  }

  async function loadMembers() {
    const tbody = document.getElementById('teamTableBody') || document.getElementById('team-table-body');
    if (!tbody) return;

    try {
      const resp = await fetch(`${API_BASE}/members`);
      const data = await resp.json();
      const members = data.members || [];

      if (members.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No team members found.</td></tr>`;
        return;
      }

      const roleBadges = {
        admin: '<span class="badge-status verified" style="background: rgba(239, 68, 68, 0.2); border-color: var(--neon-red); color: var(--neon-red);">Admin</span>',
        pentester: '<span class="badge-status verified" style="background: rgba(0, 242, 254, 0.2); border-color: var(--neon-cyan); color: var(--neon-cyan);">Pentester</span>',
        developer: '<span class="badge-status verified" style="background: rgba(16, 185, 129, 0.2); border-color: var(--neon-green); color: var(--neon-green);">Developer</span>'
      };

      tbody.innerHTML = members.map(m => `
        <tr>
          <td>
            <div style="display: flex; align-items: center; gap: 10px;">
              <div class="team-avatar">${escapeHtml(m.name.charAt(0).toUpperCase())}</div>
              <div>
                <div style="font-weight: 700; color: var(--text-primary); font-size: 13px;">${escapeHtml(m.name)}</div>
                <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(m.email)}</div>
              </div>
            </div>
          </td>
          <td>
            <div style="display: flex; flex-direction: column; gap: 2px;">
              <div>${roleBadges[m.role] || escapeHtml(m.role)}</div>
              <div style="font-size: 10px; color: var(--text-muted);">${escapeHtml(m.role_title || '')}</div>
            </div>
          </td>
          <td>
            <span class="badge-status ${m.status === 'ACTIVE' ? 'verified' : 'unverified'}">
              ${escapeHtml(m.status)}
            </span>
          </td>
          <td>
            <span style="color: ${m.two_factor ? 'var(--neon-green)' : 'var(--neon-amber)'}; font-size: 12px; font-weight: bold;">
              ${m.two_factor ? '✓ Enforced' : '⚠ Optional'}
            </span>
          </td>
          <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(m.last_active || 'N/A')}</td>
          <td>
            <button class="cyber-btn secondary btn-remove-member" data-id="${m.id}" style="padding: 4px 10px; font-size: 11px; color: var(--neon-red);">
              Revoke
            </button>
          </td>
        </tr>
      `).join('');

      document.querySelectorAll('.btn-remove-member').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.id;
          if (confirm(`Revoke enterprise access for team member #${id}?`)) {
            await removeMember(id);
          }
        });
      });

    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--neon-red); padding: 20px;">Failed to load team roster: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function loadRbacMatrix() {
    const container = document.getElementById('rbac-matrix-container');
    if (!container) return;

    try {
      const resp = await fetch(`${API_BASE}/roles`);
      const data = await resp.json();
      const roles = data.roles || [];

      const permLabels = [
        { key: "domain_verification", label: "Verify Target Domain Ownership" },
        { key: "launch_dast_scans", label: "Trigger DAST Scans & Crawler" },
        { key: "manual_payload_injection", label: "Custom Payload Testing & PoC Tuning" },
        { key: "waf_mode_toggle", label: "Modify WAF Defense Mode" },
        { key: "custom_virtual_patches", label: "Deploy Virtual Patches (Custom Regex)" },
        { key: "manage_team", label: "Manage Team & RBAC Invites" },
        { key: "api_key_management", label: "Generate CI/CD API Keys & Webhooks" },
        { key: "export_executive_reports", label: "Download Executive PDF/CSV Reports" }
      ];

      container.innerHTML = `
        <table class="cyber-table rbac-table">
          <thead>
            <tr>
              <th style="width: 35%;">Platform Security Capability</th>
              <th style="text-align: center; color: var(--neon-red);">SecOps Admin</th>
              <th style="text-align: center; color: var(--neon-cyan);">Offensive Pentester</th>
              <th style="text-align: center; color: var(--neon-green);">AppSec Developer</th>
            </tr>
          </thead>
          <tbody>
            ${permLabels.map(p => {
              const adminHas = roles.find(r => r.id === 'admin')?.permissions[p.key];
              const pentesterHas = roles.find(r => r.id === 'pentester')?.permissions[p.key];
              const devHas = roles.find(r => r.id === 'developer')?.permissions[p.key];
              return `
                <tr>
                  <td style="font-weight: 600; font-size: 13px;">${escapeHtml(p.label)}</td>
                  <td style="text-align: center; font-size: 16px; color: ${adminHas ? 'var(--neon-green)' : 'var(--text-muted)'};">
                    ${adminHas ? '✓' : '—'}
                  </td>
                  <td style="text-align: center; font-size: 16px; color: ${pentesterHas ? 'var(--neon-green)' : 'var(--text-muted)'};">
                    ${pentesterHas ? '✓' : '—'}
                  </td>
                  <td style="text-align: center; font-size: 16px; color: ${devHas ? 'var(--neon-green)' : 'var(--text-muted)'};">
                    ${devHas ? '✓' : '—'}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;

    } catch (err) {
      container.innerHTML = `<div style="color: var(--neon-red);">Failed to load RBAC matrix.</div>`;
    }
  }

  async function removeMember(id) {
    try {
      const resp = await fetch(`${API_BASE}/members/${id}`, { method: 'DELETE' });
      if (resp.ok) {
        await loadMembers();
      } else {
        alert("Failed to remove member.");
      }
    } catch (err) {
      alert("Error removing team member.");
    }
  }

  function setupEventListeners() {
    const inviteBtn = document.getElementById('btn-open-invite-modal') || document.getElementById('btnOpenInviteModal');
    const modal = document.getElementById('invite-team-modal') || document.getElementById('inviteModal');
    const closeBtn = document.getElementById('btn-close-invite-modal');
    const inviteForm = document.getElementById('invite-team-form') || document.getElementById('inviteForm');

    if (inviteBtn && modal) {
      inviteBtn.addEventListener('click', () => modal.classList.add('active'));
    }
    if (closeBtn && modal) {
      closeBtn.addEventListener('click', () => modal.classList.remove('active'));
    }

    if (inviteForm) {
      inviteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = (document.getElementById('invite-name') || document.getElementById('inviteName')).value.trim();
        const email = (document.getElementById('invite-email') || document.getElementById('inviteEmail')).value.trim();
        const role = (document.getElementById('invite-role') || document.getElementById('inviteRole')).value;
        const statusEl = document.getElementById('invite-status') || document.getElementById('inviteErrorNotice');

        try {
          const resp = await fetch(`${API_BASE}/members`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, role })
          });
          const data = await resp.json();
          if (resp.ok) {
            if (statusEl) {
              statusEl.style.color = 'var(--neon-green)';
              statusEl.textContent = data.message;
            }
            inviteForm.reset();
            setTimeout(() => {
              if (modal) modal.classList.remove('active');
              if (statusEl) statusEl.textContent = '';
              loadMembers();
            }, 1000);
          } else {
            if (statusEl) {
              statusEl.style.color = 'var(--neon-red)';
              statusEl.textContent = data.detail || 'Failed to dispatch invitation.';
            }
          }
        } catch (err) {
          if (statusEl) {
            statusEl.style.color = 'var(--neon-red)';
            statusEl.textContent = 'Connection error inviting teammate.';
          }
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
    loadMembers,
    loadRbacMatrix
  };
})();
