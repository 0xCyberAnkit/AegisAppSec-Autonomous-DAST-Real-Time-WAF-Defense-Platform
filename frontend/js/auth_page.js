/**
 * AegisAppSec - Dedicated Identity & IAM Workbench
 * Handles user profile display, instant persona switching, registration as Individual vs Enterprise, and session security.
 */

window.AegisAuthPage = (function() {
  const API_BASE = '/api/auth';

  async function init() {
    renderProfileCard();
    setupEventListeners();
  }

  function renderProfileCard() {
    const user = window.AegisAuth ? window.AegisAuth.getUser() : null;
    const profileContainer = document.getElementById('auth-page-profile-container');
    if (!profileContainer) return;

    if (!user) {
      profileContainer.innerHTML = `
        <div class="empty-card-box">
          <div style="font-size: 36px; margin-bottom: 10px;">🔐</div>
          <h3 style="font-size: 16px; margin-bottom: 6px;">No Active Session Detected</h3>
          <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
            Sign in below or select a 1-click operator persona to access enterprise features and scan targets.
          </p>
        </div>
      `;
      return;
    }

    const roleBadges = {
      admin: '<span class="badge-status verified" style="background: rgba(239, 68, 68, 0.2); border-color: var(--neon-red); color: var(--neon-red);">SecOps Admin</span>',
      pentester: '<span class="badge-status verified" style="background: rgba(0, 242, 254, 0.2); border-color: var(--neon-cyan); color: var(--neon-cyan);">Offensive Pentester</span>',
      developer: '<span class="badge-status verified" style="background: rgba(16, 185, 129, 0.2); border-color: var(--neon-green); color: var(--neon-green);">AppSec Developer</span>'
    };

    profileContainer.innerHTML = `
      <div class="iam-profile-card">
        <div class="iam-profile-header">
          <div class="iam-avatar">${escapeHtml(user.full_name.charAt(0).toUpperCase())}</div>
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
              <h3 style="font-size: 18px; font-weight: 800;">${escapeHtml(user.full_name)}</h3>
              ${roleBadges[user.role] || ''}
            </div>
            <div style="font-size: 13px; color: var(--neon-cyan); font-family: var(--font-mono);">${escapeHtml(user.email)}</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
              Organization: <strong>${escapeHtml(user.company || 'Enterprise Workspace')}</strong>
            </div>
          </div>
          <button id="btn-page-logout" class="cyber-btn secondary" style="padding: 6px 14px; font-size: 12px;">Sign Out</button>
        </div>

        <div class="iam-details-grid">
          <div class="iam-detail-item">
            <div class="detail-label">Account Tier</div>
            <div class="detail-val" style="color: var(--neon-purple);">
              ${user.company && user.company !== 'Independent' ? 'Enterprise Tier (Multi-User)' : 'Individual Pentester Pro'}
            </div>
          </div>
          <div class="iam-detail-item">
            <div class="detail-label">JWT Token Status</div>
            <div class="detail-val" style="color: var(--neon-green);">Active / Validated (HS256)</div>
          </div>
          <div class="iam-detail-item">
            <div class="detail-label">Domain Auth Scope</div>
            <div class="detail-val">${user.role === 'admin' ? 'Full Domain Governance' : (user.role === 'pentester' ? 'Authorized Pentest Scans' : 'Remediation Read-Only')}</div>
          </div>
          <div class="iam-detail-item">
            <div class="detail-label">2-Factor Auth</div>
            <div class="detail-val" style="color: var(--neon-cyan);">Enforced (TOTP / Hardware Key)</div>
          </div>
        </div>
      </div>
    `;

    const logoutBtn = document.getElementById('btn-page-logout');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        if (window.AegisAuth) window.AegisAuth.logout();
        renderProfileCard();
      });
    }
  }

  function setupEventListeners() {
    // 1-Click persona switchers in page
    document.querySelectorAll('.page-role-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const role = btn.dataset.role;
        try {
          const resp = await fetch(`${API_BASE}/demo-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role })
          });
          const data = await resp.json();
          if (resp.ok) {
            localStorage.setItem('aegis_token', data.access_token);
            localStorage.setItem('aegis_user', JSON.stringify(data.user));
            if (window.AegisAuth) window.AegisAuth.updateNavbarUser();
            renderProfileCard();
            showStatus('auth-page-status', `Switched operator persona to ${data.user.full_name} (${data.user.role})`, true);
          } else {
            showStatus('auth-page-status', data.detail || 'Demo login failed', false);
          }
        } catch (e) {
          showStatus('auth-page-status', 'Connection error switching persona', false);
        }
      });
    });

    // In-page Login Form
    const pageLoginForm = document.getElementById('page-login-form');
    if (pageLoginForm) {
      pageLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('page-login-email').value.trim();
        const password = document.getElementById('page-login-password').value;
        const statusEl = 'page-login-status';

        try {
          const resp = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
          });
          const data = await resp.json();
          if (resp.ok) {
            localStorage.setItem('aegis_token', data.access_token);
            localStorage.setItem('aegis_user', JSON.stringify(data.user));
            if (window.AegisAuth) window.AegisAuth.updateNavbarUser();
            renderProfileCard();
            showStatus(statusEl, `Welcome back, ${data.user.full_name}!`, true);
          } else {
            showStatus(statusEl, data.detail || 'Invalid email or password', false);
          }
        } catch (err) {
          showStatus(statusEl, 'Error contacting auth server', false);
        }
      });
    }

    // In-page Register Form
    const pageRegisterForm = document.getElementById('page-register-form');
    if (pageRegisterForm) {
      pageRegisterForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const full_name = document.getElementById('page-reg-name').value.trim();
        const email = document.getElementById('page-reg-email').value.trim();
        const password = document.getElementById('page-reg-password').value;
        const role = document.getElementById('page-reg-role').value;
        const company = document.getElementById('page-reg-company').value.trim() || 'Independent';
        const statusEl = 'page-reg-status';

        try {
          const resp = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full_name, email, password, role, company })
          });
          const data = await resp.json();
          if (resp.ok) {
            localStorage.setItem('aegis_token', data.access_token);
            localStorage.setItem('aegis_user', JSON.stringify(data.user));
            if (window.AegisAuth) window.AegisAuth.updateNavbarUser();
            renderProfileCard();
            showStatus(statusEl, `Account registered! Logged in as ${data.user.full_name}`, true);
          } else {
            showStatus(statusEl, data.detail || 'Registration failed', false);
          }
        } catch (err) {
          showStatus(statusEl, 'Error registering account', false);
        }
      });
    }

    // Page Auth sub-tabs
    document.querySelectorAll('.page-auth-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.page-auth-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        const targetForm = tab.dataset.form;
        document.querySelectorAll('.page-auth-panel').forEach(p => p.classList.remove('active'));
        const activePanel = document.getElementById(targetForm);
        if (activePanel) activePanel.classList.add('active');
      });
    });
  }

  function showStatus(elementId, msg, isSuccess) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.style.color = isSuccess ? 'var(--neon-green)' : 'var(--neon-red)';
    el.style.display = 'block';
    el.textContent = msg;
    setTimeout(() => {
      if (el) el.style.display = 'none';
    }, 4000);
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
    renderProfileCard
  };
})();
