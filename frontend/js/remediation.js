/**
 * Developer Remediation Hub Controller
 */

window.Remediation = {
  currentCwe: 'CWE-89',
  currentLang: 'python',
  guides: {},

  init() {
    this.fetchAllGuides();

    document.querySelectorAll('.rem-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.rem-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        this.currentCwe = tab.getAttribute('data-cwe');
        this.renderGuidance();
      });
    });

    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentLang = btn.getAttribute('data-lang');
        this.renderGuidance();
      });
    });
  },

  async fetchAllGuides() {
    try {
      const resp = await fetch('/api/reports/all-remediations');
      const data = await resp.json();
      if (data.status === 'success') {
        this.guides = data.guides;
        this.renderGuidance();
      }
    } catch (e) {
      console.warn('Failed to load remediation guides:', e);
    }
  },

  loadGuidance(cweId) {
    this.currentCwe = cweId.toUpperCase();
    document.querySelectorAll('.rem-tab').forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-cwe') === this.currentCwe);
    });
    this.renderGuidance();
  },

  renderGuidance() {
    const guide = this.guides[this.currentCwe];
    if (!guide) return;

    document.getElementById('rem-title').textContent = `${guide.title} (${this.currentCwe})`;
    document.getElementById('rem-owasp').textContent = guide.owasp;
    document.getElementById('rem-desc').textContent = guide.description;

    // Render Checklist
    const checklistEl = document.getElementById('rem-checklist');
    if (checklistEl && guide.checklist) {
      checklistEl.innerHTML = guide.checklist.map(item => `
        <li style="margin-bottom: 6px; color: var(--text-secondary);">
          <span style="color: var(--neon-green); font-weight: bold; margin-right: 6px;">✓</span>
          ${escapeHtml(item)}
        </li>
      `).join('');
    }

    // Render Code Snippets
    const snippets = guide.code_snippets ? guide.code_snippets[this.currentLang] : null;
    const vulnCodeEl = document.getElementById('diff-vuln-code');
    const secureCodeEl = document.getElementById('diff-secure-code');

    if (snippets) {
      if (vulnCodeEl) vulnCodeEl.textContent = snippets.vulnerable;
      if (secureCodeEl) secureCodeEl.textContent = snippets.secure;
    } else {
      if (vulnCodeEl) vulnCodeEl.textContent = '// Code snippet not available for selected language';
      if (secureCodeEl) secureCodeEl.textContent = '// Code snippet not available for selected language';
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  window.Remediation.init();
});
