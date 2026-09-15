/**
 * Vulnerability Triage & Inspector
 */

window.Vulnerabilities = {
  findings: [],
  activeFilter: 'ALL',

  init() {
    document.querySelectorAll('.filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        this.activeFilter = chip.getAttribute('data-filter');
        this.renderGrid();
      });
    });
  },

  render(findingsList) {
    this.findings = findingsList || [];
    this.renderGrid();
  },

  addFinding(finding) {
    // Avoid duplicate IDs
    if (!this.findings.some(f => f.id === finding.id)) {
      this.findings.unshift(finding);
      this.renderGrid();
    }
  },

  renderGrid() {
    const grid = document.getElementById('vuln-cards-grid');
    if (!grid) return;

    let filtered = this.findings;
    if (this.activeFilter !== 'ALL') {
      filtered = this.findings.filter(f => f.severity.toUpperCase() === this.activeFilter);
    }

    if (filtered.length === 0) {
      grid.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; padding: 60px 20px; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">🛡️</div>
          <div style="font-size: 16px; font-weight: 600;">No Vulnerabilities Discovered for Filter [${this.activeFilter}]</div>
          <div style="font-size: 13px; margin-top: 6px;">Initiate a DAST scan from the Workbench or toggle WAF to OFF to uncover weaknesses.</div>
        </div>
      `;
      return;
    }

    grid.innerHTML = filtered.map(f => {
      const sevClass = `sev-${f.severity.toLowerCase()}`;
      return `
        <div class="vuln-card">
          <div>
            <div class="vuln-card-top">
              <span class="severity-pill ${sevClass}">${f.severity}</span>
              <span class="cvss-meter">CVSS ${f.cvss_score}</span>
            </div>
            <div class="vuln-title">${escapeHtml(f.title)}</div>
            <div class="vuln-meta">
              <span><strong>Endpoint:</strong> <code>${f.method} ${escapeHtml(f.endpoint)}</code></span>
              <span><strong>CWE:</strong> ${f.cwe_id}</span>
              <span><strong>OWASP:</strong> ${f.owasp_category}</span>
            </div>
            <div class="vuln-evidence">
              <strong>Evidence:</strong> ${escapeHtml(f.evidence)}
            </div>
          </div>
            <div class="vuln-actions" style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn-poc" style="flex: 1;" onclick="window.PoCViewer.open('${f.id}')">
              ⚡ View Exploit PoC & Raw Diff
            </button>
            <button class="cyber-btn secondary btn-jira-copy" style="padding: 6px 12px; font-size: 11px;" onclick="window.Vulnerabilities.copyJiraMarkdown('${f.id}')">
              📋 Copy Jira/GitHub Issue
            </button>
          </div>
        </div>
      `;
    }).join('');
  },

  copyJiraMarkdown(id) {
    const f = this.getFindingById(id);
    if (!f) return;

    const md = `## [${f.severity}] Security Vulnerability: ${f.title}

### Vulnerability Summary
- **Severity:** \`${f.severity}\` (CVSS v3.1: **${f.cvss_score}**)
- **CVSS Vector:** \`${f.cvss_vector || 'N/A'}\`
- **CWE Identifier:** \`${f.cwe_id}\`
- **OWASP Top 10 Category:** \`${f.owasp_category}\`
- **Endpoint Affected:** \`${f.method} ${f.endpoint}\`
${f.parameter ? `- **Vulnerable Parameter:** \`${f.parameter}\`` : ''}

### Verified Evidence & Proof
> ${f.evidence}

### Reproducible cURL Command
\`\`\`bash
${f.curl_command || 'N/A'}
\`\`\`

### Remediation Guidance
${f.remediation_summary || 'Apply contextual output encoding and parameterized queries.'}

---
*Reported by AegisAppSec Autonomous DAST Engine*`;

    navigator.clipboard.writeText(md).then(() => {
      alert(`Vulnerability Issue template for "${f.title}" copied to clipboard! Ready to paste into Jira, GitHub, or GitLab.`);
    }).catch(() => {
      alert("Failed to copy markdown to clipboard.");
    });
  },

  getFindingById(id) {
    return this.findings.find(f => f.id === id);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  window.Vulnerabilities.init();
});
