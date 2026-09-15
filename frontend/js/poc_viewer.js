/**
 * Proof-of-Concept (PoC) Exploit Viewer & HTTP Transaction Inspector
 */

window.PoCViewer = {
  open(findingId) {
    const finding = window.Vulnerabilities.getFindingById(findingId);
    if (!finding) return;

    const modal = document.getElementById('poc-modal');
    if (!modal) return;

    document.getElementById('poc-modal-title').textContent = finding.title;
    document.getElementById('poc-modal-sev').textContent = finding.severity;
    document.getElementById('poc-modal-sev').className = `severity-pill sev-${finding.severity.toLowerCase()}`;
    document.getElementById('poc-modal-cvss').textContent = `CVSS ${finding.cvss_score} (${finding.cvss_vector})`;
    document.getElementById('poc-modal-endpoint').textContent = `${finding.method} ${finding.endpoint}`;
    document.getElementById('poc-modal-payload').textContent = finding.payload_used;
    document.getElementById('poc-modal-curl').textContent = finding.curl_command;
    document.getElementById('poc-modal-req').textContent = finding.request_raw;
    document.getElementById('poc-modal-resp').textContent = finding.response_raw;
    document.getElementById('poc-modal-remediation').textContent = finding.remediation_summary;

    const jumpBtn = document.getElementById('btn-jump-remediation');
    if (jumpBtn) {
      jumpBtn.onclick = () => {
        this.close();
        App.switchTab('remediation');
        if (window.Remediation) {
          window.Remediation.loadGuidance(finding.cwe_id);
        }
      };
    }

    modal.classList.add('active');
  },

  close() {
    const modal = document.getElementById('poc-modal');
    if (modal) modal.classList.remove('active');
  },

  copyCurl() {
    const curlText = document.getElementById('poc-modal-curl').textContent;
    navigator.clipboard.writeText(curlText).then(() => {
      const btn = document.getElementById('btn-copy-curl');
      if (btn) {
        btn.textContent = '✓ Copied to Clipboard!';
        setTimeout(() => { btn.textContent = '📋 Copy cURL Command'; }, 2000);
      }
    });
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const closeBtn = document.getElementById('btn-close-poc-modal');
  if (closeBtn) closeBtn.addEventListener('click', () => window.PoCViewer.close());

  const overlay = document.getElementById('poc-modal');
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) window.PoCViewer.close();
    });
  }

  const copyBtn = document.getElementById('btn-copy-curl');
  if (copyBtn) copyBtn.addEventListener('click', () => window.PoCViewer.copyCurl());
});
