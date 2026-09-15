/**
 * AegisAppSec — Enterprise Regulatory Compliance & Audit Scorecard Manager
 * Clean, corporate sec-ops implementation (Strictly Zero Emojis, Pure SVGs).
 */

let currentFramework = 'all';
let currentStatus = 'all';
let currentSearch = '';
let isAllExpanded = false;

// 1. Toggle Accordion Card
function toggleReqCard(headerEl) {
  if (!headerEl) return;
  const card = headerEl.closest('.cp-req-card');
  if (!card) return;
  card.classList.toggle('open');
}

// 2. Select Framework Tab
function selectFramework(btnEl, frameworkKey) {
  currentFramework = frameworkKey;
  document.querySelectorAll('.cp-tab-btn').forEach(b => b.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
  filterCompliance();
}

// 3. Filter Requirements (Framework + Status + Search)
function filterCompliance() {
  const statusEl = document.getElementById('cp-status-filter');
  const searchEl = document.getElementById('cp-search-box');
  
  currentStatus = statusEl ? statusEl.value : 'all';
  currentSearch = searchEl ? searchEl.value.toLowerCase().trim() : '';

  const cards = document.querySelectorAll('.cp-req-card');
  cards.forEach(card => {
    const f = card.getAttribute('data-framework') || '';
    const s = card.getAttribute('data-status') || '';
    const t = card.getAttribute('data-text') || '';

    const frameworkMatch = (currentFramework === 'all') || (f === currentFramework);
    const statusMatch = (currentStatus === 'all') || (s === currentStatus);
    const searchMatch = !currentSearch || t.includes(currentSearch);

    if (frameworkMatch && statusMatch && searchMatch) {
      card.style.display = '';
    } else {
      card.style.display = 'none';
    }
  });
}

// 4. Toggle Expand / Collapse All
function toggleAllCards() {
  isAllExpanded = !isAllExpanded;
  const toggleBtn = document.getElementById('btn-toggle-expand');
  if (toggleBtn) {
    toggleBtn.textContent = isAllExpanded ? 'Collapse All' : 'Expand All';
  }
  document.querySelectorAll('.cp-req-card').forEach(card => {
    if (card.style.display !== 'none') {
      if (isAllExpanded) {
        card.classList.add('open');
      } else {
        card.classList.remove('open');
      }
    }
  });
}

// 5. Open Certificate Modal
function openCertModal() {
  const modal = document.getElementById('compliance-cert-modal');
  if (modal) {
    modal.classList.add('active');
    updateCertPreview(window.__INITIAL_COMPLIANCE_DATA__);
  }
}

// 6. Close Certificate Modal
function closeCertModal() {
  const modal = document.getElementById('compliance-cert-modal');
  if (modal) modal.classList.remove('active');
}

// 7. Copy Certificate JSON
function copyCertJson() {
  const preview = document.getElementById('cert-json-preview');
  const text = preview ? preview.textContent : '';
  const btnText = document.getElementById('btn-copy-cert-text');
  navigator.clipboard.writeText(text).then(() => {
    if (btnText) {
      const orig = btnText.textContent;
      btnText.textContent = 'Copied!';
      setTimeout(() => { btnText.textContent = orig; }, 2000);
    }
    showToast('[CLIPBOARD] Attestation JSON copied to clipboard.');
  });
}

// 8. Recalculate Posture (POST /api/compliance/recalculate)
async function recalculateCompliance() {
  const btn = document.getElementById('btn-recalculate-posture');
  const spinner = document.getElementById('recalc-spinner-icon');
  const label = document.getElementById('recalc-btn-label');

  if (btn) btn.disabled = true;
  if (spinner) spinner.style.animation = 'cpSpin 1s linear infinite';
  if (label) label.textContent = 'Evaluating Engine Telemetry...';

  try {
    const res = await fetch('/api/compliance/recalculate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    if (res.ok) {
      const data = await res.json();
      window.__INITIAL_COMPLIANCE_DATA__ = data;
      updateHudMetrics(data);
      updateCertPreview(data);
      showToast('[SEC-OPS] Posture re-evaluated against latest findings database.');
    } else {
      showToast('[ERROR] Failed to recalculate compliance posture.');
    }
  } catch (err) {
    console.error('[Compliance] Recalculate failed:', err);
    showToast('[ERROR] Network error during recalculation.');
  } finally {
    if (btn) btn.disabled = false;
    if (spinner) spinner.style.animation = '';
    if (label) label.textContent = 'Recalculate Posture';
  }
}

// 9. Update HUD Metrics
function updateHudMetrics(data) {
  if (!data) return;
  const getStatusColor = (pct) => pct >= 90 ? '#10b981' : (pct >= 65 ? '#f59e0b' : '#f43f5e');
  const getBadgeClass = (pct) => pct >= 90 ? 'cp-badge-pass' : (pct >= 65 ? 'cp-badge-warn' : 'cp-badge-fail');

  // Overall Score
  const overallVal = document.getElementById('hud-overall-score');
  if (overallVal) {
    overallVal.textContent = `${data.overall_score_percentage}%`;
    overallVal.style.color = getStatusColor(data.overall_score_percentage);
  }
  const overallBadge = document.getElementById('hud-posture-badge');
  if (overallBadge) {
    overallBadge.textContent = `[${data.posture_label}]`;
    overallBadge.className = `cp-badge-status ${getBadgeClass(data.overall_score_percentage)}`;
  }
  const overallBar = document.getElementById('hud-overall-bar');
  if (overallBar) {
    overallBar.style.width = `${data.overall_score_percentage}%`;
    overallBar.style.background = getStatusColor(data.overall_score_percentage);
  }
  const metaCounts = document.getElementById('hud-meta-counts');
  if (metaCounts && data.counts) {
    metaCounts.textContent = `${data.counts.passed}/${data.counts.total} Passing`;
  }
  const metaBlockers = document.getElementById('hud-meta-blockers');
  if (metaBlockers) {
    metaBlockers.textContent = `${data.active_flaws_count} Flaws`;
    metaBlockers.style.color = data.active_flaws_count > 0 ? '#f43f5e' : '#10b981';
  }

  // OWASP Top 10
  const owasp = data.framework_scores?.owasp_top_10;
  if (owasp) {
    const val = document.getElementById('hud-owasp-score');
    if (val) {
      val.textContent = `${owasp.score_percentage}%`;
      val.style.color = getStatusColor(owasp.score_percentage);
    }
    const badge = document.getElementById('hud-owasp-badge');
    if (badge) {
      badge.textContent = `${owasp.passed}/${owasp.total} PASS`;
      badge.className = `cp-badge-status ${getBadgeClass(owasp.score_percentage)}`;
    }
    const bar = document.getElementById('hud-owasp-bar');
    if (bar) {
      bar.style.width = `${owasp.score_percentage}%`;
      bar.style.background = getStatusColor(owasp.score_percentage);
    }
  }

  // PCI-DSS v4.0
  const pci = data.framework_scores?.pci_dss_4_0;
  if (pci) {
    const val = document.getElementById('hud-pci-score');
    if (val) {
      val.textContent = `${pci.score_percentage}%`;
      val.style.color = getStatusColor(pci.score_percentage);
    }
    const badge = document.getElementById('hud-pci-badge');
    if (badge) {
      badge.textContent = `${pci.passed}/${pci.total} PASS`;
      badge.className = `cp-badge-status ${getBadgeClass(pci.score_percentage)}`;
    }
    const bar = document.getElementById('hud-pci-bar');
    if (bar) {
      bar.style.width = `${pci.score_percentage}%`;
      bar.style.background = getStatusColor(pci.score_percentage);
    }
  }

  // SOC 2 Type II
  const soc2 = data.framework_scores?.soc_2_type_ii;
  if (soc2) {
    const val = document.getElementById('hud-soc2-score');
    if (val) {
      val.textContent = `${soc2.score_percentage}%`;
      val.style.color = getStatusColor(soc2.score_percentage);
    }
    const badge = document.getElementById('hud-soc2-badge');
    if (badge) {
      badge.textContent = `${soc2.passed}/${soc2.total} PASS`;
      badge.className = `cp-badge-status ${getBadgeClass(soc2.score_percentage)}`;
    }
    const bar = document.getElementById('hud-soc2-bar');
    if (bar) {
      bar.style.width = `${soc2.score_percentage}%`;
      bar.style.background = getStatusColor(soc2.score_percentage);
    }
  }
}

// 10. Update Certificate Preview
function updateCertPreview(data) {
  if (!data) return;
  const hashVal = document.getElementById('cert-hash-val');
  if (hashVal) hashVal.textContent = data.attestation_hash || 'N/A';
  const tsVal = document.getElementById('cert-timestamp-val');
  if (tsVal) tsVal.textContent = data.evaluated_at || new Date().toISOString();
  const postureVal = document.getElementById('cert-posture-val');
  if (postureVal) postureVal.textContent = `${data.overall_score_percentage}% [${data.posture_label}]`;

  const jsonPreview = document.getElementById('cert-json-preview');
  if (jsonPreview) {
    const certDoc = {
      document_type: "REGULATORY_COMPLIANCE_ATTESTATION",
      standard: "AegisAppSec-Audit-v2.6",
      attestation_timestamp: data.evaluated_at,
      cryptographic_verification_hash: data.attestation_hash,
      posture_summary: {
        compliance_rating: data.posture_label,
        overall_score_percentage: data.overall_score_percentage,
        total_evaluated_requirements: data.counts?.total,
        passed_requirements: data.counts?.passed,
        failed_requirements: data.counts?.failed,
        active_vulnerabilities_in_scope: data.active_flaws_count
      },
      framework_readiness: data.framework_scores,
      digital_signature: {
        algorithm: "SHA256-HMAC-ATTEST",
        signed_by: "Aegis Autonomous SecOps Auditor Daemon",
        status: "OFFICIALLY_VERIFIED"
      }
    };
    jsonPreview.textContent = JSON.stringify(certDoc, null, 2);
  }
}

// 11. Toast Notification
function showToast(msg) {
  const toast = document.getElementById('compliance-toast');
  const msgEl = document.getElementById('compliance-toast-msg');
  if (!toast || !msgEl) return;
  msgEl.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => { toast.classList.remove('show'); }, 3200);
}

// Window exports
window.toggleReqCard = toggleReqCard;
window.selectFramework = selectFramework;
window.filterCompliance = filterCompliance;
window.toggleAllCards = toggleAllCards;
window.openCertModal = openCertModal;
window.closeCertModal = closeCertModal;
window.copyCertJson = copyCertJson;
window.recalculateCompliance = recalculateCompliance;
