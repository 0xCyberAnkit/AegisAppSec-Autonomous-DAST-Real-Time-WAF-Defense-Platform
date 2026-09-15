/**
 * AegisAppSec - Target Governance & Domain Verification UI Module
 */

const TargetsManager = {
  activeTargets: [],

  init() {
    this.bindEvents();
    this.loadTargets();
  },

  async loadTargets() {
    try {
      const res = await fetch("/api/targets");
      if (res.ok) {
        this.activeTargets = await res.json();
        this.renderTargetsTable();
        this.populateScannerDropdown();
      }
    } catch (err) {
      console.warn("Could not load targets:", err);
    }
  },

  renderTargetsTable() {
    const tbody = document.getElementById("targets-table-body");
    if (!tbody) return;

    if (!this.activeTargets.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">
            No targets registered yet. Add a target domain to verify ownership and authorize scans.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = this.activeTargets.map(t => {
      const statusBadge = t.is_verified
        ? `<span class="badge-status verified">✓ VERIFIED</span>`
        : `<span class="badge-status pending">⏳ PENDING VERIFICATION</span>`;
      
      const scanBtn = t.is_verified
        ? `<button class="cyber-btn primary sm btn-quick-scan" data-url="${t.base_url}">⚡ Scan Now</button>`
        : `<button class="cyber-btn sm btn-open-verify-modal" data-id="${t.id}">Verify Domain</button>`;

      return `
        <tr>
          <td>
            <strong>${t.name}</strong>
            <div style="font-size: 11px; color: var(--text-muted); font-family: monospace;">${t.domain}</div>
          </td>
          <td style="font-family: monospace; font-size: 11px; color: var(--neon-cyan);">${t.base_url}</td>
          <td><span class="badge-pill">${t.verification_method.replace('_', ' ')}</span></td>
          <td>${statusBadge}</td>
          <td style="font-size: 11px; color: var(--text-muted);">${t.verified_at ? new Date(t.verified_at).toLocaleDateString() : "Unverified"}</td>
          <td>
            <div style="display: flex; gap: 6px; align-items: center;">
              ${scanBtn}
              <button class="cyber-btn sm btn-delete-target" data-id="${t.id}" title="Delete target" style="color: var(--neon-red);">✕</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    // Bind action buttons
    tbody.querySelectorAll(".btn-open-verify-modal").forEach(b => {
      b.addEventListener("click", (e) => {
        const id = parseInt(e.currentTarget.getAttribute("data-id"));
        this.openVerificationWizard(id);
      });
    });

    tbody.querySelectorAll(".btn-quick-scan").forEach(b => {
      b.addEventListener("click", (e) => {
        const url = e.currentTarget.getAttribute("data-url");
        const scanInput = document.getElementById("scan-target-url");
        if (scanInput) scanInput.value = url;
        // Switch to scanner tab
        document.querySelector('.tab-btn[data-tab="scanner"]')?.click();
      });
    });

    tbody.querySelectorAll(".btn-delete-target").forEach(b => {
      b.addEventListener("click", async (e) => {
        const id = parseInt(e.currentTarget.getAttribute("data-id"));
        if (confirm("Are you sure you want to delete this target?")) {
          await fetch(`/api/targets/${id}`, { method: "DELETE" });
          await this.loadTargets();
        }
      });
    });
  },

  populateScannerDropdown() {
    const dropdown = document.getElementById("verified-targets-dropdown");
    if (!dropdown) return;

    const verified = this.activeTargets.filter(t => t.is_verified);
    dropdown.innerHTML = verified.map(t => `<option value="${t.base_url}">${t.name} (${t.domain})</option>`).join("");
    
    dropdown.addEventListener("change", (e) => {
      const scanInput = document.getElementById("scan-target-url");
      if (scanInput) scanInput.value = e.target.value;
    });
  },

  openVerificationWizard(targetId) {
    const target = this.activeTargets.find(t => t.id === targetId);
    if (!target) return;

    const modal = document.getElementById("verification-modal");
    if (!modal) return;

    document.getElementById("verify-target-name").textContent = target.name;
    document.getElementById("verify-target-domain").textContent = target.domain;
    document.getElementById("verify-token-val").textContent = target.verification_token;

    const instructionsEl = document.getElementById("verify-instructions-body");
    if (target.verification_method === "HTTP_WELL_KNOWN") {
      instructionsEl.innerHTML = `
        <p>1. Create a public plain text file on your web server at:</p>
        <div class="code-box">http://${target.domain}/.well-known/aegis-verification.txt</div>
        <p>2. Paste your unique token into this file:</p>
        <div class="code-box" style="color: var(--neon-green);">${target.verification_token}</div>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">
          Once deployed, click the button below to confirm live reachability and ownership.
        </p>
      `;
    } else if (target.verification_method === "HTML_META") {
      instructionsEl.innerHTML = `
        <p>1. Add this meta tag inside the <code>&lt;head&gt;</code> element of your homepage:</p>
        <div class="code-box">&lt;meta name="aegis-verification" content="${target.verification_token}"&gt;</div>
      `;
    } else {
      instructionsEl.innerHTML = `
        <p>1. Add a DNS TXT record through your domain registrar:</p>
        <div class="code-box">Host: @<br>Value: aegis-verification=${target.verification_token}</div>
      `;
    }

    const checkBtn = document.getElementById("btn-run-verify-check");
    const statusMsg = document.getElementById("verify-check-status");
    statusMsg.textContent = "";

    checkBtn.onclick = async () => {
      statusMsg.textContent = "Checking domain ownership in real-time...";
      statusMsg.style.color = "var(--neon-cyan)";
      try {
        const res = await fetch(`/api/targets/${target.id}/verify`, { method: "POST" });
        const data = await res.json();
        if (data.is_verified) {
          statusMsg.textContent = `✓ ${data.message}`;
          statusMsg.style.color = "var(--neon-green)";
          setTimeout(() => {
            modal.classList.remove("active");
            this.loadTargets();
          }, 1500);
        } else {
          statusMsg.textContent = `❌ ${data.message}`;
          statusMsg.style.color = "var(--neon-red)";
        }
      } catch (err) {
        statusMsg.textContent = `❌ Verification error: ${err.message}`;
        statusMsg.style.color = "var(--neon-red)";
      }
    };

    modal.classList.add("active");
  },

  bindEvents() {
    document.getElementById("btn-register-target")?.addEventListener("click", () => {
      document.getElementById("register-target-modal")?.classList.add("active");
    });

    document.getElementById("close-target-modal-btn")?.addEventListener("click", () => {
      document.getElementById("register-target-modal")?.classList.remove("active");
    });

    document.getElementById("close-verify-modal-btn")?.addEventListener("click", () => {
      document.getElementById("verification-modal")?.classList.remove("active");
    });

    // Form submit
    document.getElementById("new-target-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = document.getElementById("target-name").value;
      const domain = document.getElementById("target-domain").value;
      const baseUrl = document.getElementById("target-base-url").value;
      const method = document.getElementById("target-verify-method").value;
      const statusEl = document.getElementById("target-reg-status");

      statusEl.textContent = "Registering target domain...";
      try {
        const res = await fetch("/api/targets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, domain, base_url: baseUrl, verification_method: method })
        });
        const data = await res.json();
        if (res.ok) {
          statusEl.textContent = "✓ Target registered!";
          statusEl.style.color = "var(--neon-green)";
          setTimeout(() => {
            document.getElementById("register-target-modal")?.classList.remove("active");
            this.loadTargets();
            if (!data.target.is_verified) {
              this.openVerificationWizard(data.target.id);
            }
          }, 1000);
        } else {
          statusEl.textContent = `❌ ${data.detail || "Registration failed"}`;
          statusEl.style.color = "var(--neon-red)";
        }
      } catch (err) {
        statusEl.textContent = `❌ ${err.message}`;
        statusEl.style.color = "var(--neon-red)";
      }
    });
  }
};

document.addEventListener("DOMContentLoaded", () => TargetsManager.init());
