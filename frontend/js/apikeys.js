/**
 * AegisAppSec - CI/CD Integration & Automated Scoped API Keys Module
 * Version 2.6.0
 */

const SNIPPETS = {
  github: {
    filename: ".github/workflows/aegis-dast.yml",
    code: `name: AegisAppSec Autonomous DAST Security Gate

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  dast-security-gate:
    name: DAST Dynamic Vulnerability Assessment
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Trigger AegisAppSec Autonomous DAST Gate
        id: aegis_scan
        uses: aegisappsec/dast-action@v2
        with:
          api-key: \${{ secrets.AEGIS_API_KEY }}
          target-url: "http://127.0.0.1:8000/api/shop"
          fail-on: "CRITICAL,HIGH"
          timeout-seconds: 300
          export-sarif: "true"

      - name: Upload SARIF Security Findings
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aegis-results.sarif`
  },
  gitlab: {
    filename: ".gitlab-ci.yml",
    code: `stages:
  - test
  - security-gate
  - deploy

aegis_dast_gate:
  stage: security-gate
  image: curlimages/curl:latest
  script:
    - echo "[*] Triggering AegisAppSec Autonomous DAST Gate..."
    - |
      RESPONSE=$(curl -s -X POST "$AEGIS_BASE_URL/api/scanner/start" \\
        -H "X-Aegis-API-Key: $AEGIS_API_KEY" \\
        -H "Content-Type: application/json" \\
        -d "{\\"target_url\\": \\"$STAGING_URL\\"}")
      SCAN_ID=$(echo $RESPONSE | grep -o '"scan_id":[0-9]*' | cut -d: -f2)
      echo "[+] DAST Assessment initiated under Scan ID: $SCAN_ID"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'`
  },
  jenkins: {
    filename: "Jenkinsfile",
    code: `pipeline {
    agent any
    environment {
        AEGIS_KEY = credentials('aegis-ci-cd-token')
        TARGET_URL = 'http://127.0.0.1:8000/api/shop'
        AEGIS_HOST = 'http://127.0.0.1:8000'
    }
    stages {
        stage('Autonomous DAST Gate') {
            steps {
                sh '''
                    echo "[aegis-ci] Enforcing zero-vulnerability build gate..."
                    curl -f -X POST "\${AEGIS_HOST}/api/scanner/start" \\
                         -H "X-Aegis-API-Key: \${AEGIS_KEY}" \\
                         -H "Content-Type: application/json" \\
                         -d "{\\"target_url\\": \\"\${TARGET_URL}\\"}"
                '''
            }
        }
    }
}`
  },
  curl: {
    filename: "ci-gate.sh",
    code: `#!/usr/bin/env bash
set -euo pipefail

# AegisAppSec CI/CD Gate CLI Executor
API_KEY="\${AEGIS_API_KEY:-aegis_live_ab12...}"
TARGET_URL="http://127.0.0.1:8000/api/shop"

echo "[*] Triggering Autonomous DAST Scan on: $TARGET_URL"
SCAN_INIT=$(curl -s -X POST "http://127.0.0.1:8000/api/scanner/start" \\
  -H "X-Aegis-API-Key: $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d "{\\"target_url\\": \\"$TARGET_URL\\"}")

echo "[+] Scan initiated. Enforcing policy: FAIL_ON=CRITICAL,HIGH"`
  },
  python: {
    filename: "aegis_ci.py",
    code: `import os
import sys
import httpx

API_KEY = os.getenv("AEGIS_API_KEY", "aegis_live_...")
TARGET_URL = os.getenv("TARGET_URL", "http://127.0.0.1:8000/api/shop")

client = httpx.Client(base_url="http://127.0.0.1:8000", headers={"X-Aegis-API-Key": API_KEY})
resp = client.post("/api/scanner/start", json={"target_url": TARGET_URL})
if resp.status_code != 200:
    print(f"[FAIL] DAST trigger failed: {resp.text}")
    sys.exit(1)

data = resp.json()
print(f"[SUCCESS] DAST initiated. Scan ID: {data.get('scan_id')}")`
  }
};

const ApiKeysManager = {
  currentPlatform: "github",
  keysCache: [],
  webhooksCache: [],

  init() {
    this.bindEvents();
    this.loadKeys();
    this.loadWebhooks();
    this.switchPlatform("github");
  },

  showToast(msg) {
    const toast = document.getElementById("skToast");
    const msgEl = document.getElementById("skToastMsg");
    if (!toast || !msgEl) return;
    msgEl.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => {
      toast.classList.remove("show");
    }, 3500);
  },

  async loadKeys() {
    try {
      const res = await fetch("/api/keys");
      if (res.ok) {
        const keys = await res.json();
        this.keysCache = keys;
        this.renderKeysTable(keys);
        this.updateKeySelect(keys);
      }
    } catch (err) {
      console.warn("[ApiKeysManager] Could not load API keys:", err);
    }
  },

  renderKeysTable(keys) {
    const tbody = document.getElementById("apikeys-table-body");
    const hudCount = document.getElementById("hudActiveKeys");
    const tableCount = document.getElementById("tableKeysCount");

    if (hudCount) hudCount.textContent = keys.length;
    if (tableCount) tableCount.textContent = `${keys.length} ${keys.length === 1 ? 'KEY' : 'KEYS'}`;

    if (!tbody) return;

    if (!keys || !keys.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 28px;">
            No active API keys found. Generate a scoped credential above to integrate your CI/CD runner.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = keys.map(k => {
      const createdStr = k.created_at ? new Date(k.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : 'N/A';
      const usedStr = k.last_used_at ? new Date(k.last_used_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }) : 'Never used';
      const roleStr = (k.role || 'ci_cd_runner').toUpperCase();

      return `
        <tr>
          <td>
            <div style="display: flex; align-items: center; gap: 8px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan, #00f0ff)" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
              <strong style="color: #ffffff; font-size: 0.82rem;">${escapeHtml(k.name)}</strong>
            </div>
          </td>
          <td>
            <code style="color: var(--cyan, #00f0ff); font-size: 0.74rem; background: rgba(0,240,255,0.06); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(0,240,255,0.2);">
              ${escapeHtml(k.key_prefix)}••••••••
            </code>
          </td>
          <td>
            <span class="sk-role-badge">${roleStr}</span>
          </td>
          <td style="color: var(--text-muted); font-size: 0.74rem;">${createdStr}</td>
          <td style="color: var(--text-muted); font-size: 0.74rem;">${usedStr}</td>
          <td>
            <span class="sk-status-pill">
              <span class="sk-dot-pulse"></span> ACTIVE
            </span>
          </td>
          <td style="text-align: right;">
            <div style="display: inline-flex; align-items: center; gap: 6px;">
              <button class="sk-copy-btn btn-copy-prefix" data-prefix="${escapeHtml(k.key_prefix)}" title="Copy key prefix">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                PREFIX
              </button>
              <button class="sk-btn-revoke btn-revoke-key" data-id="${k.id}" data-name="${escapeHtml(k.name)}" title="Revoke key immediately">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                REVOKE
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    // Bind event listeners for dynamic rows
    tbody.querySelectorAll(".btn-copy-prefix").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const prefix = e.currentTarget.getAttribute("data-prefix");
        navigator.clipboard.writeText(prefix);
        this.showToast(`Copied prefix "${prefix}" to clipboard.`);
      });
    });

    tbody.querySelectorAll(".btn-revoke-key").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const id = e.currentTarget.getAttribute("data-id");
        const name = e.currentTarget.getAttribute("data-name");
        if (confirm(`Are you sure you want to revoke API key "${name}"? Any active CI/CD pipelines using this key will immediately fail.`)) {
          try {
            const delRes = await fetch(`/api/keys/${id}`, { method: "DELETE" });
            if (delRes.ok) {
              this.showToast(`API key "${name}" revoked successfully.`);
              await this.loadKeys();
            } else {
              alert("Failed to revoke key.");
            }
          } catch (err) {
            alert("Error revoking key: " + err.message);
          }
        }
      });
    });
  },

  updateKeySelect(keys) {
    const select = document.getElementById("simKeySelect");
    if (!select) return;

    if (!keys || !keys.length) {
      select.innerHTML = `<option value="aegis_live_">No active keys (Generate one above)</option>`;
      return;
    }

    select.innerHTML = keys.map(k => `
      <option value="${escapeHtml(k.key_prefix)}">${escapeHtml(k.name)} (${escapeHtml(k.key_prefix)}...)</option>
    `).join("");
  },

  async loadWebhooks() {
    try {
      const res = await fetch("/api/keys/webhooks/list");
      if (res.ok) {
        const whs = await res.json();
        this.webhooksCache = whs;
        this.renderWebhooksTable(whs);
      }
    } catch (err) {
      console.warn("[ApiKeysManager] Could not load webhooks:", err);
    }
  },

  renderWebhooksTable(whs) {
    const tbody = document.getElementById("webhooks-table-body");
    const hudCount = document.getElementById("hudActiveWebhooks");
    const tableCount = document.getElementById("tableWebhooksCount");

    if (hudCount) hudCount.textContent = whs.length;
    if (tableCount) tableCount.textContent = `${whs.length} ${whs.length === 1 ? 'DESTINATION' : 'DESTINATIONS'}`;

    if (!tbody) return;

    if (!whs || !whs.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">
            No webhooks configured. Register a Slack, Teams, or SIEM webhook destination above.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = whs.map(w => {
      const displayUrl = w.url.length > 42 ? `${w.url.substring(0, 42)}...` : w.url;
      const events = (w.event_types || "scan_completed,vulnerability_critical").split(",").map(e => e.trim());

      return `
        <tr>
          <td>
            <div style="display: flex; align-items: center; gap: 8px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/></svg>
              <strong style="color: #ffffff; font-size: 0.82rem;">${escapeHtml(w.name)}</strong>
            </div>
          </td>
          <td>
            <code style="color: var(--text-muted); font-size: 0.74rem;" title="${escapeHtml(w.url)}">
              ${escapeHtml(displayUrl)}
            </code>
          </td>
          <td>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
              ${events.map(ev => `<span class="sk-panel-badge" style="font-size: 0.60rem;">${escapeHtml(ev)}</span>`).join("")}
            </div>
          </td>
          <td>
            <span class="sk-status-pill">
              <span class="sk-dot-pulse"></span> ACTIVE
            </span>
          </td>
          <td style="text-align: right;">
            <div style="display: inline-flex; align-items: center; gap: 6px;">
              <button class="sk-copy-btn btn-test-webhook" data-url="${escapeHtml(w.url)}" data-name="${escapeHtml(w.name)}">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                TEST PING
              </button>
              <button class="sk-btn-revoke btn-delete-webhook" data-id="${w.id}" data-name="${escapeHtml(w.name)}">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                DELETE
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    // Bind webhook actions
    tbody.querySelectorAll(".btn-test-webhook").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const url = e.currentTarget.getAttribute("data-url");
        const name = e.currentTarget.getAttribute("data-name");
        const origText = btn.innerHTML;
        btn.innerHTML = `<span style="color: var(--cyan);">DISPATCHING...</span>`;
        btn.disabled = true;

        try {
          const res = await fetch("/api/keys/webhooks/test", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
          });
          const data = await res.json();
          this.showToast(`Webhook [${name}]: ${data.message || 'Test payload dispatched.'}`);
        } catch (err) {
          alert(`Test ping failed: ${err.message}`);
        } finally {
          btn.innerHTML = origText;
          btn.disabled = false;
        }
      });
    });

    tbody.querySelectorAll(".btn-delete-webhook").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const id = e.currentTarget.getAttribute("data-id");
        const name = e.currentTarget.getAttribute("data-name");
        if (confirm(`Delete webhook destination "${name}"?`)) {
          try {
            const res = await fetch(`/api/keys/webhooks/${id}`, { method: "DELETE" });
            if (res.ok) {
              this.showToast(`Webhook "${name}" deleted.`);
              await this.loadWebhooks();
            }
          } catch (err) {
            alert("Error deleting webhook: " + err.message);
          }
        }
      });
    });
  },

  switchPlatform(platform, clickedBtn) {
    this.currentPlatform = platform;
    const item = SNIPPETS[platform];
    if (!item) return;

    // Update buttons
    document.querySelectorAll(".sk-tab-btn").forEach(b => {
      b.classList.remove("active");
      if (b.getAttribute("data-platform") === platform) {
        b.classList.add("active");
      }
    });

    const fileEl = document.getElementById("codeFilename");
    const preEl = document.getElementById("codeSnippetPre");
    if (fileEl) fileEl.textContent = item.filename;
    if (preEl) preEl.textContent = item.code;
  },

  copyCurrentSnippet() {
    const item = SNIPPETS[this.currentPlatform];
    if (item && item.code) {
      navigator.clipboard.writeText(item.code);
      this.showToast(`Copied ${item.filename} snippet to clipboard.`);
    }
  },

  copyGeneratedKey() {
    const keyEl = document.getElementById("rawKeyDisplay");
    if (keyEl && keyEl.textContent) {
      navigator.clipboard.writeText(keyEl.textContent);
      this.showToast("API Key copied to clipboard! Store it safely in secrets.");
    }
  },

  async handleGenerateKey(e) {
    if (e) e.preventDefault();
    const nameInput = document.getElementById("newKeyName");
    const roleSelect = document.getElementById("newKeyRole");
    const btnSubmit = document.getElementById("btnSubmitGenerate");

    if (!nameInput || !nameInput.value.trim()) {
      alert("Please enter a key identifier or pipeline name.");
      return;
    }

    const name = nameInput.value.trim();
    const role = roleSelect ? roleSelect.value : "ci_cd_runner";

    if (btnSubmit) {
      btnSubmit.disabled = true;
      btnSubmit.textContent = "GENERATING...";
    }

    try {
      const res = await fetch("/api/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, role })
      });
      const data = await res.json();

      if (res.ok) {
        const revealBox = document.getElementById("keyRevealBox");
        const rawKeyDisplay = document.getElementById("rawKeyDisplay");
        if (revealBox && rawKeyDisplay) {
          rawKeyDisplay.textContent = data.api_key;
          revealBox.style.display = "block";
        }
        this.showToast(`Scoped API Key "${name}" generated!`);
        await this.loadKeys();
      } else {
        alert("Failed to generate key: " + (data.detail || JSON.stringify(data)));
      }
    } catch (err) {
      alert("Network error: " + err.message);
    } finally {
      if (btnSubmit) {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
          GENERATE SCOPED API KEY
        `;
      }
    }
  },

  async handleCreateWebhook(e) {
    if (e) e.preventDefault();
    const nameInput = document.getElementById("newWebhookName");
    const urlInput = document.getElementById("newWebhookUrl");
    const btnSubmit = document.getElementById("btnSubmitWebhook");

    if (!nameInput || !urlInput) return;
    const name = nameInput.value.trim();
    const url = urlInput.value.trim();

    if (!name || !url) {
      alert("Please fill in both name and webhook URL.");
      return;
    }

    const events = [];
    if (document.getElementById("evScanComplete")?.checked) events.push("scan_completed");
    if (document.getElementById("evCritVuln")?.checked) events.push("vulnerability_critical");
    if (document.getElementById("evHighVuln")?.checked) events.push("vulnerability_high");
    if (document.getElementById("evGateBlocked")?.checked) events.push("gate_blocked");

    if (btnSubmit) {
      btnSubmit.disabled = true;
      btnSubmit.textContent = "REGISTERING...";
    }

    try {
      const res = await fetch("/api/keys/webhooks/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          url,
          event_types: events.join(",") || "scan_completed,vulnerability_critical"
        })
      });
      if (res.ok) {
        closeWebhookModal();
        nameInput.value = "";
        urlInput.value = "";
        this.showToast(`Webhook "${name}" registered successfully.`);
        await this.loadWebhooks();
      } else {
        const errData = await res.json();
        alert("Failed to register webhook: " + (errData.detail || "Server error"));
      }
    } catch (err) {
      alert("Network error: " + err.message);
    } finally {
      if (btnSubmit) {
        btnSubmit.disabled = false;
        btnSubmit.textContent = "REGISTER DESTINATION";
      }
    }
  },

  async simulatePipelineRun() {
    const keySelect = document.getElementById("simKeySelect");
    const targetInput = document.getElementById("simTargetUrl");
    const branchInput = document.getElementById("simBranch");
    const termBody = document.getElementById("simTerminalBody");
    const termStatus = document.getElementById("simTerminalStatus");
    const btnRun = document.getElementById("btnSimulateRun");

    const keyPrefix = keySelect ? keySelect.value : "aegis_live_";
    const targetUrl = targetInput ? targetInput.value.trim() : "http://127.0.0.1:8000/api/shop";
    const branch = branchInput ? branchInput.value.trim() : "main";

    if (btnRun) {
      btnRun.disabled = true;
      btnRun.textContent = "RUNNING GATE...";
    }
    if (termStatus) {
      termStatus.innerHTML = `<span style="color: var(--cyan);">PIPELINE RUNNER: EXECUTING ASSESSMENT...</span>`;
    }
    if (termBody) {
      termBody.innerHTML = `
        <div class="sk-term-line info">[aegis-ci] Connecting to AegisAppSec Engine v2.6.0...</div>
        <div class="sk-term-line mute">[aegis-ci] Target: ${escapeHtml(targetUrl)} | Branch: ${escapeHtml(branch)}</div>
      `;
    }

    try {
      const res = await fetch("/api/keys/simulate-run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          key_prefix: keyPrefix,
          target_url: targetUrl,
          branch: branch
        })
      });

      if (res.ok) {
        const data = await res.json();
        const lines = data.build_terminal || [];

        // Stream terminal output line by line for an authentic console effect
        let index = 0;
        const interval = setInterval(() => {
          if (index < lines.length) {
            const line = lines[index];
            const div = document.createElement("div");
            div.className = "sk-term-line";
            if (line.includes("[SUCCESS]") || line.includes("SECURITY GATE PASSED")) {
              div.className += " success";
            } else if (line.includes("FAIL") || line.includes("CRITICAL")) {
              div.className += " warn";
            } else if (line.startsWith("[aegis-ci] -")) {
              div.className += " mute";
            } else {
              div.className += " info";
            }
            div.textContent = line;
            termBody.appendChild(div);
            termBody.scrollTop = termBody.scrollHeight;
            index++;
          } else {
            clearInterval(interval);
            if (termStatus) {
              termStatus.innerHTML = `<span style="color: #10b981;">PIPELINE STATUS: GATE PASSED (EXIT CODE 0)</span>`;
            }
            if (btnRun) {
              btnRun.disabled = false;
              btnRun.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                RUN GATE TEST
              `;
            }
            ApiKeysManager.showToast("DAST pipeline simulation completed successfully!");
            ApiKeysManager.loadKeys(); // refresh last used timestamp
          }
        }, 120);
      } else {
        if (termBody) {
          termBody.innerHTML += `<div class="sk-term-line warn">[FAIL] Simulator endpoint returned an error.</div>`;
        }
        if (btnRun) {
          btnRun.disabled = false;
          btnRun.textContent = "RUN GATE TEST";
        }
      }
    } catch (err) {
      if (termBody) {
        termBody.innerHTML += `<div class="sk-term-line warn">[ERROR] Simulation failed: ${escapeHtml(err.message)}</div>`;
      }
      if (btnRun) {
        btnRun.disabled = false;
        btnRun.textContent = "RUN GATE TEST";
      }
    }
  },

  bindEvents() {
    // Backward compatibility for legacy test hooks
    const btnCreateLegacy = document.getElementById("btn-create-apikey");
    if (btnCreateLegacy) {
      btnCreateLegacy.addEventListener("click", () => {
        document.getElementById("generateKeyCard")?.scrollIntoView({ behavior: 'smooth' });
      });
    }

    const btnModalOpen = document.getElementById("btnOpenWebhookModal");
    if (btnModalOpen) {
      btnModalOpen.addEventListener("click", () => openWebhookModal());
    }
  }
};

// Global helper wrappers for inline HTML calls
function handleGenerateKey(e) {
  ApiKeysManager.handleGenerateKey(e);
}

function handleCreateWebhook(e) {
  ApiKeysManager.handleCreateWebhook(e);
}

function switchPlatform(platform, btn) {
  ApiKeysManager.switchPlatform(platform, btn);
}

function copyCurrentSnippet() {
  ApiKeysManager.copyCurrentSnippet();
}

function copyGeneratedKey() {
  ApiKeysManager.copyGeneratedKey();
}

function openWebhookModal() {
  document.getElementById("webhookModal")?.classList.add("active");
}

function closeWebhookModal() {
  document.getElementById("webhookModal")?.classList.remove("active");
}

function simulatePipelineRun() {
  ApiKeysManager.simulatePipelineRun();
}

function filterKeysTable() {
  const query = document.getElementById("searchKeysInput")?.value.toLowerCase().trim() || "";
  const rows = document.querySelectorAll("#apikeys-table-body tr");
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query) ? "" : "none";
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Attach globally and auto-init
window.ApiKeysManager = ApiKeysManager;
document.addEventListener("DOMContentLoaded", () => ApiKeysManager.init());
