// MazAPI Scanner — Popup Script v2.2

let _showAllEndpoints = false;
let _lastResults      = [];
let _lastScore        = 100;
let _lastTarget       = "";
let _lastChains       = [];   // correlated attack chains from the last scan
let _livePaused       = false;
let _liveTimer        = null;

// ── Theme system ───────────────────────────────────────────────────────────────
(function initTheme() {
  chrome.storage.local.get('mazapiTheme', res => {
    const theme = res?.mazapiTheme || 'dark';
    applyTheme(theme);
  });
})();

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon  = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  if (theme === 'light') {
    if (icon)  icon.textContent  = '🌙';
    if (label) label.textContent = 'Dark';
  } else {
    if (icon)  icon.textContent  = '☀️';
    if (label) label.textContent = 'Light';
  }
}

document.getElementById('btn-theme').addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  chrome.storage.local.set({ mazapiTheme: next });
});

// ── Tab navigation ────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".pane").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    const pane = document.getElementById("pane-" + tab.dataset.tab);
    if (pane) pane.classList.add("active");
    try {
      if (tab.dataset.tab === "history")  renderHistory();
      if (tab.dataset.tab === "settings") loadSettings();
      if (tab.dataset.tab === "keys")     renderKeys();
      if (tab.dataset.tab === "auth")     renderAuth();
      if (tab.dataset.tab === "replay")   initReplay();
      if (tab.dataset.tab === "openapi")  initOAS();
      if (tab.dataset.tab === "threats")  renderThreats();
      if (tab.dataset.tab === "live")     { renderLive(); startLivePolling(); }
      else stopLivePolling();
    } catch (err) {
      console.error("Error rendering pane for tab:", tab.dataset.tab, err);
    }
  });
});

// ── JWT decoder — shows algorithm, expiry, and key claims inline ──────────────
function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return '';
    const pad  = s => s + '='.repeat((4 - s.length % 4) % 4);
    const hdr  = JSON.parse(atob(pad(parts[0].replace(/-/g, '+').replace(/_/g, '/'))));
    const pay  = JSON.parse(atob(pad(parts[1].replace(/-/g, '+').replace(/_/g, '/'))));
    const alg  = hdr.alg || '?';
    const now  = Math.floor(Date.now() / 1000);
    const exp  = pay.exp;
    const iat  = pay.iat;
    const sub  = pay.sub || pay.user_id || pay.userId || pay.email || '';
    const iss  = pay.iss || '';

    const ALG_COLOR = alg === 'none' ? '#f85149' : alg.startsWith('HS') ? '#e3b341' : '#3fb950';
    const algWarn   = alg === 'none' ? ' ⚠ CRITICAL: alg=none bypass risk!' : alg.startsWith('HS') ? ' (symmetric)' : '';
    let expHtml = '';
    if (exp) {
      const diff = exp - now;
      if (diff < 0) {
        expHtml = `<span style="color:#f85149">&#10007; Expired ${Math.abs(Math.round(diff/60))} min ago</span>`;
      } else if (diff < 300) {
        expHtml = `<span style="color:#e3b341">&#9888; Expires in ${Math.round(diff/60)} min</span>`;
      } else {
        const d = new Date(exp * 1000);
        expHtml = `<span style="color:#3fb950">&#10003; Valid until ${d.toLocaleTimeString()}</span>`;
      }
    } else {
      expHtml = '<span style="color:#f85149">&#9888; No expiry (exp claim missing)</span>';
    }

    const rows = [
      `<tr><td style="color:#8b949e;padding-right:8px">alg</td><td style="color:${ALG_COLOR};font-weight:700">${alg}${algWarn}</td></tr>`,
      expHtml ? `<tr><td style="color:#8b949e">exp</td><td>${expHtml}</td></tr>` : '',
      sub ? `<tr><td style="color:#8b949e">sub</td><td style="color:#c9d1d9">${String(sub).slice(0, 40)}</td></tr>` : '',
      iss ? `<tr><td style="color:#8b949e">iss</td><td style="color:#c9d1d9">${String(iss).slice(0, 40)}</td></tr>` : '',
    ].filter(Boolean).join('');

    return `<div style="background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:6px 8px;margin-top:4px;font-size:.75em">
      <div style="color:#58a6ff;font-weight:600;margin-bottom:4px">&#128273; JWT Decoded</div>
      <table style="border-collapse:collapse;width:100%">${rows}</table>
    </div>`;
  } catch (_) { return ''; }
}

// ── Active tab helper ─────────────────────────────────────────────────────────
let _currentTabOrigin = "";

function getActiveTabOrigin(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const activeTabUrl = tabs?.[0]?.url || "";
    let origin = "";
    try {
      const u = new URL(activeTabUrl);
      if (u.protocol === "https:" || u.protocol === "http:") {
        origin = `${u.protocol}//${u.host}`;
      }
    } catch {}
    callback(origin, activeTabUrl);
  });
}

// ── Load session from background ──────────────────────────────────────────────
function loadSession() {
  getActiveTabOrigin((origin, activeTabUrl) => {
    chrome.runtime.sendMessage({ type: "GET_SESSION", origin, url: activeTabUrl }, session => {
      if (!session) return;
      renderDiscovered(session, origin || activeTabUrl);
      // Update live threat banner
      updateThreatBanner(session);
      // Update Keys tab badge count without switching to it
      const keyCount = (session.hardcoded_keys || []).length;
      const countEl  = document.getElementById("keys-count");
      if (countEl) {
        countEl.textContent = keyCount;
        countEl.className   = "keys-badge" + (keyCount ? " keys-badge-alert" : "");
      }
    });
  });
}

// Check for context-menu triggered URL
function checkContextUrl() {
  chrome.runtime.sendMessage({ type: "GET_CONTEXT_URL" }, url => {
    if (url) {
      document.getElementById("scan-target").value = url;
      document.querySelector(".tab[data-tab='scan']").click();
    }
  });
}

function renderDiscovered(session, activeTabUrl = "") {
  let scanTargetOrigin = "";
  try {
    const u = new URL(activeTabUrl);
    if (u.protocol === "https:" || u.protocol === "http:") scanTargetOrigin = `${u.protocol}//${u.host}`;
  } catch {}
  if (!scanTargetOrigin) scanTargetOrigin = session.baseUrl || "";

  document.getElementById("base-url").textContent = scanTargetOrigin || "—";

  // Tokens
  const tokenArea = document.getElementById("token-area");
  if (session.tokens?.length) {
    const tok   = session.tokens[0];
    const short = tok.length > 60 ? tok.slice(0, 60) + "…" : tok;
    document.getElementById("scan-token").value = tok;
    const jwtInfo = decodeJWT(tok);
    tokenArea.innerHTML = `<div class="token-label">Bearer Token (captured)</div><div class="token-box" title="${tok}">${short}</div>${jwtInfo}`;
  } else if (session.apiKeys?.length) {
    const k = session.apiKeys[0];
    tokenArea.innerHTML = `<div class="token-label">${k.header}</div><div class="token-box">${k.value}</div>`;
  } else {
    tokenArea.innerHTML = `<div style="color:#8b949e;font-size:.82em;margin-bottom:8px">No token captured — log in to capture auth credentials.</div>`;
  }

  // Key warnings
  const warnings = document.getElementById("key-warnings");
  if (session.hardcoded_keys?.length) {
    warnings.innerHTML = session.hardcoded_keys.slice(0, 2).map(k =>
      `<div class="key-warning">&#9888; Hardcoded credential in page JS: <code>${k.value.slice(0, 24)}…</code></div>`
    ).join("");
  }

  // Endpoints
  const eps     = Object.entries(session.endpoints || {});
  const list    = document.getElementById("endpoints-list");
  const countEl = document.getElementById("ep-count");
  countEl.textContent = eps.length;

  const targetInput = document.getElementById("scan-target");
  if (!targetInput.value && scanTargetOrigin) targetInput.value = scanTargetOrigin;

  if (!eps.length) {
    list.innerHTML = '<div class="empty">Browse the target website to capture API calls.</div>';
    return;
  }

  // Auto-fill auth endpoint (exclude telemetry/fingerprint paths)
  const NON_CRED  = /\/(browserinfo|metrics|analytics|telemetry|track|beacon|pixel|log|event|health|ping|status|info)\b/i;
  const authEpInput = document.getElementById("scan-auth-ep");
  if (!authEpInput.value) {
    const m = eps.find(([p]) => /\/(auth|login|signin|sign-in|token|oauth|session|credential|password)\b/i.test(p) && !NON_CRED.test(p));
    if (m) authEpInput.value = m[0].replace(/\{id\}/g, "1");
  }

  // Auto-fill protected path
  const protectedInput = document.getElementById("scan-protected");
  if (!protectedInput.value) {
    const m = eps.find(([, d]) => d.authRequired);
    if (m) protectedInput.value = m[0].replace(/\{id\}/g, "1");
  }

  // Render endpoint list with show/hide toggle
  const API_DOC_RE = /\/(swagger(?:-ui)?|api[-_]?docs?|openapi|redoc|graphql|playground|voyager|altair|graphiql)\b/i;
  const visibleEps = _showAllEndpoints ? eps : eps.slice(0, 20);
  const epRows = visibleEps.map(([path, data]) => {
    const methods  = (data.methods || []).map(m => `<span class="badge badge-${m.toLowerCase()}">${m}</span>`).join("");
    const authNote = data.authRequired ? '<span style="color:#e3b341;font-size:.77em"> &#128274; auth required</span>' : "";
    const docWarn  = API_DOC_RE.test(path)
      ? '<span style="color:#f85149;font-size:.77em" title="API documentation endpoint exposed — disable in production"> &#9888; docs exposed</span>'
      : "";
    return `<div class="endpoint-item"><div class="endpoint-path">${path}</div><div class="endpoint-meta">${methods}${authNote}${docWarn}</div></div>`;
  }).join("");

  const toggleBtn = eps.length > 20
    ? `<button id="btn-toggle-eps" class="export-btn" style="width:100%;margin-top:6px">${_showAllEndpoints ? "Show less" : `Show all ${eps.length} endpoints`}</button>`
    : "";

  list.innerHTML = epRows + toggleBtn;
  if (eps.length > 20) {
    document.getElementById("btn-toggle-eps").addEventListener("click", () => {
      _showAllEndpoints = !_showAllEndpoints;
      renderDiscovered(session, activeTabUrl);
    });
  }
}

// ── Clear session ─────────────────────────────────────────────────────────────
document.getElementById("btn-clear").addEventListener("click", () => {
  _showAllEndpoints = false;
  getActiveTabOrigin(origin => {
    chrome.runtime.sendMessage({ type: "CLEAR_SESSION", origin }, () => {
      document.getElementById("base-url").textContent = "—";
      document.getElementById("token-area").innerHTML = "";
      document.getElementById("endpoints-list").innerHTML = '<div class="empty">Session cleared.</div>';
      document.getElementById("ep-count").textContent = "0";
      document.getElementById("results-list").innerHTML = '<div class="empty">Run a scan to see results.</div>';
      document.getElementById("score-area").innerHTML = "";
      document.getElementById("export-bar").style.display = "none";
    });
  });
});

// ── Postman / OpenAPI export from Capture tab ─────────────────────────────────
document.getElementById("btn-postman").addEventListener("click", () => {
  const target = document.getElementById("scan-target").value.trim() || _lastTarget;
  if (!target) { alert("Browse a site first to capture endpoints."); return; }
  chrome.runtime.sendMessage({ type: "GENERATE_POSTMAN", target }, col => {
    downloadJSON(col, `mazapi-postman-${Date.now()}.json`);
  });
});

document.getElementById("btn-openapi").addEventListener("click", () => {
  const target = document.getElementById("scan-target").value.trim() || _lastTarget;
  if (!target) { alert("Browse a site first to capture endpoints."); return; }
  chrome.runtime.sendMessage({ type: "GENERATE_OPENAPI", target }, spec => {
    downloadJSON(spec, `mazapi-openapi-${Date.now()}.json`);
  });
});

// ── Run Scan ──────────────────────────────────────────────────────────────────
document.getElementById("btn-detect-port")?.addEventListener("click", () => {
  const statusEl = document.getElementById("port-detect-status");
  const inputEl  = document.getElementById("scan-monitor-url");
  if (statusEl) statusEl.textContent = "Detecting active MazAPI ports...";
  chrome.runtime.sendMessage({ type: "DETECT_PORT" }, resp => {
    if (resp?.ok) {
      if (inputEl) inputEl.value = resp.url;
      if (statusEl) statusEl.textContent = "✓ " + resp.message;
    } else {
      if (statusEl) statusEl.textContent = "⚠ " + (resp?.message || "No dashboard found");
    }
  });
});

function checkActiveScanStatus() {
  getActiveTabOrigin(origin => {
    chrome.runtime.sendMessage({ type: "GET_SCAN_STATUS", origin }, scan => {
      if (!scan || scan.status === "idle") return;
      const btn    = document.getElementById("btn-scan");
      const status = document.getElementById("scan-status");
      if (scan.status === "running") {
        if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Scanning in Background...'; }
        if (status) status.textContent = `Active scan running for ${scan.target} (safe to close/minimize)...`;
      } else if (scan.status === "done" && scan.results?.length) {
        if (btn) { btn.disabled = false; btn.innerHTML = "&#9654; Run Full Scan"; }
        if (status) status.textContent = "";
        _lastResults = scan.results;
        _lastScore   = scan.score;
        _lastTarget  = scan.target;
        _lastChains  = scan.chains || [];
        renderResults(scan.results, scan.score, scan.target);
      }
    });
  });
}

document.getElementById("btn-scan").addEventListener("click", () => {
  const target     = document.getElementById("scan-target").value.trim();
  const token      = document.getElementById("scan-token").value.trim();
  const authEp     = document.getElementById("scan-auth-ep").value.trim();
  const protected_ = document.getElementById("scan-protected").value.trim();
  const monitorUrl = document.getElementById("scan-monitor-url")?.value.trim() || "http://localhost:9000";

  if (!target) { alert("Enter a target URL first."); return; }

  _lastTarget = target;
  const btn    = document.getElementById("btn-scan");
  const status = document.getElementById("scan-status");
  btn.disabled    = true;
  btn.innerHTML   = '<span class="spinner"></span> Scanning in Background…';
  status.textContent = "Scan running in background (safe to close or minimize extension)...";

  chrome.runtime.sendMessage({
    type: "RUN_SCAN",
    target,
    token: token || null,
    monitorUrl,
    options: { authEndpoint: authEp || null, protectedPath: protected_ || null },
  }, resp => {
    btn.disabled    = false;
    btn.innerHTML   = "&#9654; Run Full Scan";
    if (!resp?.ok) {
      status.textContent = "Error: " + (resp?.error || "no response");
      return;
    }
    status.textContent = "";
    _lastResults = resp.results;
    _lastScore   = resp.score ?? Math.round((1 - resp.results.filter(r => r.vulnerable).length / resp.results.length) * 100);
    _lastChains  = resp.chains || [];
    renderResults(resp.results, _lastScore, target);
    document.querySelector(".tab[data-tab='results']").click();
  });
});

checkActiveScanStatus();

// ── Render Results ────────────────────────────────────────────────────────────
function renderResults(results, score, target) {
  const vulnCount  = results.filter(r => r.vulnerable).length;
  const totalCount = results.length;
  const sc         = score ?? Math.round((1 - vulnCount / totalCount) * 100);
  const scoreColor = sc >= 90 ? "#3fb950" : sc >= 70 ? "#e3b341" : "#f85149";
  const newCount   = results.filter(r => r.regression === "NEW").length;
  const fixedCount = results.filter(r => r.regression === "FIXED").length;

  document.getElementById("score-area").innerHTML = `
    <div class="score-row">
      <div class="score-card"><div class="score-num" style="color:${scoreColor}">${sc}%</div><div class="score-lbl">Score</div></div>
      <div class="score-card"><div class="score-num" style="color:#f85149">${vulnCount}</div><div class="score-lbl">Vulnerable</div></div>
      <div class="score-card"><div class="score-num" style="color:#3fb950">${totalCount - vulnCount}</div><div class="score-lbl">Secure</div></div>
      <div class="score-card"><div class="score-num" style="color:#e3b341">${totalCount}</div><div class="score-lbl">Total</div></div>
    </div>
    ${newCount || fixedCount ? `<div style="font-size:.78em;color:#8b949e;text-align:center;margin-bottom:8px">
      ${newCount   ? `<span style="color:#f85149;margin-right:8px">&#9650; ${newCount} new</span>` : ""}
      ${fixedCount ? `<span style="color:#3fb950">&#9660; ${fixedCount} fixed</span>` : ""}
    </div>` : ""}`;

  document.getElementById("export-bar").style.display = "block";

  getFalsePositives(target).then(fps => {
    document.getElementById("results-list").innerHTML = results.map(r => buildResultCard(r, target, fps)).join("");
    wireResultActions(results, target);
  });
}

function buildResultCard(r, target, fps) {
  const fp      = fps[`${target}::${r.test}`];
  const SEV_CLR = { CRITICAL: "#ff6b6b", HIGH: "#f85149", MEDIUM: "#e3b341", LOW: "#58a6ff" };
  const sev     = SEV_CLR[r.severity] || "#8b949e";
  const isVuln  = r.vulnerable && !fp;
  const REG_CLR = { NEW: "#f85149", RECURRING: "#e3b341", FIXED: "#3fb950" };

  const fpBadge  = fp ? `<span class="badge-fp">${fp.state === "fp" ? "FALSE POSITIVE" : "ACCEPTED RISK"}</span>` : "";
  const regBadge = r.regression ? `<span class="badge-reg" style="border-color:${REG_CLR[r.regression]};color:${REG_CLR[r.regression]}">${r.regression}</span>` : "";

  const compHtml = r.compliance ? `<div class="compliance-row">
    <span class="comp-chip">PCI-DSS</span> ${(r.compliance.pci_dss || []).join(", ")} &nbsp;
    <span class="comp-chip">GDPR</span> ${(r.compliance.gdpr || []).join(", ")} &nbsp;
    <span class="comp-chip">ISO 27001</span> ${(r.compliance.iso27001 || []).join(", ")}
  </div>` : "";

  const evHtml = r.evidence ? `<details class="evidence-block">
    <summary>Evidence</summary>
    <div class="evidence-pre">${r.evidence.request.method} ${r.evidence.request.url}${r.evidence.request.body ? "\nBody: "+r.evidence.request.body : ""}
&#8594; HTTP ${r.evidence.response.status}${r.evidence.response.snippet ? "\n"+r.evidence.response.snippet : ""}</div>
  </details>` : "";

  const fpBtn = r.vulnerable
    ? `<div class="fp-row">
        <button class="fp-btn" data-test="${encodeURIComponent(r.test)}" data-state="${fp ? "remove" : "fp"}" data-tooltip="Mark as a false positive — finding will be greyed out">${fp?.state === "fp" ? "&#10003; Unmark" : "&#9872; False Positive"}</button>
        <button class="fp-btn" data-test="${encodeURIComponent(r.test)}" data-state="${fp?.state === "risk" ? "remove" : "risk"}" data-tooltip="Accept the risk — logs that this finding is a known, accepted risk" data-tip-dir="left">${fp?.state === "risk" ? "&#10003; Unmark" : "&#128737; Accept Risk"}</button>
      </div>` : "";

  return `<div class="result-item ${isVuln ? "result-vuln" : "result-safe"}${fp ? " result-fp" : ""}" data-test="${encodeURIComponent(r.test)}">
    <div class="result-hdr">
      <span class="result-title" style="color:${isVuln ? sev : "#3fb950"}">${isVuln ? "&#10007;" : "&#10003;"} ${r.test}</span>
      <span class="sev-badge" style="color:${sev}">${r.severity}</span>
    </div>
    ${regBadge}${fpBadge}
    <div class="result-cat">${r.category}</div>
    <div class="result-detail">${r.actual}</div>
    ${compHtml}${evHtml}${fpBtn}
  </div>`;
}

function wireResultActions(results, target) {
  // False positive / accept risk buttons
  document.querySelectorAll(".fp-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const testName = decodeURIComponent(btn.dataset.test);
      const state    = btn.dataset.state === "remove" ? null : btn.dataset.state;
      chrome.runtime.sendMessage({ type: "SET_FALSE_POSITIVE", target, testName, state }, () => {
        getFalsePositives(target).then(fps => {
          document.getElementById("results-list").innerHTML = results.map(r => buildResultCard(r, target, fps)).join("");
          wireResultActions(results, target);
        });
      });
    });
  });
}

// Helper to load fps for target
function getFalsePositives(target) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: "GET_FALSE_POSITIVES" }, fps => {
      // Filter to keys for this target
      const out = {};
      for (const [k, v] of Object.entries(fps || {})) {
        if (k.startsWith(`${target}::`)) out[k] = v;
      }
      resolve(out);
    });
  });
}

// ── Export buttons ────────────────────────────────────────────────────────────
document.getElementById("btn-export-json").addEventListener("click", () => {
  if (!_lastResults.length) return;
  downloadJSON({
    tool: "MazAPI Scanner v2.0", target: _lastTarget,
    scanned_at: new Date().toISOString(), score: _lastScore,
    total: _lastResults.length, vulnerable: _lastResults.filter(r => r.vulnerable).length,
    results: _lastResults,
  }, `mazapi-scan-${Date.now()}.json`);
});

document.getElementById("btn-export-sarif").addEventListener("click", () => {
  if (!_lastResults.length) return;
  chrome.runtime.sendMessage({ type: "GENERATE_SARIF", target: _lastTarget, results: _lastResults }, sarif => {
    downloadJSON(sarif, `mazapi-sarif-${Date.now()}.sarif`);
  });
});

document.getElementById("btn-export-html").addEventListener("click", () => {
  if (!_lastResults.length) return;
  chrome.storage.local.get("mazapi_settings", d => {
    const orgName = d?.mazapi_settings?.orgName || "MazAPI Scanner";
    chrome.runtime.sendMessage({ type: "GENERATE_HTML_REPORT", target: _lastTarget, score: _lastScore, results: _lastResults, orgName }, resp => {
      if (resp?.html) {
        const blob = new Blob([resp.html], { type: "text/html" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `mazapi-report-${Date.now()}.html`;
        a.click();
      }
    });
  });
});

document.getElementById("btn-send-webhook").addEventListener("click", () => {
  chrome.storage.local.get("mazapi_settings", d => {
    const url = d?.mazapi_settings?.webhookUrl || "";
    if (!url) { alert("No webhook URL set. Go to Settings tab."); return; }
    chrome.runtime.sendMessage({ type: "SEND_WEBHOOK", webhookUrl: url, target: _lastTarget, score: _lastScore, results: _lastResults }, resp => {
      document.getElementById("btn-send-webhook").textContent = resp?.ok ? "&#10003; Sent!" : "&#10007; Failed";
      setTimeout(() => { document.getElementById("btn-send-webhook").textContent = "&#128276; Send Alert"; }, 2500);
    });
  });
});

// ── Keys tab ──────────────────────────────────────────────────────────────────
function renderKeys() {
  chrome.runtime.sendMessage({ type: "GET_SESSION" }, session => {
    const keys    = session?.hardcoded_keys || [];
    const list    = document.getElementById("keys-list");
    const countEl = document.getElementById("keys-count");
    countEl.textContent = keys.length;
    countEl.className   = "keys-badge" + (keys.length ? " keys-badge-alert" : "");

    if (!keys.length) {
      list.innerHTML = '<div class="empty">No API keys detected yet.<br>Navigate to a website — MazAPI will scan its JavaScript automatically.</div>';
      return;
    }

    const SEV = k => {
      const n = (k.name || "").toLowerCase();
      const s = (k.service || "").toLowerCase();
      if (n.includes("live") || s.includes("live") || n.includes("aws") || n.includes("private") || n.includes("anthropic")) return "CRITICAL";
      if (n.includes("test") || s.includes("test") || n.includes("generic")) return "HIGH";
      return "CRITICAL";
    };
    const SEV_COLOR = { CRITICAL: "#f85149", HIGH: "#e3b341" };
    const KEY_ICON  = k => {
      const n = (k.name || "").toLowerCase();
      if (n.includes("google"))    return "🔵";
      if (n.includes("openai"))    return "🟢";
      if (n.includes("anthropic")) return "🟣";
      if (n.includes("aws"))       return "🟠";
      if (n.includes("stripe"))    return "💜";
      if (n.includes("github"))    return "⚫";
      if (n.includes("gitlab"))    return "🟠";
      if (n.includes("slack"))     return "🔴";
      if (n.includes("twilio") || n.includes("sendgrid")) return "🔴";
      if (n.includes("hugging"))   return "🟡";
      if (n.includes("mapbox"))    return "🔵";
      if (n.includes("notion"))    return "⬜";
      return "🔑";
    };

    list.innerHTML = keys.map(k => {
      const sev   = SEV(k);
      const color = SEV_COLOR[sev] || "#f85149";
      let srcLabel = "";
      try {
        const u = new URL(k.source || "");
        srcLabel = u.pathname.length > 40 ? "…" + u.pathname.slice(-38) : u.pathname || "/";
        if (k.source && k.source.includes("(inline)")) srcLabel = "inline script";
      } catch { srcLabel = k.source || "page"; }

      return `<div class="key-card">
        <div class="key-card-hdr">
          <span class="key-name">${KEY_ICON(k)} ${k.name || "API Key"}</span>
          <span class="key-sev" style="color:${color}">${sev}</span>
        </div>
        <div class="key-service">&#128279; ${k.service || "Unknown service"}</div>
        <div class="key-masked"><code>${k.maskedValue || (k.value || "").slice(0, 8) + "****"}</code></div>
        <div class="key-source">&#128196; ${srcLabel}</div>
      </div>`;
    }).join("");
  });
}

document.getElementById("btn-clear-keys").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_SESSION" }, () => {
    document.getElementById("keys-list").innerHTML = '<div class="empty">Session cleared.</div>';
    document.getElementById("keys-count").textContent = "0";
    document.getElementById("keys-count").className = "keys-badge";
    // Also reset the capture tab counters
    document.getElementById("base-url").textContent = "—";
    document.getElementById("token-area").innerHTML = "";
    document.getElementById("endpoints-list").innerHTML = '<div class="empty">Session cleared.</div>';
    document.getElementById("ep-count").textContent = "0";
  });
});

// ── Threats tab: score ring + attack-surface map + attack chains ──────────────
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function gradeFor(results) {
  const vulns = results.filter(r => r.vulnerable);
  const crit  = vulns.filter(r => r.severity === "CRITICAL").length;
  const high  = vulns.filter(r => r.severity === "HIGH").length;
  const med   = vulns.filter(r => r.severity === "MEDIUM").length;
  const penalty = crit * 40 + high * 12 + med * 3;
  if (crit > 0 || penalty >= 60) return "F";
  if (penalty >= 30) return "D";
  if (penalty >= 12) return "C";
  if (penalty >= 4)  return "B";
  if (penalty > 0)   return "A";
  return "A+";
}

function renderThreats() {
  const results = _lastResults || [];
  const score   = _lastScore ?? 100;

  // Animated ring: dashoffset 0 = full, CIRC = empty. Higher score → fuller, greener.
  const CIRC = 351.86;
  const arc  = document.getElementById("ring-arc");
  const grade = results.length ? gradeFor(results) : "—";
  const color = score >= 90 ? "#00c896" : score >= 70 ? "#f5a623" : "#ff4d6a";
  // Force a reflow so the transition runs each time the tab opens
  arc.style.strokeDashoffset = String(CIRC);
  // eslint-disable-next-line no-unused-expressions
  arc.getBoundingClientRect();
  requestAnimationFrame(() => {
    arc.style.strokeDashoffset = String(CIRC * (1 - score / 100));
    arc.style.stroke = color;
  });
  document.getElementById("ring-grade").textContent = grade;
  document.getElementById("ring-grade").setAttribute("fill", color);
  document.getElementById("ring-score").textContent = results.length ? `${score}%` : "";

  // Severity count-up
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const r of results) if (r.vulnerable) counts[r.severity] = (counts[r.severity] || 0) + 1;
  countUp("tc-crit", counts.CRITICAL);
  countUp("tc-high", counts.HIGH);
  countUp("tc-med",  counts.MEDIUM);
  countUp("tc-low",  counts.LOW);

  renderAttackMap();
  renderChains();
}

function countUp(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = 0, dur = 600, t0 = performance.now();
  function step(now) {
    const p = Math.min(1, (now - t0) / dur);
    el.textContent = Math.round(start + (target - start) * p);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// Attack-surface map: endpoints as nodes around a centre, coloured by worst finding,
// attack chains drawn as red edges between the endpoints they implicate. Plain SVG.
function renderAttackMap() {
  const box = document.getElementById("attack-map");
  chrome.runtime.sendMessage({ type: "GET_SESSION" }, session => {
    const eps = Object.keys(session?.endpoints || {}).slice(0, 10);
    if (!eps.length) { box.innerHTML = '<div class="empty">No endpoints captured to map.</div>'; return; }

    const W = 340, H = Math.max(150, 90 + eps.length * 14), cx = W / 2, cy = H / 2;
    const R = Math.min(cx, cy) - 36;
    const SEV_COLOR = { CRITICAL: "#ff4d6a", HIGH: "#f85149", MEDIUM: "#f5a623", LOW: "#58a6ff", none: "#2d3a4d" };

    // worst severity touching each endpoint, from results that name it in evidence/actual
    const worst = {};
    for (const ep of eps) {
      let w = "none";
      for (const r of (_lastResults || [])) {
        if (!r.vulnerable) continue;
        const hay = `${r.actual || ""} ${r.evidence?.request?.url || ""}`;
        if (hay.includes(ep.replace(/\{id\}/g, "")) && SEV_RANK[r.severity] > (SEV_RANK[w] || 0)) w = r.severity;
      }
      worst[ep] = w;
    }

    const pts = eps.map((ep, i) => {
      const a = (i / eps.length) * 2 * Math.PI - Math.PI / 2;
      return { ep, x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
    });

    // chain edges: connect first two endpoints that match a chain's evidence (best-effort visual)
    const edges = [];
    for (const ch of (_lastChains || [])) {
      const touched = pts.filter(p => (ch.evidence || []).some(e => String(e).includes(p.ep.replace(/\{id\}/g, "")))).slice(0, 2);
      if (touched.length === 2) edges.push([touched[0], touched[1]]);
    }

    const edgeSvg = edges.map(([a, b]) =>
      `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke="#ff4d6a" stroke-width="1.4" stroke-dasharray="3 3" opacity=".7"/>`
    ).join("");

    const nodeSvg = pts.map(p => {
      const c = SEV_COLOR[worst[p.ep]] || SEV_COLOR.none;
      const label = (p.ep.length > 18 ? p.ep.slice(0, 17) + "…" : p.ep);
      const ring = worst[p.ep] !== "none"
        ? `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="9" fill="none" stroke="${c}" stroke-width="2" opacity=".55"/>`
        : "";
      return `${ring}<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="4.5" fill="${c}"><title>${p.ep} — ${worst[p.ep]}</title></circle>
        <text class="node-label" x="${p.x.toFixed(1)}" y="${(p.y + (p.y < cy ? -10 : 16)).toFixed(1)}" text-anchor="middle">${label}</text>`;
    }).join("");

    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}">
      <circle cx="${cx}" cy="${cy}" r="3" fill="#00d4ff"/><text class="node-label" x="${cx}" y="${cy + 14}" text-anchor="middle" fill="#00d4ff">API</text>
      ${pts.map(p => `<line x1="${cx}" y1="${cy}" x2="${p.x.toFixed(1)}" y2="${p.y.toFixed(1)}" stroke="#1a2230" stroke-width="1"/>`).join("")}
      ${edgeSvg}${nodeSvg}
    </svg>`;
  });
}

function renderChains() {
  const box = document.getElementById("chains-list");
  const chains = _lastChains || [];
  if (!chains.length) {
    box.innerHTML = '<div class="empty">No correlated attack chains. Chains appear when findings combine into an exploit path.</div>';
    return;
  }
  box.innerHTML = chains.map(c => `
    <div class="chain-card sev-${c.severity}">
      <div class="chain-hdr">
        <span class="chain-title">&#9888; ${c.title}</span>
        <span class="chain-sev">${c.severity}</span>
      </div>
      <div class="chain-narrative">${c.narrative}</div>
      <div class="chain-evidence"><b>Chained from:</b>
        <ul>${(c.evidence || []).map(e => `<li>${e}</li>`).join("")}</ul>
      </div>
    </div>`).join("");
}

// ── Live tab: real-time intercepted-request feed ──────────────────────────────
function renderLive() {
  if (_livePaused) return;
  chrome.runtime.sendMessage({ type: "GET_LIVE_FEED" }, feed => {
    const box = document.getElementById("live-feed");
    if (!feed?.length) {
      box.innerHTML = '<div class="empty">Browse the target — intercepted API requests stream here in real time.</div>';
      return;
    }
    // newest at the bottom (terminal style); show last 80
    box.innerHTML = feed.slice(-80).map(l => {
      const flag = l.verdict === "suspicious"
        ? '<span class="lv-flag" title="sensitive path or server error">&#9888;</span>'
        : (l.verdict === "watch" ? '<span class="lv-flag" title="ID in path or missing auth">&#9679;</span>' : "");
      const path = (l.path || "").length > 52 ? l.path.slice(0, 51) + "…" : (l.path || "");
      return `<div class="live-line v-${l.verdict}">
        <span class="lv-method">${l.method}</span>
        <span class="lv-status">${l.status}</span>
        <span class="lv-path" title="${l.path || ""}">${path}</span>${flag}
      </div>`;
    }).join("");
    box.scrollTop = box.scrollHeight;
  });
}

function startLivePolling() {
  stopLivePolling();
  _liveTimer = setInterval(() => { if (!_livePaused) renderLive(); }, 1500);
}
function stopLivePolling() {
  if (_liveTimer) { clearInterval(_liveTimer); _liveTimer = null; }
}

document.getElementById("btn-live-pause").addEventListener("click", () => {
  _livePaused = !_livePaused;
  document.getElementById("btn-live-pause").textContent = _livePaused ? "Resume" : "Pause";
  document.getElementById("live-dot").classList.toggle("paused", _livePaused);
});

// ── History tab ───────────────────────────────────────────────────────────────
function renderHistory() {
  chrome.runtime.sendMessage({ type: "GET_HISTORY" }, history => {
    const list = document.getElementById("history-list");
    if (!history?.length) {
      list.innerHTML = '<div class="empty">No scan history yet — run a scan first.</div>';
      return;
    }
    list.innerHTML = history.map((h, idx) => {
      const sc    = h.score;
      const color = sc >= 90 ? "#3fb950" : sc >= 70 ? "#e3b341" : "#f85149";
      const date  = new Date(h.date).toLocaleString();
      const newC  = h.results?.filter(r => r.regression === "NEW")?.length ?? 0;
      const fixC  = h.results?.filter(r => r.regression === "FIXED")?.length ?? 0;
      const hasFullResults = h.results?.length && h.results[0].severity;
      return `<div class="history-item" data-idx="${idx}" style="cursor:pointer">
        <div class="history-hdr">
          <span class="history-target">${h.target}</span>
          <span style="font-size:1.1em;font-weight:700;color:${color}">${sc}%</span>
        </div>
        <div class="history-meta">${date} &nbsp;|&nbsp; ${h.vulnerable}/${h.total} vulnerable
          ${newC  ? `&nbsp;<span style="color:#f85149">+${newC} new</span>` : ""}
          ${fixC  ? `&nbsp;<span style="color:#3fb950">-${fixC} fixed</span>` : ""}
        </div>
        <div style="margin-top:5px">
          ${hasFullResults
            ? `<button class="export-btn history-view-btn" data-idx="${idx}" style="font-size:.75em;padding:3px 8px" data-tooltip="Load these results into the Results tab without rescanning">&#128269; View Results</button>`
            : `<span style="font-size:.73em;color:#8b949e;font-style:italic">Rescan to get detailed results</span>`
          }
        </div>
      </div>`;
    }).join("");

    // Wire up "View Results" buttons
    document.querySelectorAll(".history-view-btn").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        const h = history[parseInt(btn.dataset.idx)];
        loadHistoryResults(h);
      });
    });

    // Also make the whole card clickable if it has results
    document.querySelectorAll(".history-item").forEach(card => {
      card.addEventListener("click", () => {
        const h = history[parseInt(card.dataset.idx)];
        if (h.results?.length && h.results[0].severity) loadHistoryResults(h);
      });
    });
  });
}

function loadHistoryResults(h, allHistory) {
  // Populate the scan form fields so the user can rescan if they want
  document.getElementById("scan-target").value = h.target;
  // Load results into Results tab and switch to it
  _lastTarget  = h.target;
  _lastResults = h.results;
  _lastScore   = h.score;
  renderResults(h.results, h.score, h.target);

  // Diff banner: NEW (regressions) vs FIXED relative to the previous scan of this target.
  // The stored `regression` tags were computed against the prior scan at capture time.
  const news  = (h.results || []).filter(r => r.regression === "NEW");
  const fixes = (h.results || []).filter(r => r.regression === "FIXED");
  const direction = fixes.length > news.length ? "improved"
                  : news.length > fixes.length ? "regressed" : "unchanged";
  const dirColor  = direction === "improved" ? "#00c896" : direction === "regressed" ? "#ff4d6a" : "#8b949e";
  const banner = (news.length || fixes.length)
    ? `<div class="diff-banner" style="border-color:${dirColor}">
         <span style="color:${dirColor};font-weight:700">Security ${direction}</span>
         ${fixes.length ? `<span style="color:#00c896">&#9660; ${fixes.length} fixed</span>` : ""}
         ${news.length  ? `<span style="color:#ff4d6a">&#9650; ${news.length} new</span>`   : ""}
       </div>`
    : "";
  const scoreArea = document.getElementById("score-area");
  if (banner) scoreArea.insertAdjacentHTML("beforeend", banner);

  // Recompute attack chains for this historical result set so the Threats tab stays in sync
  chrome.runtime.sendMessage({ type: "CORRELATE_CHAINS", results: h.results }, chains => {
    _lastChains = chains || [];
  });

  document.querySelector(".tab[data-tab='results']").click();
}

document.getElementById("btn-clear-history").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => renderHistory());
});

// ── Settings tab ──────────────────────────────────────────────────────────────
function loadSettings() {
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, s => {
    if (!s) return;
    document.getElementById("set-orgname").value         = s.orgName || "";
    document.getElementById("set-webhook").value         = s.webhookUrl || "";
    document.getElementById("set-auto-webhook").checked   = !!s.autoWebhook;
    const monUrl = s.monitorUrl || "http://localhost:9000";
    document.getElementById("set-monitor-url").value     = monUrl;
    document.getElementById("set-link-dashboard").checked = !!s.linkDashboard;

    const scanMonInput = document.getElementById("scan-monitor-url");
    if (scanMonInput) scanMonInput.value = monUrl;
  });
}

document.getElementById("btn-save-settings").addEventListener("click", () => {
  const monUrl = document.getElementById("set-monitor-url").value.trim() || "http://localhost:9000";
  const settings = {
    orgName:       document.getElementById("set-orgname").value.trim(),
    webhookUrl:    document.getElementById("set-webhook").value.trim(),
    autoWebhook:   document.getElementById("set-auto-webhook").checked,
    monitorUrl:    monUrl,
    linkDashboard: document.getElementById("set-link-dashboard").checked,
  };
  const scanMonInput = document.getElementById("scan-monitor-url");
  if (scanMonInput) scanMonInput.value = monUrl;

  chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", settings }, () => {
    const st = document.getElementById("settings-status");
    st.textContent = "&#10003; Settings saved";
    setTimeout(() => { st.textContent = ""; }, 2000);
  });
});

// Open the live monitoring dashboard for the current target.
document.getElementById("btn-open-dashboard")?.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, s => {
    const base = (((s && s.monitorUrl) || document.getElementById("set-monitor-url")?.value || "http://localhost:9000")).replace(/\/+$/, "");
    const site = (document.getElementById("scan-target")?.value || _lastTarget || "").trim();
    const url  = base + "/extension/live" + (site ? "?site=" + encodeURIComponent(site) : "");
    chrome.tabs.create({ url });
  });
});

// ── Utilities ─────────────────────────────────────────────────────────────────
function downloadJSON(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

// ── Tab switching handler ─────────────────────────────────────────────────────
function handleTabChange() {
  getActiveTabOrigin((origin, activeUrl) => {
    if (origin && origin !== _currentTabOrigin) {
      _currentTabOrigin = origin;
      _lastResults = [];
      _lastScore   = 100;
      _lastTarget  = origin;
      _lastChains  = [];

      const targetInput = document.getElementById("scan-target");
      if (targetInput) targetInput.value = origin;

      const resList = document.getElementById("results-list");
      if (resList) resList.innerHTML = '<div class="empty">Run a scan to see results.</div>';
      const scoreArea = document.getElementById("score-area");
      if (scoreArea) scoreArea.innerHTML = "";
      const expBar = document.getElementById("export-bar");
      if (expBar) expBar.style.display = "none";

      loadSession();
      checkActiveScanStatus();
    }
  });
}

if (chrome.tabs?.onActivated) {
  chrome.tabs.onActivated.addListener(handleTabChange);
}
if (chrome.tabs?.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === "complete" || changeInfo.url) {
      handleTabChange();
    }
  });
}

// ── Auth Token Harvester ──────────────────────────────────────────────────────
function renderAuth() {
  getActiveTabOrigin((origin, activeUrl) => {
    chrome.runtime.sendMessage({ type: "GET_SESSION", origin, url: activeUrl }, session => {
      const list = document.getElementById("auth-tokens-list");
      const badge = document.getElementById("auth-count");
      if (!session) return;
      
      const tokens = session.tokens || [];
      const apiKeys = session.apiKeys || [];
      const totalAuth = tokens.length + apiKeys.length;
      if (badge) badge.textContent = totalAuth;

      if (totalAuth === 0) {
        list.innerHTML = '<div class="empty">No tokens harvested yet. Log in to an application or make authenticated requests to populate.</div>';
        return;
      }

      let html = "";
      tokens.forEach((tok, idx) => {
        const short = tok.length > 50 ? tok.slice(0, 24) + "..." + tok.slice(-16) : tok;
        html += `
          <div class="key-card" style="border-left-color: var(--indigo); margin-bottom: 8px;">
            <div class="key-card-hdr">
              <span class="key-name">Bearer Token #${idx + 1}</span>
            </div>
            <div class="key-masked"><code>${short}</code></div>
            ${decodeJWT(tok)}
          </div>
        `;
      });

      apiKeys.forEach((k) => {
        html += `
          <div class="key-card" style="border-left-color: var(--amber); margin-bottom: 8px;">
            <div class="key-card-hdr">
              <span class="key-name">${k.header}</span>
            </div>
            <div class="key-masked"><code>${k.value}</code></div>
          </div>
        `;
      });

      list.innerHTML = html;
    });
  });
}

// ── Request Manipulator & Replay ───────────────────────────────────────────────
function initReplay() {
  getActiveTabOrigin((origin, activeUrl) => {
    chrome.runtime.sendMessage({ type: "GET_SESSION", origin, url: activeUrl }, session => {
      const picker = document.getElementById("smart-param-picker");
      const urlInput = document.getElementById("replay-url");
      const headersInput = document.getElementById("replay-headers");
      if (!session) return;

      const paramMap = {};
      Object.keys(session.endpoints || {}).forEach(path => {
        const pathMatches = path.match(/\{([^\}]+)\}|:([a-zA-Z0-9_]+)/g);
        if (pathMatches) {
          pathMatches.forEach(p => {
            paramMap[p] = "1";
          });
        }
      });

      if (session.tokens?.length && headersInput && !headersInput.value) {
        headersInput.value = `Authorization: Bearer ${session.tokens[0]}\nContent-Type: application/json`;
      }

      if (urlInput && !urlInput.value && session.baseUrl) {
        const firstEp = Object.keys(session.endpoints || {})[0] || "/api";
        urlInput.value = session.baseUrl + firstEp.replace(/\{id\}/g, "1");
      }

      if (picker) {
        let optionsHtml = '<option value="">-- Select parameter to insert/swap --</option>';
        optionsHtml += '<option value="user_id=2">user_id=2 (BOLA Cross-Tenant Swap)</option>';
        optionsHtml += '<option value="id=9999">id=9999 (IDOR Enumeration)</option>';
        optionsHtml += '<option value="role=admin">role=admin (Privilege Escalation)</option>';
        optionsHtml += '<option value="is_admin=true">is_admin=true (Mass Assignment)</option>';
        Object.keys(paramMap).forEach(p => {
          optionsHtml += `<option value="${p}=2">${p}=2 (Observed in Path)</option>`;
        });
        picker.innerHTML = optionsHtml;
      }
    });
  });
}

document.getElementById("smart-param-picker")?.addEventListener("change", (e) => {
  const val = e.target.value;
  if (!val) return;
  const urlInput = document.getElementById("replay-url");
  const bodyInput = document.getElementById("replay-body");
  if (urlInput && (val.startsWith("{") || val.includes("id="))) {
    urlInput.value = urlInput.value.replace(/\/\d+(?=\/|$)/, "/2");
  } else if (bodyInput && (val.includes("admin") || val.includes("role"))) {
    try {
      const parsed = JSON.parse(bodyInput.value || "{}");
      const [k, v] = val.split("=");
      parsed[k] = v === "true" ? true : v;
      bodyInput.value = JSON.stringify(parsed, null, 2);
    } catch {
      bodyInput.value = `{"${val.split('=')[0]}": "${val.split('=')[1]}"}`;
    }
  }
});

document.getElementById("btn-replay-send")?.addEventListener("click", async () => {
  const method = document.getElementById("replay-method")?.value || "GET";
  const url = document.getElementById("replay-url")?.value.trim();
  const rawHeaders = document.getElementById("replay-headers")?.value.trim() || "";
  const body = document.getElementById("replay-body")?.value.trim();
  const respArea = document.getElementById("replay-response-area");
  const respBadge = document.getElementById("replay-status-badge");
  const latencyEl = document.getElementById("replay-latency");
  const respBody = document.getElementById("replay-response-body");

  if (!url) return;

  const headers = {};
  rawHeaders.split("\n").forEach(l => {
    const idx = l.indexOf(":");
    if (idx > 0) headers[l.slice(0, idx).trim()] = l.slice(idx + 1).trim();
  });

  if (respArea) respArea.style.display = "block";
  if (respBody) respBody.textContent = "Sending request...";
  const start = performance.now();

  try {
    const fetchOpts = { method, headers };
    if (["POST", "PUT", "PATCH"].includes(method) && body) {
      fetchOpts.body = body;
    }
    const res = await fetch(url, fetchOpts);
    const duration = Math.round(performance.now() - start);
    const text = await res.text();

    if (respBadge) {
      respBadge.textContent = `${res.status} ${res.statusText || ""}`;
      respBadge.className = `badge ${res.status < 300 ? 'badge-get' : res.status < 500 ? 'badge-delete' : 'badge-post'}`;
    }
    if (latencyEl) latencyEl.textContent = `${duration}ms`;

    if (respBody) {
      try {
        respBody.textContent = JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        respBody.textContent = text || "(Empty response)";
      }
    }
  } catch (err) {
    if (respBadge) {
      respBadge.textContent = "FETCH ERROR";
      respBadge.className = "badge badge-delete";
    }
    if (respBody) respBody.textContent = err.message;
  }
});

// ── OAS Picker & OpenAPI Spec ─────────────────────────────────────────────────
function initOAS() {
  getActiveTabOrigin((origin, activeUrl) => {
    chrome.runtime.sendMessage({ type: "GET_SESSION", origin, url: activeUrl }, session => {
      const container = document.getElementById("oas-endpoints-checkboxes");
      if (!container) return;
      if (!session || !session.endpoints || !Object.keys(session.endpoints).length) {
        container.innerHTML = '<div class="empty">No captured endpoints to export yet. Browse the target app to populate.</div>';
        return;
      }

      let html = "";
      Object.entries(session.endpoints).forEach(([path, data]) => {
        const methods = (data.methods || ["GET"]).join(", ");
        html += `
          <label class="oas-check-item">
            <input type="checkbox" checked class="oas-ep-checkbox" data-path="${path}" data-methods="${methods}" data-auth="${data.authRequired}">
            <span style="color: var(--accent); font-weight: 700;">${methods}</span>
            <span style="flex: 1; overflow: hidden; text-overflow: ellipsis;">${path}</span>
          </label>
        `;
      });
      container.innerHTML = html;
    });
  });
}

document.getElementById("btn-oas-select-all")?.addEventListener("click", () => {
  document.querySelectorAll(".oas-ep-checkbox").forEach(cb => cb.checked = true);
});
document.getElementById("btn-oas-clear-all")?.addEventListener("click", () => {
  document.querySelectorAll(".oas-ep-checkbox").forEach(cb => cb.checked = false);
});

document.getElementById("btn-export-oas-yaml")?.addEventListener("click", () => {
  getActiveTabOrigin((origin) => {
    chrome.runtime.sendMessage({ type: "GET_SESSION", origin }, session => {
      const selectedPaths = {};
      document.querySelectorAll(".oas-ep-checkbox:checked").forEach(cb => {
        const path = cb.dataset.path;
        selectedPaths[path] = (session && session.endpoints && session.endpoints[path]) || { methods: [cb.dataset.methods], authRequired: cb.dataset.auth === 'true' };
      });
      const spec = generateOpenAPI(origin || (session && session.baseUrl) || "http://localhost:8000", selectedPaths);
      downloadYAML(spec, `openapi_${new URL(origin || 'http://localhost').hostname}.yaml`);
    });
  });
});

document.getElementById("btn-export-oas-json")?.addEventListener("click", () => {
  getActiveTabOrigin((origin) => {
    chrome.runtime.sendMessage({ type: "GET_SESSION", origin }, session => {
      const selectedPaths = {};
      document.querySelectorAll(".oas-ep-checkbox:checked").forEach(cb => {
        const path = cb.dataset.path;
        selectedPaths[path] = (session && session.endpoints && session.endpoints[path]) || { methods: [cb.dataset.methods], authRequired: cb.dataset.auth === 'true' };
      });
      const spec = generateOpenAPI(origin || (session && session.baseUrl) || "http://localhost:8000", selectedPaths);
      downloadJSON(spec, `openapi_${new URL(origin || 'http://localhost').hostname}.json`);
    });
  });
});

function downloadYAML(obj, filename) {
  function toYaml(data, indent = 0) {
    const pad = "  ".repeat(indent);
    let str = "";
    if (typeof data === "object" && data !== null) {
      if (Array.isArray(data)) {
        data.forEach(item => {
          str += `${pad}- ${typeof item === 'object' ? '\n' + toYaml(item, indent + 1) : item}\n`;
        });
      } else {
        Object.entries(data).forEach(([k, v]) => {
          if (typeof v === "object" && v !== null) {
            str += `${pad}${k}:\n${toYaml(v, indent + 1)}`;
          } else {
            str += `${pad}${k}: ${v}\n`;
          }
        });
      }
    }
    return str;
  }
  const yamlStr = "openapi: 3.0.3\n" + toYaml(obj);
  const blob = new Blob([yamlStr], { type: "text/yaml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

function updateThreatBanner(session) {
  const banner = document.getElementById("live-threat-banner");
  const textEl = document.getElementById("threat-banner-text");
  if (!banner || !session) return;

  const behs = session.behavioral || [];
  const keys = session.hardcoded_keys || [];
  if (behs.length > 0) {
    const worst = behs[behs.length - 1];
    if (textEl) textEl.textContent = `[${worst.severity}] ${worst.title}: ${worst.path}`;
    banner.style.display = "flex";
  } else if (keys.length > 0) {
    if (textEl) textEl.textContent = `[CRITICAL] Hardcoded API key detected in page JavaScript`;
    banner.style.display = "flex";
  } else {
    banner.style.display = "none";
  }
}

document.getElementById("btn-view-threat")?.addEventListener("click", () => {
  document.querySelector(".tab[data-tab='threats']")?.click();
});

// ── Boot ──────────────────────────────────────────────────────────────────────
loadSettings();
loadSession();
checkContextUrl();
checkActiveScanStatus();
setInterval(loadSession, 3000);
