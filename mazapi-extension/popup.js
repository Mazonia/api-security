// MazAPI Scanner — Popup Script v2.0

let _showAllEndpoints = false;
let _lastResults      = [];
let _lastScore        = 100;
let _lastTarget       = "";

// ── Tab navigation ────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".pane").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    const pane = document.getElementById("pane-" + tab.dataset.tab);
    if (pane) pane.classList.add("active");
    if (tab.dataset.tab === "history")  renderHistory();
    if (tab.dataset.tab === "settings") loadSettings();
    if (tab.dataset.tab === "keys")     renderKeys();
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

// ── Load session from background ──────────────────────────────────────────────
function loadSession() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const activeTabUrl = tabs?.[0]?.url || "";
    chrome.runtime.sendMessage({ type: "GET_SESSION" }, session => {
      if (!session) return;
      renderDiscovered(session, activeTabUrl);
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
  chrome.runtime.sendMessage({ type: "CLEAR_SESSION" }, () => {
    document.getElementById("base-url").textContent = "—";
    document.getElementById("token-area").innerHTML = "";
    document.getElementById("endpoints-list").innerHTML = '<div class="empty">Session cleared.</div>';
    document.getElementById("ep-count").textContent = "0";
    document.getElementById("results-list").innerHTML = '<div class="empty">Run a scan to see results.</div>';
    document.getElementById("score-area").innerHTML = "";
    document.getElementById("export-bar").style.display = "none";
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
document.getElementById("btn-scan").addEventListener("click", () => {
  const target    = document.getElementById("scan-target").value.trim();
  const token     = document.getElementById("scan-token").value.trim();
  const authEp    = document.getElementById("scan-auth-ep").value.trim();
  const protected_ = document.getElementById("scan-protected").value.trim();

  if (!target) { alert("Enter a target URL first."); return; }

  _lastTarget = target;
  const btn    = document.getElementById("btn-scan");
  const status = document.getElementById("scan-status");
  btn.disabled    = true;
  btn.innerHTML   = '<span class="spinner"></span> Scanning…';
  status.textContent = "Running all test categories…";

  chrome.runtime.sendMessage({
    type: "RUN_SCAN",
    target,
    token: token || null,
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
    renderResults(resp.results, _lastScore, target);
    document.querySelector(".tab[data-tab='results']").click();
  });
});

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
    const orgName = d.mazapi_settings?.orgName || "MazAPI Scanner";
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
    const url = d.mazapi_settings?.webhookUrl || "";
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
        const u = new URL(k.source);
        srcLabel = u.pathname.length > 40 ? "…" + u.pathname.slice(-38) : u.pathname || "/";
        if (k.source.includes("(inline)")) srcLabel = "inline script";
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

function loadHistoryResults(h) {
  // Populate the scan form fields so the user can rescan if they want
  document.getElementById("scan-target").value = h.target;
  // Load results into Results tab and switch to it
  _lastTarget  = h.target;
  _lastResults = h.results;
  _lastScore   = h.score;
  renderResults(h.results, h.score, h.target);
  document.querySelector(".tab[data-tab='results']").click();
}

document.getElementById("btn-clear-history").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => renderHistory());
});

// ── Settings tab ──────────────────────────────────────────────────────────────
function loadSettings() {
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, s => {
    if (!s) return;
    document.getElementById("set-orgname").value       = s.orgName || "";
    document.getElementById("set-webhook").value       = s.webhookUrl || "";
    document.getElementById("set-auto-webhook").checked = !!s.autoWebhook;
  });
}

document.getElementById("btn-save-settings").addEventListener("click", () => {
  const settings = {
    orgName:     document.getElementById("set-orgname").value.trim(),
    webhookUrl:  document.getElementById("set-webhook").value.trim(),
    autoWebhook: document.getElementById("set-auto-webhook").checked,
  };
  chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", settings }, () => {
    const st = document.getElementById("settings-status");
    st.textContent = "&#10003; Settings saved";
    setTimeout(() => { st.textContent = ""; }, 2000);
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

// ── Boot ──────────────────────────────────────────────────────────────────────
loadSession();
checkContextUrl();
setInterval(loadSession, 3000);
