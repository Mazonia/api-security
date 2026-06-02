// MazAPI Scanner — Popup Script

// ── Tab navigation ────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".pane").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("pane-" + tab.dataset.tab).classList.add("active");
  });
});

// ── Load session from background ──────────────────────────────────────────────
function loadSession() {
  chrome.runtime.sendMessage({ type: "GET_SESSION" }, (session) => {
    if (!session) return;
    renderDiscovered(session);
  });
}

function renderDiscovered(session) {
  // Base URL
  document.getElementById("base-url").textContent = session.baseUrl || "—";

  // Tokens
  const tokenArea = document.getElementById("token-area");
  if (session.tokens && session.tokens.length) {
    const tok = session.tokens[0];
    const short = tok.length > 60 ? tok.slice(0, 60) + "…" : tok;
    tokenArea.innerHTML = `
      <div class="token-label">Bearer Token (captured from headers)</div>
      <div class="token-box" title="${tok}">${short}</div>`;
    document.getElementById("scan-token").value  = tok;
  } else if (session.apiKeys && session.apiKeys.length) {
    const k = session.apiKeys[0];
    tokenArea.innerHTML = `<div class="token-label">${k.header}</div><div class="token-box">${k.value}</div>`;
  } else {
    tokenArea.innerHTML = `<div style="color:#8b949e;font-size:.82em;margin-bottom:8px">No token captured yet — log in to the site to capture auth credentials.</div>`;
  }

  // Hardcoded key warnings from content script
  const warnings = document.getElementById("key-warnings");
  if (session.hardcoded_keys && session.hardcoded_keys.length) {
    warnings.innerHTML = session.hardcoded_keys.slice(0, 2).map(k =>
      `<div class="key-warning">⚠️ Hardcoded credential detected in page JS: <code>${k.value.slice(0, 24)}…</code></div>`
    ).join("");
  }

  // Endpoints
  const list    = document.getElementById("endpoints-list");
  const eps     = Object.entries(session.endpoints || {});
  const countEl = document.getElementById("ep-count");
  countEl.textContent = eps.length;

  if (!eps.length) {
    list.innerHTML = '<div class="empty">Browse the target website to capture API calls.</div>';
    if (session.baseUrl) document.getElementById("scan-target").value = session.baseUrl;
    return;
  }

  if (session.baseUrl) document.getElementById("scan-target").value = session.baseUrl;

  list.innerHTML = eps.slice(0, 20).map(([path, data]) => {
    const methods = (data.methods || []).map(m =>
      `<span class="badge badge-${m.toLowerCase()}">${m}</span>`).join("");
    const authNote = data.authRequired ? '<span style="color:#e3b341;font-size:.77em"> 🔒 auth required</span>' : "";
    return `<div class="endpoint-item">
      <div class="endpoint-path">${path}</div>
      <div class="endpoint-meta">${methods}${authNote}</div>
    </div>`;
  }).join("") + (eps.length > 20 ? `<div style="color:#8b949e;font-size:.78em;padding:4px 0">…and ${eps.length - 20} more</div>` : "");
}

// ── Clear session ─────────────────────────────────────────────────────────────
document.getElementById("btn-clear").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_SESSION" }, () => {
    document.getElementById("base-url").textContent = "—";
    document.getElementById("token-area").innerHTML = "";
    document.getElementById("endpoints-list").innerHTML = '<div class="empty">Session cleared.</div>';
    document.getElementById("ep-count").textContent = "0";
    document.getElementById("results-list").innerHTML = '<div class="empty">Run a scan to see results.</div>';
    document.getElementById("score-area").innerHTML = "";
  });
});

// ── Run Scan ──────────────────────────────────────────────────────────────────
document.getElementById("btn-scan").addEventListener("click", () => {
  const target    = document.getElementById("scan-target").value.trim();
  const token     = document.getElementById("scan-token").value.trim();
  const authEp    = document.getElementById("scan-auth-ep").value.trim();
  const protected_ = document.getElementById("scan-protected").value.trim();

  if (!target) { alert("Enter a target URL first."); return; }

  const btn    = document.getElementById("btn-scan");
  const status = document.getElementById("scan-status");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning…';
  status.textContent = "Running 7 test categories…";

  chrome.runtime.sendMessage({
    type: "RUN_SCAN",
    target,
    token: token || null,
    options: { authEndpoint: authEp, protectedPath: protected_ }
  }, (resp) => {
    btn.disabled = false;
    btn.innerHTML = "▶ Run Scan";
    if (!resp || !resp.ok) {
      status.textContent = "Error: " + (resp ? resp.error : "no response");
      return;
    }
    status.textContent = "";
    renderResults(resp.results);
    // Auto-switch to results tab
    document.querySelector(".tab[data-tab='results']").click();
  });
});

function renderResults(results) {
  const vulnCount  = results.filter(r => r.vulnerable).length;
  const totalCount = results.length;
  const score      = totalCount ? Math.round((1 - vulnCount / totalCount) * 100) : 100;
  const scoreColor = score === 100 ? "#3fb950" : score >= 70 ? "#e3b341" : "#f85149";

  document.getElementById("score-area").innerHTML = `
    <div class="score-row">
      <div class="score-card"><div class="score-num" style="color:${scoreColor}">${score}%</div><div class="score-lbl">Security Score</div></div>
      <div class="score-card"><div class="score-num" style="color:#f85149">${vulnCount}</div><div class="score-lbl">Vulnerable</div></div>
      <div class="score-card"><div class="score-num" style="color:#3fb950">${totalCount - vulnCount}</div><div class="score-lbl">Secure</div></div>
    </div>`;

  document.getElementById("results-list").innerHTML = results.map(r => `
    <div class="result-item ${r.vulnerable ? "result-vuln" : "result-safe"}">
      <div class="result-title">${r.vulnerable ? "✗" : "✓"} ${r.test}</div>
      <div class="result-cat">${r.category}</div>
      <div class="result-detail">${r.actual}</div>
    </div>`).join("");
}

// ── Load on open ──────────────────────────────────────────────────────────────
loadSession();
// Auto-refresh every 3s while popup is open
setInterval(loadSession, 3000);
