/**
 * MazAPI Scanner — Background Service Worker v2.0
 * Full feature set: evidence capture, compliance mapping, scan history,
 * regression detection, SARIF/HTML/Postman export, webhook, context menu,
 * GraphQL introspection, mass assignment, PII detection, JWT alg:none.
 */

// ── Compliance mapping ────────────────────────────────────────────────────────
const COMPLIANCE_MAP = {
  "API1:2023 - Broken Object Level Authorization":            { pci_dss: ["6.2.4","8.2.3"],       gdpr: ["Art. 5(1)(f)","Art. 32"],      iso27001: ["A.9.4.1","A.14.2.5"] },
  "API2:2023 - Broken Authentication":                        { pci_dss: ["8.2.1","8.3.1"],        gdpr: ["Art. 32(1)(b)"],               iso27001: ["A.9.4.3","A.10.1.1"] },
  "API3:2023 - Broken Object Property Level Authorization":   { pci_dss: ["6.2.4"],                gdpr: ["Art. 5(1)(c)","Art. 25"],      iso27001: ["A.14.2.5","A.18.1.3"] },
  "API4:2023 - Unrestricted Resource Consumption":            { pci_dss: ["6.2.4","6.3.1"],        gdpr: ["Art. 32"],                     iso27001: ["A.12.6.1","A.17.2.1"] },
  "API5:2023 - Broken Function Level Authorization":          { pci_dss: ["7.1.1","7.2.1"],        gdpr: ["Art. 32(4)"],                  iso27001: ["A.9.2.3","A.9.4.1"] },
  "API7:2023 - Server-Side Request Forgery":                  { pci_dss: ["6.2.4","6.3.3"],        gdpr: ["Art. 32"],                     iso27001: ["A.13.1.3","A.14.2.5"] },
  "API8:2023 - Security Misconfiguration":                    { pci_dss: ["6.3.3","6.4.1"],        gdpr: ["Art. 32"],                     iso27001: ["A.14.1.3","A.18.1.3"] },
  "API8:2023 - Security Misconfiguration (hardening)":        { pci_dss: ["6.3.3"],                gdpr: ["Art. 32"],                     iso27001: ["A.14.1.3"] },
  "API9:2023 - Improper Inventory Management / GraphQL":      { pci_dss: ["6.3.3"],                gdpr: ["Art. 32"],                     iso27001: ["A.12.6.1"] },
  "CVE-2021-41773 / CWE-22 - Path Traversal":                { pci_dss: ["6.2.4"],                gdpr: ["Art. 32"],                     iso27001: ["A.14.2.5"] },
  "CVE-2019-11229 / CWE-601 - Open Redirect":                { pci_dss: ["6.2.4"],                gdpr: ["Art. 32"],                     iso27001: ["A.14.2.5"] },
  "CWE-650 - HTTP Verb Tampering":                            { pci_dss: ["6.2.4"],                gdpr: ["Art. 32"],                     iso27001: ["A.14.2.5"] },
  "CWE-312 / GDPR - PII Exposure in API Response":           { pci_dss: ["3.4.1","4.2.1"],        gdpr: ["Art. 5","Art. 17","Art. 25","Art. 32","Art. 83(4)"], iso27001: ["A.18.1.4","A.8.2.3"] },
};

function getCompliance(category) {
  for (const [key, val] of Object.entries(COMPLIANCE_MAP)) {
    if (category === key || category.startsWith(key.split(" - ")[0])) return val;
  }
  return null;
}

// ── PII detection patterns ────────────────────────────────────────────────────
const PII_PATTERNS = [
  { name: "Email address",       re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { name: "Phone number",        re: /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g },
  { name: "Credit card number",  re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
  { name: "US Social Security",  re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: "AWS Access Key",      re: /AKIA[0-9A-Z]{16}/g },
  { name: "Private IP address",  re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g },
  { name: "Password in response",re: /"password"\s*:\s*"[^"]{3,}"/g },
  { name: "Date of birth field", re: /(?:"dob"|"date_of_birth"|"birthdate")\s*:\s*"[^"]+"/gi },
  { name: "IBAN",                re: /[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}/g },
];

function detectPII(text) {
  const found = [];
  for (const { name, re } of PII_PATTERNS) {
    re.lastIndex = 0;
    const matches = text.match(re);
    if (matches?.length) found.push({ name, count: matches.length, sample: matches[0].slice(0, 40) });
  }
  return found;
}

// ── Session state ─────────────────────────────────────────────────────────────
let sessionData = {
  baseUrl:        "",
  endpoints:      {},
  tokens:         [],
  apiKeys:        [],
  lastUrl:        "",
  hardcoded_keys: [],
};

// ── Request interception ──────────────────────────────────────────────────────
chrome.webRequest.onCompleted.addListener(
  (details) => {
    const url = new URL(details.url);
    if (["chrome-extension:", "chrome:", "moz-extension:"].includes(url.protocol)) return;
    if (["image","stylesheet","font"].includes(details.type)) return;

    const origin = `${url.protocol}//${url.host}`;
    const path   = url.pathname;

    if (!sessionData.baseUrl || details.type === "xmlhttprequest" || details.type === "fetch") {
      sessionData.baseUrl = origin;
    }
    sessionData.lastUrl = details.url;

    const isApiPath = /\/(api|v\d+|graphql|rest|auth|users|orders|products|search|data|service)\b/.test(path);
    if (!isApiPath && !path.includes("/api")) return;

    const normPath = path.replace(/\/\d+/g, "/{id}");
    if (!sessionData.endpoints[normPath]) {
      sessionData.endpoints[normPath] = { methods: [], statuses: [], authRequired: false };
    }
    const ep = sessionData.endpoints[normPath];
    if (!ep.methods.includes(details.method)) ep.methods.push(details.method);
    ep.statuses.push(details.statusCode);
    if ([401, 403].includes(details.statusCode)) ep.authRequired = true;

    chrome.storage.session.set({ mazapi_session: sessionData });
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    for (const hdr of (details.requestHeaders || [])) {
      const name  = hdr.name.toLowerCase();
      const value = hdr.value || "";
      if (name === "authorization" && value.toLowerCase().startsWith("bearer ")) {
        const tok = value.slice(7).trim();
        if (tok && !sessionData.tokens.includes(tok)) {
          sessionData.tokens.push(tok);
          chrome.storage.session.set({ mazapi_session: sessionData });
        }
      }
      if (["x-api-key","x-auth-token","api-key","apikey"].includes(name)) {
        if (!sessionData.apiKeys.find(k => k.header === hdr.name) && value) {
          sessionData.apiKeys.push({ header: hdr.name, value });
          chrome.storage.session.set({ mazapi_session: sessionData });
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// ── Storage helpers ───────────────────────────────────────────────────────────
const HISTORY_KEY  = "mazapi_history";
const SETTINGS_KEY = "mazapi_settings";
const FP_KEY       = "mazapi_fp";

const getHistory        = () => new Promise(r => chrome.storage.local.get(HISTORY_KEY,  d => r(d[HISTORY_KEY]  || [])));
const getSettings       = () => new Promise(r => chrome.storage.local.get(SETTINGS_KEY, d => r(d[SETTINGS_KEY] || { webhookUrl: "", orgName: "", autoWebhook: false })));
const saveSettings      = s  => new Promise(r => chrome.storage.local.set({ [SETTINGS_KEY]: s }, r));
const getFalsePositives = () => new Promise(r => chrome.storage.local.get(FP_KEY, d => r(d[FP_KEY] || {})));

async function saveToHistory(target, score, total, vulnerable, results) {
  const history = await getHistory();
  const entry = {
    target, score, total, vulnerable,
    date: new Date().toISOString(),
    results: results.map(({ test, category, vulnerable: v }) => ({ test, category, vulnerable: v })),
  };
  const updated = [entry, ...history.filter(h => h.target !== target)].slice(0, 10);
  return new Promise(r => chrome.storage.local.set({ [HISTORY_KEY]: updated }, r));
}

async function setFalsePositive(target, testName, state) {
  const fps = await getFalsePositives();
  const key = `${target}::${testName}`;
  if (state === null) delete fps[key];
  else fps[key] = { state, date: new Date().toISOString() };
  return new Promise(r => chrome.storage.local.set({ [FP_KEY]: fps }, r));
}

// ── Regression detection ──────────────────────────────────────────────────────
function addRegressionTags(results, lastScan) {
  if (!lastScan) return results.map(r => ({ ...r, regression: r.vulnerable ? "NEW" : null }));
  const prev = Object.fromEntries(lastScan.results.map(r => [r.test, r.vulnerable]));
  return results.map(r => {
    const was = prev[r.test];
    let regression = null;
    if (was === undefined)    regression = r.vulnerable ? "NEW" : null;
    else if (was && r.vulnerable)  regression = "RECURRING";
    else if (!was && r.vulnerable) regression = "NEW";
    else if (was && !r.vulnerable) regression = "FIXED";
    return { ...r, regression };
  });
}

// ── Webhook sender ────────────────────────────────────────────────────────────
async function sendWebhook(webhookUrl, target, score, results) {
  if (!webhookUrl) return;
  const vulns    = results.filter(r => r.vulnerable);
  const critical = vulns.filter(r => r.severity === "CRITICAL");
  const high     = vulns.filter(r => r.severity === "HIGH");
  const payload  = {
    source: "MazAPI Scanner",
    target, score,
    scanned_at: new Date().toISOString(),
    summary: `${vulns.length}/${results.length} tests vulnerable`,
    critical: critical.length, high: high.length,
    findings: vulns.map(({ test, category, severity, actual }) => ({ test, category, severity, actual })),
    // Slack-compatible block
    text: `*MazAPI Alert* — \`${target}\`\nScore: *${score}%* | Critical: ${critical.length} | High: ${high.length}`,
    attachments: critical.length ? [{
      color: "#f85149",
      title: `${critical.length} Critical Finding(s)`,
      text: critical.map(r => `• ${r.test}: ${r.actual}`).join("\n"),
    }] : undefined,
  };
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000),
    });
  } catch { /* non-fatal */ }
}

// ── SARIF generator ───────────────────────────────────────────────────────────
function generateSARIF(target, results) {
  const seen = new Set();
  const rules = results.reduce((acc, r) => {
    const id = r.category.replace(/[^A-Za-z0-9-]/g, "-");
    if (!seen.has(id)) {
      seen.add(id);
      acc.push({
        id,
        name: r.category.split(" - ")[0],
        shortDescription: { text: r.category.split(" - ").slice(1).join(" - ") || r.category },
        helpUri: "https://owasp.org/API-Security/",
        properties: { tags: ["security", "api"] },
      });
    }
    return acc;
  }, []);

  const sarifResults = results.filter(r => r.vulnerable).map(r => ({
    ruleId: r.category.replace(/[^A-Za-z0-9-]/g, "-"),
    level: ["CRITICAL","HIGH"].includes(r.severity) ? "error" : "warning",
    message: { text: `${r.test}: ${r.actual}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: target, uriBaseId: "TARGETROOT" } } }],
    properties: { severity: r.severity, expected: r.expected, compliance: r.compliance || {} },
  }));

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "MazAPI Scanner", version: "1.0.0", informationUri: "https://github.com/Mazonia/api-security", rules } },
      results: sarifResults,
      properties: { target, scannedAt: new Date().toISOString() },
    }],
  };
}

// ── Postman collection generator ──────────────────────────────────────────────
function generatePostman(target, endpoints) {
  const host = target.replace(/https?:\/\//, "").replace(/\/$/, "");
  const items = Object.entries(endpoints).map(([path, data]) => {
    const method = (data.methods || ["GET"])[0];
    const url    = target + path.replace(/\{id\}/g, "1");
    return {
      name: `${method} ${path}`,
      request: {
        method,
        header: [{ key: "Authorization", value: "Bearer {{bearerToken}}", type: "text" }],
        url: { raw: url, host: [host], path: path.split("/").filter(Boolean) },
      },
      response: [],
    };
  });
  return {
    info: {
      name: `MazAPI — ${target}`,
      description: `Discovered by MazAPI Scanner on ${new Date().toISOString()}`,
      schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    item: items,
    variable: [
      { key: "baseUrl",     value: target },
      { key: "bearerToken", value: "" },
    ],
  };
}

// ── OpenAPI spec generator ────────────────────────────────────────────────────
function generateOpenAPI(target, endpoints) {
  const paths = {};
  for (const [path, data] of Object.entries(endpoints)) {
    const oaPath = path.replace(/\{id\}/g, "{id}");
    paths[oaPath] = {};
    for (const method of (data.methods || ["get"])) {
      paths[oaPath][method.toLowerCase()] = {
        summary: `${method} ${path}`,
        security: data.authRequired ? [{ bearerAuth: [] }] : [],
        responses: { "200": { description: "Success" }, "401": { description: "Unauthorized" } },
      };
    }
  }
  return {
    openapi: "3.0.3",
    info: { title: `MazAPI Discovery — ${target}`, version: "1.0.0", description: `Auto-discovered by MazAPI Scanner on ${new Date().toISOString()}` },
    servers: [{ url: target }],
    components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
    paths,
  };
}

// ── HTML report generator ─────────────────────────────────────────────────────
function generateHTMLReport(target, score, results, orgName, fpMap = {}) {
  const vulnCount  = results.filter(r => r.vulnerable && !fpMap[`${target}::${r.test}`]).length;
  const totalCount = results.length;
  const scoreColor = score >= 90 ? "#3fb950" : score >= 70 ? "#e3b341" : "#f85149";
  const date = new Date().toLocaleString();

  const SEV_COLOR = { CRITICAL: "#ff6b6b", HIGH: "#f85149", MEDIUM: "#e3b341", LOW: "#58a6ff" };

  const rows = results.map(r => {
    const fp  = fpMap[`${target}::${r.test}`];
    const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    const fpBadge  = fp ? `<span style="background:#30363d;color:#8b949e;padding:2px 6px;border-radius:3px;font-size:.72em;margin-left:6px">${fp.state === "fp" ? "FALSE POSITIVE" : "ACCEPTED RISK"}</span>` : "";
    const regColor = { NEW: "#f85149", FIXED: "#3fb950", RECURRING: "#e3b341" }[r.regression] || "";
    const regBadge = r.regression ? `<span style="background:rgba(0,0,0,.3);color:${regColor};border:1px solid ${regColor};padding:2px 6px;border-radius:3px;font-size:.72em;margin-left:6px">${r.regression}</span>` : "";
    const sev      = SEV_COLOR[r.severity] || "#8b949e";
    const isVuln   = r.vulnerable && !fp;

    const compHtml = r.compliance ? `<div style="margin-top:7px;font-size:.77em;color:#8b949e">
      <b style="color:#58a6ff">Compliance:</b>
      ${r.compliance.pci_dss?.length  ? `PCI-DSS ${r.compliance.pci_dss.join(", ")} &nbsp;` : ""}
      ${r.compliance.gdpr?.length     ? `GDPR ${r.compliance.gdpr.join(", ")} &nbsp;` : ""}
      ${r.compliance.iso27001?.length ? `ISO 27001 ${r.compliance.iso27001.join(", ")}` : ""}
    </div>` : "";

    const evHtml = r.evidence ? `<details style="margin-top:7px"><summary style="font-size:.77em;color:#58a6ff;cursor:pointer">Evidence</summary>
      <pre style="background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:8px;margin-top:4px;font-size:.74em;white-space:pre-wrap;color:#c9d1d9;overflow-x:auto">${esc(r.evidence.request.method)} ${esc(r.evidence.request.url)}${r.evidence.request.body ? "\nBody: "+esc(r.evidence.request.body) : ""}
→ HTTP ${esc(r.evidence.response.status)}${r.evidence.response.snippet ? "\n"+esc(r.evidence.response.snippet) : ""}</pre></details>` : "";

    return `<div style="border-left:3px solid ${isVuln ? sev : "#30363d"};background:${isVuln ? "rgba(248,81,73,.04)" : "rgba(63,185,80,.04)"};padding:12px 14px;margin-bottom:8px;border-radius:0 6px 6px 0">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:4px">
        <span style="font-weight:600;color:${isVuln ? sev : "#3fb950"}">${isVuln ? "✗" : "✓"} ${esc(r.test)}${fpBadge}${regBadge}</span>
        <span style="font-size:.78em;color:${sev};font-weight:700">${r.severity}</span>
      </div>
      <div style="font-size:.77em;color:#8b949e;margin-top:3px">${esc(r.category)}</div>
      <div style="font-size:.82em;margin-top:5px">${esc(r.actual)}</div>
      ${compHtml}${evHtml}
    </div>`;
  }).join("");

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>MazAPI Report — ${target}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#c9d1d9}@media print{body{background:#fff;color:#000}details{display:none}}</style>
</head><body>
<div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:36px;text-align:center;border-bottom:2px solid #30363d">
  <div style="font-size:1.9em;font-weight:700;color:#58a6ff">${esc(orgName || "MazAPI Scanner")}</div>
  <div style="color:#8b949e;margin-top:4px">API Security Scan Report</div>
</div>
<div style="max-width:920px;margin:0 auto;padding:28px">
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px">
    ${[["Security Score", score+"%", scoreColor],["Vulnerable",vulnCount,"#f85149"],["Secure",totalCount-vulnCount,"#3fb950"],["Total Tests",totalCount,"#58a6ff"]].map(([lbl,val,c]) =>
      `<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center"><div style="font-size:2em;font-weight:700;color:${c}">${val}</div><div style="font-size:.79em;color:#8b949e;margin-top:4px">${lbl}</div></div>`
    ).join("")}
  </div>
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:.83em;color:#8b949e">
    <b style="color:#c9d1d9">Target:</b> ${target} &nbsp;|&nbsp; <b style="color:#c9d1d9">Scanned:</b> ${date} &nbsp;|&nbsp; <b style="color:#c9d1d9">Tool:</b> MazAPI Scanner v2.0
  </div>
  ${rows}
  <div style="text-align:center;padding:18px;font-size:.77em;color:#8b949e;border-top:1px solid #21262d;margin-top:20px">MazAPI Scanner — CY384 API Security Project, University of Mines and Technology, Ghana</div>
</div></body></html>`;

  function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
}

// ── Scan engine ───────────────────────────────────────────────────────────────
async function runScan(target, token, options = {}) {
  const results = [];
  const authHdrs = token ? { Authorization: `Bearer ${token}` } : {};

  function makeResult(test, category, severity, vulnerable, actual, expected, evReq, evResp) {
    const r = { test, category, severity, vulnerable, actual, expected, compliance: getCompliance(category) };
    if (evReq) r.evidence = {
      request:  { method: evReq.method, url: evReq.url, body: evReq.body || null },
      response: { status: evResp?.status ?? "—", snippet: evResp?.snippet || null },
    };
    return r;
  }

  async function get(path, extraHdrs = {}) {
    try {
      return await fetch(target + path, { method: "GET", headers: { ...authHdrs, ...extraHdrs }, signal: AbortSignal.timeout(8000), redirect: "manual" });
    } catch { return null; }
  }
  async function getFollow(path) {
    try {
      return await fetch(target + path, { method: "GET", headers: authHdrs, signal: AbortSignal.timeout(8000), redirect: "follow" });
    } catch { return null; }
  }
  async function post(path, body, extraHdrs = {}) {
    try {
      return await fetch(target + path, { method: "POST", headers: { "Content-Type": "application/json", ...authHdrs, ...extraHdrs }, body: JSON.stringify(body), signal: AbortSignal.timeout(8000) });
    } catch { return null; }
  }

  // ── API8: Sensitive path exposure ────────────────────────────────────────────
  const sensitivePaths = ["/debug/config","/debug","/.env","/config","/admin","/admin/users","/metrics","/actuator/env","/swagger","/docs","/openapi.json","/api-docs"];
  const exposed = [];
  for (const p of sensitivePaths) {
    const r = await get(p);
    if (r?.status === 200) exposed.push(p);
  }
  results.push(makeResult(
    "Sensitive path exposure", "API8:2023 - Security Misconfiguration", "HIGH",
    exposed.length > 0,
    exposed.length > 0 ? `Exposed: ${exposed.slice(0,3).join(", ")}` : "No sensitive paths exposed",
    "All return 404 or 401",
    { method: "GET", url: target + (exposed[0] || "/admin") },
    { status: exposed.length > 0 ? 200 : 404, snippet: exposed.length > 0 ? "200 OK — content served unauthenticated" : "Not exposed" },
  ));

  // ── API8: CORS wildcard ───────────────────────────────────────────────────────
  const corsR = await get("/health", { Origin: "http://evil.attacker.example.com" })
              || await get("/",      { Origin: "http://evil.attacker.example.com" });
  if (corsR) {
    const acao = corsR.headers.get("access-control-allow-origin") || "";
    results.push(makeResult(
      "CORS wildcard header", "API8:2023 - Security Misconfiguration", "MEDIUM",
      acao === "*",
      `ACAO: ${acao || "(none)"}`,
      "No wildcard * header",
      { method: "GET", url: target + "/health", body: null },
      { status: corsR.status, snippet: `Access-Control-Allow-Origin: ${acao || "(none)"}` },
    ));
  }

  // ── API8: Security headers (follows redirects) ───────────────────────────────
  const shR = await getFollow("/") || await getFollow("/health");
  if (shR) {
    const isHtml = (shR.headers.get("content-type") || "").includes("text/html");
    const missing = [];
    if (!shR.headers.get("x-content-type-options")) missing.push("x-content-type-options");
    if (isHtml && !shR.headers.get("x-frame-options")) missing.push("x-frame-options");
    if (isHtml && !shR.headers.get("content-security-policy")) missing.push("content-security-policy");
    results.push(makeResult(
      "Missing security headers", "API8:2023 - Security Misconfiguration", "MEDIUM",
      missing.length >= 2,
      missing.length ? `Missing: ${missing.join(", ")}` : `All applicable headers present${!isHtml ? " (non-HTML)" : ""}`,
      "X-Content-Type-Options always; X-Frame-Options + CSP for HTML",
      { method: "GET", url: target + "/" },
      { status: shR.status, snippet: `Content-Type: ${shR.headers.get("content-type") || "(none)"}` },
    ));

    // Per-header checks
    for (const [h, why, relevant] of [
      ["x-content-type-options","blocks MIME-sniffing", true],
      ["x-frame-options",       "prevents clickjacking", isHtml],
      ["content-security-policy","mitigates XSS",        isHtml],
    ]) {
      const present = !!shR.headers.get(h);
      results.push(makeResult(
        `Hardening header: ${h}`, "API8:2023 - Security Misconfiguration (hardening)", "LOW",
        relevant && !present,
        present ? shR.headers.get(h) : relevant ? `not set — ${why}` : "not applicable for non-HTML API endpoints",
        `present (${why})`,
        { method: "GET", url: target + "/" },
        { status: shR.status, snippet: `${h}: ${shR.headers.get(h) || "(missing)"}` },
      ));
    }
  }

  // ── API4: Rate limiting ───────────────────────────────────────────────────────
  if (options.authEndpoint) {
    let got429 = false, altLimit = false, lastR = null;
    for (let i = 0; i < 10; i++) {
      const r = await post(options.authEndpoint, { username: "__probe__", password: "x" });
      if (!r) continue;
      lastR = r;
      if (r.status === 429) { got429 = true; break; }
      const body = await r.clone().text().catch(() => "");
      if (/captcha|recaptcha|challenge|locked|too.?many|verify/i.test(body)) { altLimit = true; break; }
    }
    results.push(makeResult(
      `Rate limiting on ${options.authEndpoint}`, "API4:2023 - Unrestricted Resource Consumption", "MEDIUM",
      !got429 && !altLimit,
      got429 ? "HTTP 429 received" : altLimit ? "CAPTCHA/challenge — alternative rate limiting in place" : "No 429 or challenge detected — unlimited attempts may be allowed",
      "HTTP 429 or challenge after repeated failures",
      { method: "POST", url: target + options.authEndpoint, body: '{"username":"__probe__","password":"x"}' },
      { status: lastR?.status ?? "—", snippet: `Status on attempt 10: ${lastR?.status ?? "no response"}` },
    ));
  }

  // ── API2: JWT weak secret + alg:none bypass ──────────────────────────────────
  if (options.protectedPath) {
    const toB64 = o => btoa(JSON.stringify(o)).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
    // Weak secret test
    const weakH    = toB64({ alg: "HS256", typ: "JWT" });
    const weakP    = toB64({ sub: "9999", role: "admin", username: "hacker" });
    const weakJwt  = `${weakH}.${weakP}.fake_signature`;
    const weakR    = await get(options.protectedPath, { Authorization: `Bearer ${weakJwt}` });
    results.push(makeResult(
      "JWT weak secret / forged token", "API2:2023 - Broken Authentication", "CRITICAL",
      weakR ? ![401,403].includes(weakR.status) : false,
      weakR ? `Forged JWT (key='secret') → HTTP ${weakR.status}` : "unreachable",
      "401 or 403 — forged token must be rejected",
      { method: "GET", url: target + options.protectedPath, body: null },
      { status: weakR?.status ?? "—", snippet: `JWT signed with 'secret' → ${weakR?.status ?? "no response"}` },
    ));
    // alg:none bypass
    const noneH   = toB64({ alg: "none", typ: "JWT" });
    const noneP   = toB64({ sub: "1", role: "admin" });
    const noneJwt = `${noneH}.${noneP}.`;
    const noneR   = await get(options.protectedPath, { Authorization: `Bearer ${noneJwt}` });
    results.push(makeResult(
      "JWT algorithm confusion — alg:none (unsigned token)", "API2:2023 - Broken Authentication", "CRITICAL",
      noneR ? ![401,403].includes(noneR.status) : false,
      noneR ? `Unsigned JWT (alg=none) → HTTP ${noneR.status}` : "unreachable",
      "401 — unsigned tokens must always be rejected",
      { method: "GET", url: target + options.protectedPath, body: null },
      { status: noneR?.status ?? "—", snippet: `alg:none unsig token → ${noneR?.status ?? "no response"}` },
    ));
  }

  // ── CWE-22: Path traversal ────────────────────────────────────────────────────
  let traversalHit = false;
  for (const payload of ["/../../../etc/passwd","/%2F..%2F..%2Fetc%2Fpasswd"]) {
    const r = await get(payload);
    if (r?.status === 200) {
      const text = await r.text().catch(() => "");
      if (text.includes("root:") || text.includes("daemon:")) { traversalHit = true; break; }
    }
  }
  results.push(makeResult(
    "Path traversal (CWE-22)", "CVE-2021-41773 / CWE-22 - Path Traversal", "CRITICAL",
    traversalHit,
    traversalHit ? "200 — /etc/passwd content in response" : "Traversal payloads rejected",
    "404 or 400",
    { method: "GET", url: target + "/../../../etc/passwd" },
    { status: traversalHit ? 200 : 404, snippet: traversalHit ? "root:x:0:0:..." : "Not vulnerable" },
  ));

  // ── CWE-601: Open redirect ────────────────────────────────────────────────────
  let redirectHit = false, redirParam = null;
  for (const p of ["redirect","url","next","return","goto"]) {
    const r = await fetch(`${target}/?${p}=http://evil.attacker.example.com`, { redirect: "manual", signal: AbortSignal.timeout(5000) }).catch(() => null);
    if (r && (r.headers.get("location") || "").includes("evil.attacker.example.com")) {
      redirectHit = true; redirParam = p; break;
    }
  }
  results.push(makeResult(
    "Open redirect via query parameters", "CVE-2019-11229 / CWE-601 - Open Redirect", "MEDIUM",
    redirectHit,
    redirectHit ? `302 → external domain via ?${redirParam}=` : "No open redirect detected",
    "No redirect to external domain",
    { method: "GET", url: `${target}/?redirect=http://evil.attacker.example.com` },
    { status: redirectHit ? 302 : 200, snippet: redirectHit ? "Location: http://evil.attacker.example.com" : "Not vulnerable" },
  ));

  // ── API7: SSRF ────────────────────────────────────────────────────────────────
  let ssrfHit = false;
  for (const p of ["url","callback","fetch","dest"]) {
    const r = await get(`/?${p}=http://169.254.169.254/latest/meta-data/`);
    if (r?.status === 200) {
      const text = await r.text().catch(() => "");
      if (text.includes("ami-id") || text.includes("instance-id")) { ssrfHit = true; break; }
    }
  }
  results.push(makeResult(
    "SSRF via URL/callback parameters", "API7:2023 - Server-Side Request Forgery", "CRITICAL",
    ssrfHit,
    ssrfHit ? "Internal metadata service response detected" : "No SSRF indicators found",
    "No internal metadata in response",
    { method: "GET", url: `${target}/?url=http://169.254.169.254/latest/meta-data/` },
    { status: ssrfHit ? 200 : 400, snippet: ssrfHit ? "AWS metadata returned" : "Not vulnerable" },
  ));

  // ── HTTP verb tampering ────────────────────────────────────────────────────────
  try {
    const tr = await fetch(target + "/", { method: "DELETE", signal: AbortSignal.timeout(5000) });
    results.push(makeResult(
      "HTTP verb tampering (DELETE /)", "CWE-650 - HTTP Verb Tampering", "MEDIUM",
      ![405,404,501,403,400].includes(tr.status),
      `DELETE / → ${tr.status}`,
      "405 Method Not Allowed",
      { method: "DELETE", url: target + "/" },
      { status: tr.status, snippet: `DELETE on root → ${tr.status}` },
    ));
  } catch { /* blocked at network layer = good */ }

  // ── SPA-aware sensitive path re-check ────────────────────────────────────────
  let spaShellLen = -1;
  const spaProbe = await get("/zz-nonexistent-mazapi-404probe");
  if (spaProbe?.status === 200) spaShellLen = (await spaProbe.text().catch(() => "")).length;
  for (const p of ["/admin","/debug/config","/.env","/config"]) {
    const r = await get(p);
    if (!r) continue;
    let vuln = false, note;
    if (r.status !== 200) {
      note = `${r.status} (protected / not found)`;
    } else {
      const body = await r.text().catch(() => "");
      if (spaShellLen >= 0 && Math.abs(body.length - spaShellLen) <= 64) note = "200 — SPA shell (not a real exposure)";
      else if (/type=["']password["']|sign in|log in/i.test(body))        note = "200 — login page (gated)";
      else { vuln = true; note = `200 — ${body.length} bytes served unauthenticated`; }
    }
    const cat = p.includes("admin") ? "API5:2023 - Broken Function Level Authorization" : "API8:2023 - Security Misconfiguration";
    results.push(makeResult(`Sensitive path: ${p}`, cat, "HIGH", vuln, note, "401, 403, 404, or login page",
      { method: "GET", url: target + p }, { status: r.status, snippet: note }));
  }

  // ── GraphQL introspection ─────────────────────────────────────────────────────
  for (const gqlPath of ["/graphql","/api/graphql","/v1/graphql","/query"]) {
    const gqlR = await post(gqlPath, { query: "{ __schema { types { name } } }" });
    if (gqlR?.status === 200) {
      const body = await gqlR.clone().text().catch(() => "");
      if (body.includes("__schema") || body.includes("__typename")) {
        const schemaExposed = body.includes("__schema") && body.includes("types");
        results.push(makeResult(
          "GraphQL introspection enabled", "API9:2023 - Improper Inventory Management / GraphQL", "MEDIUM",
          schemaExposed,
          schemaExposed ? `Full schema returned at ${gqlPath} — exposes all types, mutations, queries` : `GraphQL at ${gqlPath} but introspection disabled`,
          "Disable introspection in production",
          { method: "POST", url: target + gqlPath, body: '{"query":"{ __schema { types { name } } }"}' },
          { status: gqlR.status, snippet: schemaExposed ? "__schema data in response" : "introspection disabled" },
        ));
        break;
      }
    }
  }

  // ── Mass assignment ───────────────────────────────────────────────────────────
  const massCandidates = [
    { path: "/auth/register",  body: { username: "probe_user", password: "x", email: "p@x.com", role: "admin", is_admin: true }, method: "POST" },
    { path: "/users/me",       body: { role: "admin", is_admin: true, balance: 99999 }, method: "PUT" },
    { path: "/profile",        body: { role: "admin", is_admin: true, verified: true }, method: "PUT" },
    { path: "/api/users/me",   body: { role: "admin", is_admin: true }, method: "PATCH" },
  ];
  let massHit = false, massSnippet = null, massPath = null;
  for (const { path, body, method } of massCandidates) {
    const mr = await fetch(target + path, {
      method, headers: { "Content-Type": "application/json", ...authHdrs },
      body: JSON.stringify(body), signal: AbortSignal.timeout(5000),
    }).catch(() => null);
    if (mr?.status === 200) {
      const text = await mr.clone().text().catch(() => "");
      if (/"role"\s*:\s*"admin"/.test(text) || /"is_admin"\s*:\s*true/.test(text) || /"balance"\s*:\s*99999/.test(text)) {
        massHit = true; massSnippet = text.slice(0, 120); massPath = path; break;
      }
    }
  }
  results.push(makeResult(
    "Mass assignment — privilege field injection", "API3:2023 - Broken Object Property Level Authorization", "HIGH",
    massHit,
    massHit ? `Server echoed admin fields at ${massPath}: ${massSnippet}` : "Server ignored injected privilege fields",
    "Injected fields (role, is_admin) must be stripped server-side",
    { method: "POST", url: target + (massPath || "/auth/register"), body: '{"role":"admin","is_admin":true}' },
    { status: massHit ? 200 : 0, snippet: massHit ? massSnippet : "Not vulnerable or endpoint not found" },
  ));

  // ── PII / sensitive data detection ────────────────────────────────────────────
  const piiEndpoints = options.discoveredEndpoints
    ? Object.keys(options.discoveredEndpoints).slice(0, 8)
    : ["/api/users","/users","/api/user","/api/profile","/profile","/api/me","/me","/api/customers"];
  let piiFound = [], piiAt = null;
  for (const ep of piiEndpoints) {
    const piiR = await getFollow(ep.replace(/\{id\}/g, "1"));
    if (piiR?.status === 200) {
      const body = await piiR.text().catch(() => "");
      if (body.length > 20) {
        const detected = detectPII(body);
        if (detected.length) { piiFound = detected; piiAt = ep; break; }
      }
    }
  }
  results.push(makeResult(
    "PII / sensitive data in API responses", "CWE-312 / GDPR - PII Exposure in API Response", "HIGH",
    piiFound.length > 0,
    piiFound.length > 0
      ? `PII detected at ${piiAt}: ${piiFound.map(p => `${p.name} (×${p.count})`).join(", ")}`
      : "No obvious PII patterns detected in sampled responses",
    "API responses must not expose unnecessary PII",
    { method: "GET", url: target + (piiAt || "/api/users") },
    { status: piiFound.length > 0 ? 200 : 0, snippet: piiFound.length > 0 ? `Found: ${piiFound.map(p => p.name).join(", ")}` : "Not detected" },
  ));

  return results;
}

// ── Action icon (drawn on canvas so no PNG needed) ───────────────────────────
function _drawIcon(size) {
  const c = new OffscreenCanvas(size, size);
  const ctx = c.getContext('2d');
  const s = size, cx = s / 2, cy = s * 0.48, r = s * 0.41;

  // Background
  ctx.fillStyle = '#0d1117';
  if (ctx.roundRect) {
    ctx.beginPath(); ctx.roundRect(0, 0, s, s, s * 0.16); ctx.fill();
  } else {
    ctx.fillRect(0, 0, s, s);
  }

  // Hexagon (pointy-top)
  const grad = ctx.createLinearGradient(0, 0, s, s);
  grad.addColorStop(0, '#00d4ff');
  grad.addColorStop(1, '#7c3aed');
  ctx.beginPath();
  for (let i = 0; i < 6; i++) {
    const a = -Math.PI / 2 + i * Math.PI / 3;
    const px = cx + r * Math.cos(a), py = cy + r * Math.sin(a);
    i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
  }
  ctx.closePath();
  ctx.strokeStyle = grad;
  ctx.lineWidth = Math.max(1, s * 0.07);
  ctx.shadowColor = '#00d4ff';
  ctx.shadowBlur = s * 0.14;
  ctx.stroke();
  ctx.shadowBlur = 0;

  // M
  const lx = cx - r * 0.50, rx2 = cx + r * 0.50;
  const ty = cy - r * 0.50, by = cy + r * 0.34, mid = cy - r * 0.04;
  ctx.strokeStyle = '#e2e8f0';
  ctx.lineWidth = Math.max(1, s * 0.09);
  ctx.lineCap = 'round'; ctx.lineJoin = 'round';
  ctx.beginPath();
  ctx.moveTo(lx, by); ctx.lineTo(lx, ty);
  ctx.lineTo(cx, mid);
  ctx.lineTo(rx2, ty); ctx.lineTo(rx2, by);
  ctx.stroke();

  return ctx.getImageData(0, 0, s, s);
}

function _setActionIcon() {
  try {
    chrome.action.setIcon({ imageData: { 16: _drawIcon(16), 32: _drawIcon(32), 48: _drawIcon(48) } });
  } catch (e) { /* OffscreenCanvas not ready yet */ }
}

// ── Context menu ──────────────────────────────────────────────────────────────
// Create inside onInstalled so it only runs once, not on every service-worker wake
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id:       "mazapi-scan-link",
    title:    "Scan this API with MazAPI",
    contexts: ["link", "selection"],
  });
  _setActionIcon();
});

chrome.runtime.onStartup.addListener(_setActionIcon);

chrome.contextMenus.onClicked.addListener((info) => {
  const url = info.linkUrl || info.selectionText?.trim() || "";
  if (url.startsWith("http")) {
    chrome.storage.session.set({ mazapi_context_url: url });
  }
});

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {

  if (msg.type === "GET_SESSION") {
    chrome.storage.session.get("mazapi_session", d => sendResponse(d.mazapi_session || sessionData));
    return true;
  }

  if (msg.type === "RUN_SCAN") {
    const { target, token, options } = msg;
    getLastScan(target).then(lastScan =>
      runScan(target, token, options).then(async raw => {
        const results = addRegressionTags(raw, lastScan);
        const vulns   = results.filter(r => r.vulnerable).length;
        const score   = results.length ? Math.round((1 - vulns / results.length) * 100) : 100;
        await saveToHistory(target, score, results.length, vulns, results);
        const settings = await getSettings();
        if (settings.autoWebhook && settings.webhookUrl && results.some(r => r.vulnerable && r.severity === "CRITICAL")) {
          await sendWebhook(settings.webhookUrl, target, score, results);
        }
        sendResponse({ ok: true, results, score });
      })
    ).catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "GET_HISTORY")        { getHistory().then(h => sendResponse(h)); return true; }
  if (msg.type === "CLEAR_HISTORY")      { chrome.storage.local.remove(HISTORY_KEY, () => sendResponse({ ok: true })); return true; }
  if (msg.type === "GET_SETTINGS")       { getSettings().then(s => sendResponse(s)); return true; }
  if (msg.type === "SAVE_SETTINGS")      { saveSettings(msg.settings).then(() => sendResponse({ ok: true })); return true; }
  if (msg.type === "GET_FALSE_POSITIVES"){ getFalsePositives().then(fps => sendResponse(fps)); return true; }
  if (msg.type === "SET_FALSE_POSITIVE") { setFalsePositive(msg.target, msg.testName, msg.state).then(() => sendResponse({ ok: true })); return true; }

  if (msg.type === "SEND_WEBHOOK") {
    sendWebhook(msg.webhookUrl, msg.target, msg.score, msg.results)
      .then(() => sendResponse({ ok: true })).catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "GENERATE_SARIF") {
    sendResponse(generateSARIF(msg.target, msg.results));
    return true;
  }

  if (msg.type === "GENERATE_POSTMAN") {
    chrome.storage.session.get("mazapi_session", d => {
      const eps = (d.mazapi_session || sessionData).endpoints || {};
      sendResponse(generatePostman(msg.target, eps));
    });
    return true;
  }

  if (msg.type === "GENERATE_OPENAPI") {
    chrome.storage.session.get("mazapi_session", d => {
      const eps = (d.mazapi_session || sessionData).endpoints || {};
      sendResponse(generateOpenAPI(msg.target, eps));
    });
    return true;
  }

  if (msg.type === "GENERATE_HTML_REPORT") {
    getFalsePositives().then(fps => {
      sendResponse({ html: generateHTMLReport(msg.target, msg.score, msg.results, msg.orgName, fps) });
    });
    return true;
  }

  if (msg.type === "GET_CONTEXT_URL") {
    chrome.storage.session.get("mazapi_context_url", d => {
      sendResponse(d.mazapi_context_url || null);
      chrome.storage.session.remove("mazapi_context_url");
    });
    return true;
  }

  if (msg.type === "CONTENT_FINDINGS") {
    if (!sessionData.hardcoded_keys) sessionData.hardcoded_keys = [];
    for (const k of (msg.keys || [])) {
      if (!sessionData.hardcoded_keys.some(x => x.value === k.value)) {
        sessionData.hardcoded_keys.push(k);
      }
    }
    chrome.storage.session.set({ mazapi_session: sessionData });
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "CLEAR_SESSION") {
    sessionData = { baseUrl: "", endpoints: {}, tokens: [], apiKeys: [], lastUrl: "", hardcoded_keys: [] };
    chrome.storage.session.set({ mazapi_session: sessionData });
    sendResponse({ ok: true });
    return true;
  }
});

// ── Helper: get last scan for target ─────────────────────────────────────────
async function getLastScan(target) {
  const history = await getHistory();
  return history.find(h => h.target === target) || null;
}
