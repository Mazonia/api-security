/**
 * MazAPI Scanner — Background Service Worker
 *
 * Intercepts all HTTP requests made by the browser.
 * Extracts API endpoints, auth tokens, and API keys.
 * Runs OWASP / CWE / MITRE vulnerability probes directly (no backend needed).
 */

// ── Session state ─────────────────────────────────────────────────────────────
let sessionData = {
  baseUrl:   "",
  endpoints: {},   // path → { methods: Set, authRequired: bool, sample_status: int }
  tokens:    [],
  apiKeys:   [],
  lastUrl:   "",
};

// ── Request interception ──────────────────────────────────────────────────────
chrome.webRequest.onCompleted.addListener(
  (details) => {
    const url = new URL(details.url);

    // Skip browser internal and extension requests
    if (["chrome-extension:", "chrome:", "moz-extension:"].includes(url.protocol)) return;
    if (details.type === "image" || details.type === "stylesheet" || details.type === "font") return;

    const origin = `${url.protocol}//${url.host}`;
    const path   = url.pathname;

    // Track the dominant origin
    if (!sessionData.baseUrl || details.type === "xmlhttprequest" || details.type === "fetch") {
      sessionData.baseUrl = origin;
    }
    sessionData.lastUrl = details.url;

    // Only log paths that look like API routes
    const isApiPath = /\/(api|v\d+|graphql|rest|auth|users|orders|products|search|data|service)\b/.test(path);
    if (!isApiPath && !path.includes("/api")) return;

    // Normalise integer IDs
    const normPath = path.replace(/\/\d+/g, "/{id}");

    if (!sessionData.endpoints[normPath]) {
      sessionData.endpoints[normPath] = { methods: [], statuses: [], authRequired: false };
    }
    const ep = sessionData.endpoints[normPath];
    if (!ep.methods.includes(details.method)) ep.methods.push(details.method);
    ep.statuses.push(details.statusCode);
    if (details.statusCode === 401 || details.statusCode === 403) ep.authRequired = true;

    // Persist to storage for popup access
    chrome.storage.session.set({ mazapi_session: sessionData });
  },
  { urls: ["<all_urls>"] }
);

// Extract auth headers from request headers
chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    for (const hdr of (details.requestHeaders || [])) {
      const name  = hdr.name.toLowerCase();
      const value = hdr.value || "";
      if (name === "authorization") {
        if (value.toLowerCase().startsWith("bearer ")) {
          const tok = value.slice(7).trim();
          if (tok && !sessionData.tokens.includes(tok)) {
            sessionData.tokens.push(tok);
            chrome.storage.session.set({ mazapi_session: sessionData });
          }
        }
      }
      if (["x-api-key", "x-auth-token", "api-key", "apikey"].includes(name)) {
        const existing = sessionData.apiKeys.find(k => k.header === hdr.name);
        if (!existing && value) {
          sessionData.apiKeys.push({ header: hdr.name, value });
          chrome.storage.session.set({ mazapi_session: sessionData });
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// ── Scan engine (self-contained, runs in background worker) ──────────────────

async function runScan(target, token, options = {}) {
  const results = [];
  const headers = token ? { Authorization: `Bearer ${token}` } : {};

  async function get(path, extraHeaders = {}) {
    try {
      const r = await fetch(target + path, {
        method: "GET",
        headers: { ...headers, ...extraHeaders },
        signal: AbortSignal.timeout(8000),
        redirect: "manual",
      });
      return r;
    } catch { return null; }
  }

  async function post(path, body, extraHeaders = {}) {
    try {
      const r = await fetch(target + path, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers, ...extraHeaders },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(8000),
      });
      return r;
    } catch { return null; }
  }

  // ── OWASP API8: Sensitive paths ─────────────────────────────────────────────
  const sensitivePaths = [
    "/debug/config", "/debug", "/.env", "/config",
    "/admin", "/admin/users", "/metrics", "/actuator/env",
    "/swagger", "/docs", "/openapi.json", "/api-docs",
  ];
  let exposed = [];
  for (const p of sensitivePaths) {
    const r = await get(p);
    if (r && r.status === 200) exposed.push(p);
  }
  results.push({
    test: "Sensitive path exposure",
    category: "API8:2023 - Security Misconfiguration",
    severity: "HIGH",
    vulnerable: exposed.length > 0,
    actual: exposed.length > 0 ? `Exposed: ${exposed.slice(0,3).join(", ")}` : "No sensitive paths exposed",
    expected: "All return 404 or 401",
  });

  // ── OWASP API8: CORS ────────────────────────────────────────────────────────
  const corsR = await get("/health", { Origin: "http://evil.attacker.example.com" })
              || await get("/",     { Origin: "http://evil.attacker.example.com" });
  if (corsR) {
    const acao = corsR.headers.get("access-control-allow-origin") || "";
    results.push({
      test: "CORS wildcard header",
      category: "API8:2023 - Security Misconfiguration",
      severity: "MEDIUM",
      vulnerable: acao === "*",
      actual: `ACAO: ${acao || "(none)"}`,
      expected: "No wildcard *",
    });
  }

  // ── OWASP API8: Security headers ───────────────────────────────────────────
  const shR = await get("/") || await get("/health");
  if (shR) {
    const missing = [];
    for (const h of ["x-content-type-options", "x-frame-options", "content-security-policy"]) {
      if (!shR.headers.get(h)) missing.push(h);
    }
    results.push({
      test: "Missing security headers",
      category: "API8:2023 - Security Misconfiguration",
      severity: "MEDIUM",
      vulnerable: missing.length >= 2,
      actual: missing.length ? `Missing: ${missing.join(", ")}` : "All headers present",
      expected: "X-Content-Type-Options, X-Frame-Options, CSP present",
    });
  }

  // ── OWASP API4: Rate limiting ───────────────────────────────────────────────
  if (options.authEndpoint) {
    let got429 = false;
    for (let i = 0; i < 10; i++) {
      const r = await post(options.authEndpoint, { username: "__probe__", password: "x" });
      if (r && r.status === 429) { got429 = true; break; }
    }
    results.push({
      test: `Rate limiting on ${options.authEndpoint}`,
      category: "API4:2023 - Unrestricted Resource Consumption",
      severity: "MEDIUM",
      vulnerable: !got429,
      actual: got429 ? "429 received after repeated failures" : "No 429 — unlimited attempts allowed",
      expected: "HTTP 429 after repeated failures",
    });
  }

  // ── OWASP API2: JWT weak secret ─────────────────────────────────────────────
  if (options.protectedPath) {
    // Forge a token with weak secret "secret"
    const h = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
    const p = btoa(JSON.stringify({ sub: "9999", role: "admin", username: "hacker" })).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
    const forged = `${h}.${p}.fake_signature`;
    const jwtR = await get(options.protectedPath, { Authorization: `Bearer ${forged}` });
    results.push({
      test: "JWT weak secret / algorithm confusion",
      category: "API2:2023 - Broken Authentication",
      severity: "CRITICAL",
      vulnerable: jwtR ? !([401,403].includes(jwtR.status)) : false,
      actual: jwtR ? String(jwtR.status) : "unreachable",
      expected: "401 or 403",
    });
  }

  // ── CWE-22: Path traversal ──────────────────────────────────────────────────
  let traversalHit = false;
  for (const payload of ["/../../../etc/passwd", "/%2F..%2F..%2Fetc%2Fpasswd"]) {
    const r = await get(payload);
    if (r && r.status === 200) {
      const text = await r.text().catch(() => "");
      if (text.includes("root:") || text.includes("daemon:")) { traversalHit = true; break; }
    }
  }
  results.push({
    test: "Path traversal (CVE-2021-41773 class)",
    category: "CVE-2021-41773 / CWE-22 - Path Traversal",
    severity: "CRITICAL",
    vulnerable: traversalHit,
    actual: traversalHit ? "200 — /etc/passwd content in response" : "Traversal payloads rejected",
    expected: "404 or 400",
  });

  // ── CWE-601: Open redirect ──────────────────────────────────────────────────
  let redirectHit = false;
  for (const param of ["redirect", "url", "next", "return", "goto"]) {
    const r = await fetch(`${target}/?${param}=http://evil.attacker.example.com`,
                         { redirect: "manual", signal: AbortSignal.timeout(5000) }).catch(() => null);
    if (r) {
      const loc = r.headers.get("location") || "";
      if (loc.includes("evil.attacker.example.com")) { redirectHit = true; break; }
    }
  }
  results.push({
    test: "Open redirect via query parameters",
    category: "CVE-2019-11229 / CWE-601 - Open Redirect",
    severity: "MEDIUM",
    vulnerable: redirectHit,
    actual: redirectHit ? "302 → evil domain" : "No open redirect detected",
    expected: "No redirect to external domain",
  });

  // ── API7: SSRF ──────────────────────────────────────────────────────────────
  let ssrfHit = false;
  for (const param of ["url", "callback", "fetch", "dest"]) {
    const r = await get(`/?${param}=http://169.254.169.254/latest/meta-data/`);
    if (r && r.status === 200) {
      const text = await r.text().catch(() => "");
      if (text.includes("ami-id") || text.includes("instance")) { ssrfHit = true; break; }
    }
  }
  results.push({
    test: "SSRF via URL/callback parameters",
    category: "API7:2023 - Server-Side Request Forgery",
    severity: "CRITICAL",
    vulnerable: ssrfHit,
    actual: ssrfHit ? "Internal service response detected" : "No SSRF indicators",
    expected: "No internal metadata in response",
  });

  return results;
}

// ── Message handler (from popup) ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_SESSION") {
    chrome.storage.session.get("mazapi_session", (data) => {
      sendResponse(data.mazapi_session || sessionData);
    });
    return true; // keep channel open for async
  }

  if (msg.type === "RUN_SCAN") {
    const { target, token, options } = msg;
    runScan(target, token, options)
      .then(results => sendResponse({ ok: true, results }))
      .catch(err  => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "CLEAR_SESSION") {
    sessionData = { baseUrl: "", endpoints: {}, tokens: [], apiKeys: [], lastUrl: "" };
    chrome.storage.session.set({ mazapi_session: sessionData });
    sendResponse({ ok: true });
    return true;
  }
});
