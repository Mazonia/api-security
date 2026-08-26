#!/usr/bin/env python3
"""
Comparative security evaluation: run identical attack scenarios against both APIs
and produce a detailed side-by-side HTML + JSON report.

Usage (from project root, with containers running):
    python evaluate.py
    python evaluate.py --vulnerable http://localhost:8000 --hardened http://localhost:8001
"""
import argparse
import json
import os
import time
from datetime import datetime, timezone
from html import escape as _esc
from jinja2 import Template

try:
    import httpx
except ImportError:
    raise SystemExit("httpx required: pip install httpx")

try:
    from jose import jwt as jose_jwt
    _JOSE_OK = True
except ImportError:
    _JOSE_OK = False


# ── per-scenario metadata ──────────────────────────────────────────────────────

SCENARIO_DETAIL = {
    "API1-BOLA": {
        "owasp_id":      "API1:2023",
        "severity":      "HIGH",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "cves":          ["CVE-2019-14234", "CVE-2020-7927", "CVE-2021-21302"],
        "attack_payload":"GET /users/2  (authenticated as alice, user_id=1)",
        "vuln_reason":   "Returns HTTP 200 with Bob's full profile. The endpoint fetches records by path parameter with no ownership check — any authenticated user can read any account.",
        "hard_reason":   "Returns HTTP 403 Forbidden. A FastAPI dependency enforces user_id == current_user.id before the database query; cross-user access is rejected at the framework level.",
    },
    "API2-JWT": {
        "owasp_id":      "API2:2023",
        "severity":      "CRITICAL",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        "cves":          ["CVE-2018-1000531", "CVE-2022-21449", "CVE-2021-27958"],
        "attack_payload":'JWT forged with key="secret", sub="3", role="admin"  →  GET /admin/users',
        "vuln_reason":   "Returns HTTP 200. The signing key 'secret' is hard-coded in source; anyone with repository access can forge tokens for any identity, including admin, with no time limit.",
        "hard_reason":   "Returns HTTP 403. The signing key is loaded from JWT_SECRET env var (strong random value set at deploy time); the forged token signed with 'secret' fails HMAC verification.",
    },
    "API3-MASS": {
        "owasp_id":      "API3:2023",
        "severity":      "HIGH",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "cves":          ["CVE-2012-2676", "CVE-2022-32532", "CVE-2021-41079"],
        "attack_payload":'PUT /users/1  body: {"role": "admin", "balance": 999999}',
        "vuln_reason":   "Returns HTTP 200 and writes role='admin'. The input schema includes role and balance; all fields are passed directly to the ORM update with no allowlist.",
        "hard_reason":   "The role and balance fields are silently ignored. The hardened UserUpdate schema exposes only email and password; privilege fields are stripped server-side before the database call.",
    },
    "API4-RATELIMIT": {
        "owasp_id":      "API4:2023",
        "severity":      "MEDIUM",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "cves":          ["CVE-2019-11324", "CVE-2020-26258", "CVE-2021-25742"],
        "attack_payload":"POST /auth/login  ×10 rapid requests, wrong password each time",
        "vuln_reason":   "No HTTP 429 returned across all 10 requests. Unlimited login attempts are permitted, enabling brute-force and credential-stuffing attacks at full network speed.",
        "hard_reason":   "Returns HTTP 429 after 5 attempts. slowapi enforces a 5 requests/minute rate limit per IP on the login endpoint; further attempts are blocked until the window expires.",
    },
    "API5-FUNCAUTH": {
        "owasp_id":      "API5:2023",
        "severity":      "HIGH",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        "cves":          ["CVE-2021-41773", "CVE-2022-22947", "CVE-2020-14882"],
        "attack_payload":"GET /admin/users  (authenticated as alice, role='user')",
        "vuln_reason":   "Returns HTTP 200 with the full user database. The endpoint verifies a token is present but never checks the user's role; any logged-in account can invoke admin-only functions.",
        "hard_reason":   "Returns HTTP 403. A shared require_admin dependency verifies current_user.role == 'admin' before the handler executes; all other roles are rejected at the dependency level.",
    },
    "API8-DEBUG": {
        "owasp_id":      "API8:2023",
        "severity":      "MEDIUM",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "cves":          ["CVE-2021-44228", "CVE-2020-1938", "CVE-2019-0232"],
        "attack_payload":"GET /debug/config  (unauthenticated)",
        "vuln_reason":   "Returns HTTP 200 with the JWT signing secret, database URL, and full os.environ dump in plaintext. No authentication or environment guard is applied.",
        "hard_reason":   "Returns HTTP 404. The debug route is gated by ENV != 'production'; the hardened container sets ENV=hardened at startup, so the route does not exist at the application layer.",
    },
    "API8-CORS": {
        "owasp_id":      "API8:2023",
        "severity":      "LOW",
        "owasp_ref":     "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "cves":          ["CVE-2021-44228", "CVE-2020-1938", "CVE-2019-0232"],
        "attack_payload":"GET /health  with header: Origin: http://evil.com",
        "vuln_reason":   "Response includes Access-Control-Allow-Origin: *. Any web page on the internet can make credentialed cross-origin requests to this API, enabling CSRF-style data exfiltration.",
        "hard_reason":   "No wildcard ACAO header present. CORS is configured with an explicit origin allowlist via ALLOWED_ORIGINS env var; the Origin: evil.com header receives no cross-origin grant.",
    },
}

_SEV_CSS = {
    "CRITICAL": "background:rgba(188,30,30,.2);color:#ff6b6b;border:1px solid #ff6b6b",
    "HIGH":     "background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149",
    "MEDIUM":   "background:rgba(227,179,65,.15);color:#e3b341;border:1px solid #e3b341",
    "LOW":      "background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid #58a6ff",
}


# ── test functions ─────────────────────────────────────────────────────────────

def _login(base: str, username: str, password: str) -> str:
    try:
        r = httpx.post(f"{base}/auth/login",
                       json={"username": username, "password": password}, timeout=10)
        return r.json().get("access_token", "")
    except Exception:
        return ""


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _test_bola(base: str) -> dict:
    token = _login(base, "alice", "alice123")
    r = httpx.get(f"{base}/users/2", headers=_bearer(token), timeout=10)
    return {"status": r.status_code, "pass": r.status_code in (401, 403)}


def _test_jwt_forge(base: str) -> dict:
    if not _JOSE_OK:
        return {"status": 0, "pass": False, "note": "python-jose not installed"}
    forged = jose_jwt.encode({"sub": "3", "username": "h4x0r", "role": "admin"},
                             "secret", algorithm="HS256")
    r = httpx.get(f"{base}/admin/users", headers=_bearer(forged), timeout=10)
    return {"status": r.status_code, "pass": r.status_code in (401, 403)}


def _test_mass_assign(base: str) -> dict:
    token = _login(base, "alice", "alice123")
    r = httpx.put(f"{base}/users/1", headers=_bearer(token),
                  json={"role": "admin", "balance": 999999}, timeout=10)
    if r.status_code == 200:
        try:
            body = r.json()
            user = body.get("user", body)
            escalated = user.get("role") == "admin" or user.get("balance") == 999999
        except Exception:
            escalated = False
        return {"status": r.status_code, "pass": not escalated,
                "detail": "role/balance accepted" if escalated else "role/balance rejected"}
    return {"status": r.status_code, "pass": True, "detail": f"HTTP {r.status_code}"}


def _test_rate_limit(base: str) -> dict:
    got_429 = False
    for _ in range(10):
        r = httpx.post(f"{base}/auth/login",
                       json={"username": "nobody", "password": "x"}, timeout=10)
        if r.status_code == 429:
            got_429 = True
            break
    return {"status": 429 if got_429 else 401, "pass": got_429}


def _test_func_auth(base: str) -> dict:
    token = _login(base, "alice", "alice123")
    r = httpx.get(f"{base}/admin/users", headers=_bearer(token), timeout=10)
    return {"status": r.status_code, "pass": r.status_code in (401, 403)}


def _test_debug_endpoint(base: str) -> dict:
    r = httpx.get(f"{base}/debug/config", timeout=10)
    return {"status": r.status_code, "pass": r.status_code == 404}


def _test_cors(base: str) -> dict:
    r = httpx.get(f"{base}/health", headers={"Origin": "http://evil.com"}, timeout=10)
    acao = r.headers.get("access-control-allow-origin", "")
    return {"status": r.status_code, "pass": acao != "*", "detail": f"ACAO: {acao or '(none)'}"}


SCENARIOS = [
    ("API1-BOLA",      "Broken Object Level Authorization",         "Alice reads Bob's profile by ID",                  _test_bola),
    ("API2-JWT",       "Broken Authentication — JWT Weak Secret",   "Forge admin JWT with hardcoded key 'secret'",       _test_jwt_forge),
    ("API3-MASS",      "Mass Assignment — Privilege Escalation",    "PUT role=admin via profile update",                 _test_mass_assign),
    ("API4-RATELIMIT", "Unrestricted Resource Consumption",         "10 rapid login attempts — expect HTTP 429",         _test_rate_limit),
    ("API5-FUNCAUTH",  "Broken Function Level Authorization",       "Regular user calls GET /admin/users",               _test_func_auth),
    ("API8-DEBUG",     "Security Misconfiguration — Debug Endpoint","GET /debug/config without authentication",          _test_debug_endpoint),
    ("API8-CORS",      "Security Misconfiguration — CORS Wildcard", "Origin: evil.com — check ACAO response header",    _test_cors),
]


# ── HTML template ──────────────────────────────────────────────────────────────

_TMPL = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Comparative Security Evaluation</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Inter:wght@400;500;600;700;800&family=Outfit:wght@500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg: #070b13;
  --surf: #0e1424;
  --surf2: #171e35;
  --border: rgba(255, 255, 255, 0.09);
  --border-glow: rgba(99, 102, 241, 0.35);
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --emerald: #10b981;
  --emerald-dim: rgba(16, 185, 129, 0.15);
  --indigo: #6366f1;
  --indigo-dim: rgba(99, 102, 241, 0.15);
  --rose: #f43f5e;
  --rose-dim: rgba(244, 63, 94, 0.15);
  --amber: #f59e0b;
  --amber-dim: rgba(245, 158, 11, 0.15);
  --purple: #8b5cf6;
  --radius: 14px;
  --radius-sm: 8px;
  --shadow: 0 10px 30px rgba(0,0,0,0.35);
  --toc-bg: rgba(14, 20, 36, 0.92);
}

[data-theme="light"] {
  --bg: #f8fafc;
  --surf: #ffffff;
  --surf2: #f1f5f9;
  --border: #e2e8f0;
  --border-glow: rgba(99, 102, 241, 0.25);
  --text: #0f172a;
  --text-muted: #64748b;
  --emerald: #059669;
  --emerald-dim: rgba(5, 150, 105, 0.12);
  --indigo: #4f46e5;
  --indigo-dim: rgba(79, 70, 229, 0.1);
  --rose: #dc2626;
  --rose-dim: rgba(220, 38, 38, 0.1);
  --amber: #d97706;
  --amber-dim: rgba(217, 119, 6, 0.12);
  --purple: #7c3aed;
  --shadow: 0 8px 24px rgba(149, 157, 165, 0.12);
  --toc-bg: rgba(255, 255, 255, 0.95);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding-bottom: 60px;
  transition: background 0.25s, color 0.25s;
}

.hdr {
  background: linear-gradient(135deg, #0a0f1d 0%, #1e1b4b 50%, #070b13 100%);
  padding: 40px 24px 36px;
  text-align: center;
  border-bottom: 1px solid var(--border);
  box-shadow: var(--shadow);
  position: relative;
}
[data-theme="light"] .hdr {
  background: linear-gradient(135deg, #ffffff 0%, #e0e7ff 60%, #f8fafc 100%);
  border-bottom: 1px solid #cbd5e1;
}
.hdr-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1320px;
  margin: 0 auto 18px;
}
.brand-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: var(--emerald-dim);
  color: var(--emerald);
  border: 1px solid rgba(16, 185, 129, 0.35);
  padding: 5px 14px;
  border-radius: 99px;
  font-size: 0.82rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.theme-toggle-btn {
  background: var(--surf);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 18px;
  border-radius: 99px;
  cursor: pointer;
  font-size: 0.85rem;
  font-weight: 700;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  transition: all 0.2s ease;
  box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.theme-toggle-btn:hover {
  border-color: var(--indigo);
  color: var(--indigo);
  transform: translateY(-1px);
}
.hdr h1 {
  font-family: 'Outfit', sans-serif;
  font-size: 2.3rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  margin-bottom: 8px;
}
[data-theme="light"] .hdr h1 {
  color: #0f172a;
}
.hdr p { color: var(--text-muted); font-size: 0.95rem; font-weight: 500; }

.layout {
  max-width: 1380px;
  margin: 0 auto;
  padding: 32px 24px;
  display: grid;
  grid-template-columns: 240px 1fr;
  gap: 32px;
  align-items: start;
}
@media (max-width: 1024px) {
  .layout { grid-template-columns: 1fr; }
  .report-toc { display: none; }
}

.report-toc {
  position: sticky;
  top: 24px;
  background: var(--toc-bg);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 14px;
  box-shadow: var(--shadow);
  max-height: calc(100vh - 48px);
  overflow-y: auto;
}
.toc-title {
  font-family: 'Outfit', sans-serif;
  font-size: 0.78rem;
  font-weight: 800;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 0 8px 10px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 10px;
}
.toc-list { list-style: none; display: flex; flex-direction: column; gap: 4px; }
.toc-item a {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.82rem;
  font-weight: 600;
  transition: all 0.15s ease;
}
.toc-item a:hover {
  background: var(--surf2);
  color: var(--indigo);
  transform: translateX(3px);
}

.summary {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 18px;
  margin-bottom: 30px;
}
@media (max-width: 768px) {
  .summary { grid-template-columns: 1fr; }
}
.api-card {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  text-align: center;
  box-shadow: var(--shadow);
  transition: transform 0.2s, border-color 0.2s;
  position: relative;
  overflow: hidden;
}
.api-card:hover { transform: translateY(-3px); border-color: var(--border-glow); }
.api-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3.5px; }
.api-card.rv::before { background: var(--rose); }
.api-card.gh::before { background: var(--emerald); }
.api-card.impr::before { background: var(--purple); }

.api-card h2 {
  font-size: 0.78rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
  font-weight: 700;
}
.api-card .sc {
  font-family: 'Outfit', sans-serif;
  font-size: 3rem;
  font-weight: 800;
  line-height: 1.1;
  margin-bottom: 6px;
}
.api-card p { color: var(--text-muted); font-size: 0.82rem; font-weight: 600; }
.rv { color: var(--rose); }
.gh { color: var(--emerald); }
.impr { color: var(--purple); }

.charts { display: grid; grid-template-columns: 1.2fr 1fr; gap: 22px; margin-bottom: 36px; }
@media (max-width: 800px) { .charts { grid-template-columns: 1fr; } }
.cb {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  box-shadow: var(--shadow);
}
.cb h3 {
  font-family: 'Outfit', sans-serif;
  color: var(--text);
  font-weight: 700;
  font-size: 1.05rem;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.cb h3::before {
  content: '';
  display: inline-block;
  width: 4px;
  height: 16px;
  background: var(--indigo);
  border-radius: 2px;
}
.chart-container { position: relative; height: 230px; width: 100%; }

.section-hdr {
  font-family: 'Outfit', sans-serif;
  font-size: 0.78rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  padding: 12px 0 8px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--border);
}

.scenario {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 24px;
  overflow: hidden;
  box-shadow: var(--shadow);
  transition: border-color 0.2s ease;
}
.scenario:hover { border-color: var(--border-glow); }
.sc-hdr {
  padding: 18px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--surf2);
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.owasp-tag {
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--text-muted);
  background: var(--surf);
  padding: 3px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
}
.sc-name { font-size: 1.05rem; font-weight: 700; color: var(--text); flex: 1; font-family: 'Outfit', sans-serif; }
.badge { padding: 4px 10px; border-radius: 12px; font-size: 0.76rem; font-weight: 700; }
.badge-ok { background: var(--emerald-dim); color: var(--emerald); border: 1px solid rgba(16,185,129,0.35); }
.badge-fail { background: var(--rose-dim); color: var(--rose); border: 1px solid rgba(244,63,94,0.35); }

.sc-body { display: grid; grid-template-columns: 1fr 1.1fr 1.1fr; gap: 0; }
@media (max-width: 900px) { .sc-body { grid-template-columns: 1fr; } }
.sc-col { padding: 18px 24px; border-right: 1px solid var(--border); }
@media (max-width: 900px) { .sc-col { border-right: none; border-bottom: 1px solid var(--border); } }
.sc-col:last-child { border-right: none; border-bottom: none; }
.sc-col-lbl {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--text-muted);
  margin-bottom: 10px;
}
.attack-code {
  background: var(--surf2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  font-size: 0.82rem;
  font-family: 'Fira Code', monospace;
  color: var(--indigo);
  word-break: break-all;
  line-height: 1.5;
}
.result-status { font-size: 0.95rem; font-weight: 700; margin-bottom: 6px; }
.result-reason { font-size: 0.85rem; color: var(--text-muted); line-height: 1.6; }
.col-vuln .result-status { color: var(--rose); }
.col-hard-ok .result-status { color: var(--emerald); }
.col-hard-fail .result-status { color: var(--rose); }
.col-vuln { background: rgba(244,63,94,0.03); }
.col-hard-ok { background: rgba(16,185,129,0.03); }
.col-hard-fail { background: rgba(244,63,94,0.03); }

.sc-footer {
  padding: 14px 24px;
  border-top: 1px solid var(--border);
  background: var(--surf2);
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.cve-badge {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: 5px;
  padding: 3px 10px;
  font-size: 0.76rem;
  font-family: 'Fira Code', monospace;
  color: var(--indigo);
  text-decoration: none;
  font-weight: 600;
}
.cve-badge:hover { border-color: var(--indigo); transform: translateY(-1px); }
.owasp-link { font-size: 0.8rem; color: var(--emerald); text-decoration: none; margin-left: auto; font-weight: 700; }
.owasp-link:hover { text-decoration: underline; }

.footer {
  text-align: center;
  padding: 32px;
  color: var(--text-muted);
  font-size: 0.85rem;
  border-top: 1px solid var(--border);
  margin-top: 40px;
}
.footer span { color: var(--emerald); font-weight: 700; }
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-top">
    <div class="brand-pill">📊 Comparative Security Workbench</div>
    <button class="theme-toggle-btn" id="theme-btn" onclick="toggleReportTheme()">☀️ Light Mode</button>
  </div>
  <h1>Comparative Security Evaluation</h1>
  <p>Vulnerable API vs Hardened API &nbsp;•&nbsp; {{ timestamp }} &nbsp;•&nbsp; {{ total }} OWASP Attack Scenarios</p>
</div>

<div class="layout">
  <aside class="report-toc">
    <div class="toc-title">📑 Scenarios</div>
    <ul class="toc-list">
      <li class="toc-item"><a href="#overview"><span>📊</span> Overview Metrics</a></li>
      <li class="toc-item"><a href="#analytics"><span>📈</span> Visual Analytics</a></li>
      <li class="toc-title" style="margin-top: 12px;">🔍 Detailed Tests</li>
      {% for r in rows %}
      <li class="toc-item">
        <a href="#sc-{{ loop.index }}">
          <span>•</span>
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ r.name }}</span>
        </a>
      </li>
      {% endfor %}
    </ul>
  </aside>

  <main class="content">
    <section id="overview">
      <div class="summary">
        <div class="api-card rv">
          <h2>Vulnerable API</h2>
          <div class="sc rv">{{ vuln_score }}%</div>
          <p>{{ vuln_pass }}/{{ total }} attacks blocked</p>
        </div>
        <div class="api-card impr">
          <h2>Security Improvement</h2>
          <div class="sc impr">+{{ hard_score - vuln_score }}pp</div>
          <p>percentage points gained</p>
        </div>
        <div class="api-card gh">
          <h2>Hardened API</h2>
          <div class="sc gh">{{ hard_score }}%</div>
          <p>{{ hard_pass }}/{{ total }} attacks blocked</p>
        </div>
      </div>
    </section>

    <section id="analytics">
      <div class="charts">
        <div class="cb">
          <h3>Security Score Comparison</h3>
          <div class="chart-container">
            <canvas id="barChart"></canvas>
          </div>
        </div>
        <div class="cb">
          <h3>Hardened API — Attack Outcomes</h3>
          <div class="chart-container">
            <canvas id="pieChart"></canvas>
          </div>
        </div>
      </div>
    </section>

    <h2 class="section-hdr">Detailed Comparative Log</h2>

    {% for r in rows %}
    {% set sev_css = sev_styles.get(r.severity, '') %}
    <div class="scenario" id="sc-{{ loop.index }}">
      <div class="sc-hdr">
        <span class="owasp-tag">{{ r.owasp_id }}</span>
        <span class="badge" style="{{ sev_css }}">{{ r.severity }}</span>
        <span class="sc-name">{{ r.id }} &mdash; {{ r.name }}</span>
        <span class="badge {% if r.h_pass %}badge-ok{% else %}badge-fail{% endif %}">
          Hardened: {{ "SECURE" if r.h_pass else "VULNERABLE" }}
        </span>
      </div>
      <div class="sc-body">
        <div class="sc-col">
          <div class="sc-col-lbl">Attack Sent</div>
          <div class="attack-code">{{ r.attack_payload }}</div>
          <div style="margin-top:8px;font-size:.82em;color:var(--text-muted)">{{ r.desc }}</div>
        </div>
        <div class="sc-col col-vuln">
          <div class="sc-col-lbl">Vulnerable API (port 8000)</div>
          <div class="result-status">{{ r.v_status }} — {{ 'SECURE' if r.v_pass else 'EXPOSED' }}</div>
          <div class="result-reason">{{ r.vuln_reason }}</div>
        </div>
        <div class="sc-col {% if r.h_pass %}col-hard-ok{% else %}col-hard-fail{% endif %}">
          <div class="sc-col-lbl">Hardened API (port 8001)</div>
          <div class="result-status">{{ r.h_status }} — {{ 'BLOCKED' if r.h_pass else 'EXPOSED' }}</div>
          <div class="result-reason">{{ r.hard_reason }}</div>
        </div>
      </div>
      <div class="sc-footer">
        {% if r.cves %}
          {% for c in r.cves %}
            <a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{{ c }}" target="_blank">{{ c }}</a>
          {% endfor %}
        {% endif %}
        <a class="owasp-link" href="{{ r.owasp_ref }}" target="_blank">OWASP Docs &rarr;</a>
      </div>
    </div>
    {% endfor %}

    <div class="footer">
      MazAPI Security Scanner &nbsp;•&nbsp; <span>CY384 Cybersecurity Lab Work II</span> &nbsp;•&nbsp; UMaT Ghana
    </div>
  </main>
</div>

<script>
let barChartInstance = null;
let doughnutChartInstance = null;

function getThemeColors() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  return {
    textColor: isLight ? '#475569' : '#9ca3af',
    gridColor: isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.06)',
    cardBg: isLight ? '#ffffff' : '#0e1424'
  };
}

function initCharts() {
  const tc = getThemeColors();

  const ctxBar = document.getElementById('barChart').getContext('2d');
  if (barChartInstance) barChartInstance.destroy();
  barChartInstance = new Chart(ctxBar, {
    type: 'bar',
    data: {
      labels: ['Vulnerable API', 'Hardened API'],
      datasets: [{
        label: 'Security Score (%)',
        data: [{{ vuln_score }}, {{ hard_score }}],
        backgroundColor: ['#f43f5e', '#10b981'],
        borderColor: ['#f43f5e', '#10b981'],
        borderWidth: 1.5,
        borderRadius: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          min: 0,
          max: 100,
          ticks: { color: tc.textColor, font: { family: 'Inter' } },
          grid: { color: tc.gridColor }
        },
        x: {
          ticks: { color: tc.textColor, font: { family: 'Inter' } },
          grid: { display: false }
        }
      }
    }
  });

  const ctxPie = document.getElementById('pieChart').getContext('2d');
  if (doughnutChartInstance) doughnutChartInstance.destroy();
  doughnutChartInstance = new Chart(ctxPie, {
    type: 'doughnut',
    data: {
      labels: ['Attacks Blocked', 'Still Exposed'],
      datasets: [{
        data: [{{ hard_pass }}, {{ total - hard_pass }}],
        backgroundColor: ['#10b981', '#f43f5e'],
        borderColor: [tc.cardBg, tc.cardBg],
        borderWidth: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: tc.textColor, font: { family: 'Inter', size: 11 } }
        }
      }
    }
  });
}

function toggleReportTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('mazapi_report_theme', next);

  const btn = document.getElementById('theme-btn');
  if (btn) btn.innerHTML = next === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';

  initCharts();
}

// Load saved theme
const savedTheme = localStorage.getItem('mazapi_report_theme');
if (savedTheme) {
  document.documentElement.setAttribute('data-theme', savedTheme);
  const btn = document.getElementById('theme-btn');
  if (btn) btn.innerHTML = savedTheme === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
}

window.addEventListener('DOMContentLoaded', initCharts);
</script>
</body>
</html>"""


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="CY384 Comparative Security Evaluation")
    parser.add_argument("--vulnerable", default=os.getenv("VULNERABLE_URL", "http://localhost:8000"))
    parser.add_argument("--hardened",   default=os.getenv("HARDENED_URL",   "http://localhost:8001"))
    parser.add_argument("--reports",    default=os.getenv("REPORT_DIR",     "./reports"))
    args = parser.parse_args()

    os.makedirs(args.reports, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ts_file   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    rows = []
    vuln_pass = hard_pass = 0

    print(f"\n{'='*66}")
    print(f"  CY384 Comparative Security Evaluation  |  {timestamp}")
    print(f"  Vulnerable: {args.vulnerable}")
    print(f"  Hardened:   {args.hardened}")
    print(f"{'='*66}\n")

    for sid, name, desc, fn in SCENARIOS:
        detail = SCENARIO_DETAIL.get(sid, {})
        print(f"  [{sid:<18}] ", end="", flush=True)
        v = fn(args.vulnerable)
        time.sleep(0.4)
        h = fn(args.hardened)
        if v["pass"]: vuln_pass += 1
        if h["pass"]: hard_pass += 1
        v_lbl = "OK  " if v["pass"] else "FAIL"
        h_lbl = "OK  " if h["pass"] else "FAIL"
        print(f"Vuln={v['status']} [{v_lbl}]   Hard={h['status']} [{h_lbl}]")
        rows.append({
            "id": sid, "name": name, "desc": desc,
            "v_status": v["status"], "v_pass": v["pass"],
            "h_status": h["status"], "h_pass": h["pass"],
            **detail,
        })

    total      = len(SCENARIOS)
    vuln_score = round(vuln_pass / total * 100)
    hard_score = round(hard_pass / total * 100)

    print(f"\n  Vulnerable API: {vuln_score}%  ({vuln_pass}/{total} blocked)")
    print(f"  Hardened   API: {hard_score}%  ({hard_pass}/{total} blocked)")
    print(f"  Improvement:    +{hard_score - vuln_score} percentage points\n")

    payload = {
        "timestamp": timestamp, "vulnerable_url": args.vulnerable,
        "hardened_url": args.hardened, "vuln_score": vuln_score,
        "hard_score": hard_score, "vuln_pass": vuln_pass, "hard_pass": hard_pass,
        "total": total, "results": rows,
    }
    json_path = os.path.join(args.reports, f"comparison_{ts_file}.json")
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)

    html_path = os.path.join(args.reports, f"comparison_{ts_file}.html")
    html = Template(_TMPL).render(
        timestamp=timestamp, rows=rows, total=total,
        vuln_score=vuln_score, hard_score=hard_score,
        vuln_pass=vuln_pass, hard_pass=hard_pass,
        sev_styles=_SEV_CSS,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  JSON -> {json_path}")
    print(f"  HTML -> {html_path}\n")


if __name__ == "__main__":
    main()
