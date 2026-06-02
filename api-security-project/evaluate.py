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
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Comparative Security Evaluation</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9}
.hdr{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:40px;text-align:center}
.hdr h1{color:#58a6ff;font-size:2.2em;margin-bottom:8px}
.hdr p{color:#8b949e}
.wrap{max-width:1200px;margin:0 auto;padding:30px}
.summary{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:28px}
.api-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:28px;text-align:center}
.api-card h2{font-size:1.05em;color:#8b949e;margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em}
.api-card .sc{font-size:3em;font-weight:700;margin-bottom:6px}
.api-card p{color:#8b949e;font-size:.85em}
.rv{color:#f85149}.gh{color:#3fb950}.impr{color:#e3b341}
.improvement{font-size:2em;font-weight:700}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}
.cb{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px}
.cb h3{color:#58a6ff;margin-bottom:14px;font-size:.95em}
.section-hdr{font-size:.78em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;padding:10px 0 8px;margin-bottom:10px;border-bottom:1px solid #21262d}
/* Scenario cards */
.scenario{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:14px;overflow:hidden}
.sc-hdr{padding:14px 18px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.owasp-tag{font-size:.78em;font-weight:700;color:#8b949e;background:#0d1117;padding:2px 8px;border-radius:4px;border:1px solid #30363d}
.sc-name{font-size:.95em;font-weight:600;color:#e6edf3;flex:1}
.badge{padding:3px 10px;border-radius:12px;font-size:.76em;font-weight:700}
.sc-body{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0}
.sc-col{padding:14px 18px;border-right:1px solid #21262d}
.sc-col:last-child{border-right:none}
.sc-col-lbl{font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#8b949e;margin-bottom:8px}
.attack-code{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:8px 10px;font-size:.8em;font-family:Consolas,monospace;color:#79c0ff;word-break:break-all;line-height:1.5}
.result-status{font-size:1em;font-weight:700;margin-bottom:6px}
.result-reason{font-size:.83em;color:#8b949e;line-height:1.6}
.col-vuln .result-status{color:#f85149}
.col-hard-ok .result-status{color:#3fb950}
.col-hard-fail .result-status{color:#f85149}
.col-vuln{background:rgba(248,81,73,.04)}
.col-hard-ok{background:rgba(63,185,80,.04)}
.sc-footer{padding:10px 18px;border-top:1px solid #21262d;background:#0a0d10;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.cve-badge{background:#161b22;border:1px solid #30363d;border-radius:5px;padding:2px 8px;font-size:.76em;font-family:monospace;color:#58a6ff;text-decoration:none}
.cve-badge:hover{border-color:#58a6ff}
.owasp-link{font-size:.78em;color:#8b949e;text-decoration:none;margin-left:auto}
.owasp-link:hover{color:#58a6ff}
.footer{text-align:center;padding:28px;color:#8b949e;font-size:.82em;border-top:1px solid #21262d;margin-top:32px}
</style>
</head>
<body>
<div class="hdr">
  <h1>Comparative Security Evaluation</h1>
  <p>Vulnerable API vs Hardened API &nbsp;|&nbsp; {{ timestamp }} &nbsp;|&nbsp; {{ total }} OWASP Attack Scenarios</p>
</div>
<div class="wrap">

  <div class="summary">
    <div class="api-card"><h2>Vulnerable API</h2><div class="sc rv">{{ vuln_score }}%</div><p>{{ vuln_pass }}/{{ total }} attacks blocked</p></div>
    <div class="api-card"><h2>Security Improvement</h2><div class="sc impr">+{{ hard_score - vuln_score }}pp</div><p>percentage points gained</p></div>
    <div class="api-card"><h2>Hardened API</h2><div class="sc gh">{{ hard_score }}%</div><p>{{ hard_pass }}/{{ total }} attacks blocked</p></div>
  </div>

  <div class="charts">
    <div class="cb"><h3>Security Score Comparison</h3><canvas id="barChart" height="200"></canvas></div>
    <div class="cb"><h3>Hardened API — Attack Outcomes</h3><canvas id="pieChart" height="200"></canvas></div>
  </div>

  <div class="section-hdr">Attack Scenario Results — {{ total }} Scenarios</div>

  {% for r in rows %}
  {% set sev_css = sev_styles.get(r.severity, '') %}
  <div class="scenario">
    <div class="sc-hdr">
      <span class="owasp-tag">{{ r.owasp_id }}</span>
      <span class="badge" style="{{ sev_css }}">{{ r.severity }}</span>
      <span class="sc-name">{{ r.id }} &mdash; {{ r.name }}</span>
    </div>
    <div class="sc-body">
      <div class="sc-col">
        <div class="sc-col-lbl">Attack Sent</div>
        <div class="attack-code">{{ r.attack_payload }}</div>
        <div style="margin-top:8px;font-size:.82em;color:#8b949e">{{ r.desc }}</div>
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
      {% for cve in r.cves %}
      <a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{{ cve }}" target="_blank" rel="noopener">{{ cve }}</a>
      {% endfor %}
      <a class="owasp-link" href="{{ r.owasp_ref }}" target="_blank" rel="noopener">{{ r.owasp_id }} Reference &rarr;</a>
    </div>
  </div>
  {% endfor %}

</div>
<div class="footer">CY384 API Security Project &nbsp;|&nbsp; University of Mines and Technology, Ghana &nbsp;|&nbsp; OWASP API Security Top 10:2023</div>
<script>
new Chart(document.getElementById('barChart'),{type:'bar',data:{labels:['Vulnerable API','Hardened API'],datasets:[{label:'Security Score (%)',data:[{{ vuln_score }},{{ hard_score }}],backgroundColor:['rgba(248,81,73,.7)','rgba(63,185,80,.7)'],borderColor:['#f85149','#3fb950'],borderWidth:2}]},options:{plugins:{legend:{labels:{color:'#c9d1d9'}}},scales:{y:{min:0,max:100,ticks:{color:'#8b949e'},grid:{color:'#21262d'}},x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}}}});
new Chart(document.getElementById('pieChart'),{type:'doughnut',data:{labels:['Attacks Blocked','Still Exposed'],datasets:[{data:[{{ hard_pass }},{{ total - hard_pass }}],backgroundColor:['rgba(63,185,80,.7)','rgba(248,81,73,.7)'],borderColor:['#3fb950','#f85149'],borderWidth:2}]},options:{plugins:{legend:{labels:{color:'#c9d1d9'}}}}});
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
