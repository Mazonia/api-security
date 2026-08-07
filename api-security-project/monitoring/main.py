"""Transparent proxy + SQLite traffic logger + ML anomaly detection + live dashboard."""
import asyncio
import base64 as _b64
import glob as _glob
import json as _json
import os
import re as _re
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

import aiosqlite
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from anomaly_detector import detector

DB_PATH   = "/data/traffic.db"
UPSTREAM  = "http://vulnerable-api:8000"
templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT,
                method           TEXT,
                path             TEXT,
                status_code      INTEGER,
                response_time_ms REAL,
                has_auth         INTEGER,
                anomaly          INTEGER,
                anomaly_score    REAL,
                anomaly_reason   TEXT
            )
        """)
        await db.commit()
    import os
    if not os.path.exists("/data/model.joblib") or not os.path.exists("/data/rf_model.joblib"):
        subprocess.run(["python", "train_model.py"], check=False)
        detector.reload()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


async def _log(rec: dict) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO traffic "
            "(timestamp,method,path,status_code,response_time_ms,has_auth,anomaly,anomaly_score,anomaly_reason) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (rec["timestamp"], rec["method"], rec["path"], rec["status_code"],
             rec["response_time_ms"], 1 if rec["has_auth"] else 0,
             1 if rec["anomaly"] else 0, rec["score"], rec["reason"]),
        )
        await db.commit()


# ── Browser-extension live link ────────────────────────────────────────────────
# The MazAPI browser extension runs every scan locally on the user's machine. When a
# user links a website to this dashboard, the extension POSTs a compact summary of each
# completed scan here so it can be watched live. This is NOT an external service: the
# dashboard runs on the user's own computer (localhost), so nothing leaves the machine.
from collections import deque as _deque

_EXT_EVENTS: "_deque[dict]" = _deque(maxlen=500)
_EXT_SEQ = {"n": 0}

_EXT_LIVE_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MazAPI - Live Extension Results</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;max-width:980px;margin:0 auto}
h1{color:#58a6ff;font-size:1.3em;margin-bottom:4px}
.sub{color:#8b949e;font-size:.85em;margin-bottom:16px}
.bar{display:flex;gap:10px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
select{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:6px;font-size:.85em}
.dot{width:9px;height:9px;border-radius:50%;background:#3fb950;display:inline-block;animation:pulse 1.5s infinite;margin-right:6px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px 14px;margin-bottom:10px}
.card .top{display:flex;justify-content:space-between;font-size:.8em;color:#8b949e;margin-bottom:6px}
.score{font-weight:700}
.f{font-size:.82em;padding:3px 0;border-top:1px solid #21262d}
.sev{display:inline-block;min-width:64px;font-weight:700}
.CRITICAL{color:#f85149}.HIGH{color:#f0883e}.MEDIUM{color:#d29922}.LOW{color:#3fb950}
.empty{color:#8b949e;text-align:center;padding:40px}
.disc{margin-top:24px;padding:12px 14px;border:1px solid #21262d;border-radius:8px;color:#8b949e;font-size:.76em;line-height:1.5}
.disc b{color:#3fb950}
</style></head><body>
<h1>MazAPI Live Results</h1>
<div class="sub"><span class="dot"></span>Streaming scan results from your browser extension. Everything stays on this machine.</div>
<div class="bar"><label>Site:</label><select id="site" onchange="changeSite()"><option value="">All linked sites</option></select><span id="status" class="sub"></span></div>
<div id="list"><div class="empty">Waiting for scans. Run a scan in the MazAPI extension with dashboard linking enabled.</div></div>
<div class="disc"><b>Privacy:</b> MazAPI has no server of its own and collects no telemetry or analytics. Every scan runs locally in your browser, results are stored only on this machine, and this dashboard is served from your own computer (localhost). No user data is stored remotely or leaves your machine. The only outbound requests MazAPI makes are the security tests sent to the target you choose to scan.</div>
<script>
var params=new URLSearchParams(location.search);
var site=params.get('site')||'';var since=0;var seenSites={};
function changeSite(){site=document.getElementById('site').value;since=0;document.getElementById('list').innerHTML='<div class="empty">Waiting for scans...</div>';}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function render(ev){var list=document.getElementById('list');if(list.querySelector('.empty'))list.innerHTML='';
var fh=(ev.findings||[]).map(function(f){return '<div class="f"><span class="sev '+esc(f.severity)+'">'+esc(f.severity)+'</span> '+esc(f.test||f.label||f.message||'')+(f.category?' <span style="color:#6e7681">['+esc(f.category)+']</span>':'')+'</div>';}).join('');
var col=ev.score>=80?'#3fb950':ev.score>=50?'#d29922':'#f85149';
var card=document.createElement('div');card.className='card';
card.innerHTML='<div class="top"><span>'+esc(ev.target)+'</span><span>'+esc(ev.ts)+'</span></div>'+
'<div><span class="score" style="color:'+col+'">Score '+esc(ev.score)+'%</span> &middot; <span class="CRITICAL">'+esc(ev.criticals)+' critical</span> &middot; <span class="HIGH">'+esc(ev.highs)+' high</span></div>'+fh;
list.insertBefore(card,list.firstChild);}
function poll(){fetch('/extension/live/data?site='+encodeURIComponent(site)+'&since='+since).then(function(r){return r.json();}).then(function(d){
var sel=document.getElementById('site');(d.sites||[]).forEach(function(s){if(!seenSites[s]){seenSites[s]=1;var o=document.createElement('option');o.value=s;o.textContent=s;if(s===site)o.selected=true;sel.appendChild(o);}});
(d.events||[]).forEach(function(ev){since=Math.max(since,ev.id);render(ev);});
document.getElementById('status').textContent='Last update '+new Date().toLocaleTimeString();
}).catch(function(){document.getElementById('status').textContent='Dashboard offline';});}
poll();setInterval(poll,3000);
</script></body></html>"""


@app.post("/extension/ingest")
async def extension_ingest(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON"}, status_code=400)
    findings = body.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    _EXT_SEQ["n"] += 1
    site = str(body.get("site") or body.get("target") or "unknown")[:200]
    event = {
        "id":        _EXT_SEQ["n"],
        "ts":        datetime.utcnow().strftime("%H:%M:%S"),
        "site":      site,
        "target":    str(body.get("target") or site)[:300],
        "score":     body.get("score"),
        "criticals": int(body.get("criticals") or 0),
        "highs":     int(body.get("highs") or 0),
        "total":     int(body.get("total") or len(findings)),
        "findings":  findings[:100],
    }
    _EXT_EVENTS.append(event)
    return {"ok": True, "id": event["id"]}


@app.get("/extension/live/data")
async def extension_live_data(site: str = "", since: int = 0):
    evs = [e for e in _EXT_EVENTS if (not site or e["site"] == site) and e["id"] > since]
    sites = sorted({e["site"] for e in _EXT_EVENTS})
    return {"events": evs, "sites": sites, "latest": _EXT_SEQ["n"]}


@app.get("/extension/live", response_class=HTMLResponse, include_in_schema=False)
async def extension_live():
    return _EXT_LIVE_HTML


@app.get("/monitor/health")
@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "MazAPI Monitoring Proxy"}


# ── internal monitor API (ALL before the /{path:path} catch-all) ───────────────

@app.get("/monitor/stats")
async def stats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async def scalar(sql, *args):
            cur = await db.execute(sql, args)
            row = await cur.fetchone()
            return row[0] if row else 0

        total      = await scalar("SELECT COUNT(*) FROM traffic")
        anomalies  = await scalar("SELECT COUNT(*) FROM traffic WHERE anomaly=1")
        errors     = await scalar("SELECT COUNT(*) FROM traffic WHERE status_code>=400")
        avg_ms     = await scalar("SELECT AVG(response_time_ms) FROM traffic") or 0
        auth_count = await scalar("SELECT SUM(has_auth) FROM traffic") or 0

        error_rate = round(errors / total * 100, 1) if total else 0.0
        anomaly_rate = round(anomalies / total * 100, 1) if total else 0.0

        # Requests in last 60 seconds (last 2 minute buckets)
        now = datetime.utcnow()
        cur_min  = now.strftime("%H:%M")
        prev_min = (now - timedelta(minutes=1)).strftime("%H:%M")
        recent = await scalar(
            "SELECT COUNT(*) FROM traffic WHERE substr(timestamp,1,5) IN (?,?)",
            cur_min, prev_min)

        # Seconds since last anomaly
        cur = await db.execute(
            "SELECT timestamp FROM traffic WHERE anomaly=1 ORDER BY id DESC LIMIT 1")
        row = await cur.fetchone()
        last_anomaly_secs = -1
        if row:
            try:
                ts = datetime.strptime(row[0], "%H:%M:%S").replace(
                    year=now.year, month=now.month, day=now.day)
                diff = int((now - ts).total_seconds())
                last_anomaly_secs = max(0, diff)
            except Exception:
                pass

        # Method distribution
        cur = await db.execute(
            "SELECT method, COUNT(*) FROM traffic GROUP BY method")
        method_counts = {r[0]: r[1] for r in await cur.fetchall()}

        # Status buckets
        cur = await db.execute(
            "SELECT status_code, COUNT(*) FROM traffic GROUP BY status_code")
        status_buckets: dict = {}
        for r in await cur.fetchall():
            bucket = f"{str(r[0])[0]}xx"
            status_buckets[bucket] = status_buckets.get(bucket, 0) + r[1]

        # Last request timestamp
        cur = await db.execute("SELECT timestamp FROM traffic ORDER BY id DESC LIMIT 1")
        row = await cur.fetchone()
        last_request_time = row[0] if row else None

    return {
        "total_requests":    total,
        "anomalies":         anomalies,
        "anomaly_rate":      anomaly_rate,
        "authenticated":     int(auth_count),
        "unauthenticated":   total - int(auth_count),
        "error_count":       errors,
        "error_rate":        error_rate,
        "avg_response_ms":   round(avg_ms, 1),
        "recent_per_2min":   recent,
        "last_anomaly_secs": last_anomaly_secs,
        "last_request_time": last_request_time,
        "method_counts":     method_counts,
        "status_buckets":    status_buckets,
    }


@app.get("/monitor/timeline")
async def timeline(minutes: int = 60):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT substr(timestamp,1,5) as minute, COUNT(*) as total, "
            "SUM(anomaly) as anomalies, MIN(id) as min_id "
            "FROM traffic GROUP BY minute ORDER BY min_id DESC LIMIT ?", (max(minutes, 300),))
        raw_rows = await cur.fetchall()

    counts = {r["minute"]: {"total": r["total"], "anomalies": r["anomalies"] or 0} for r in raw_rows}
    
    now = datetime.utcnow()
    ref_time = now
    if raw_rows:
        latest_min = raw_rows[0]["minute"]
        try:
            latest_dt = datetime.strptime(latest_min, "%H:%M").replace(
                year=now.year, month=now.month, day=now.day)
            if latest_dt > ref_time:
                ref_time = latest_dt
        except Exception:
            pass

    result = []
    for i in range(minutes - 1, -1, -1):
        t = ref_time - timedelta(minutes=i)
        m_str = t.strftime("%H:%M")
        c = counts.get(m_str, {"total": 0, "anomalies": 0})
        result.append({
            "minute": m_str,
            "total": c["total"],
            "anomalies": c["anomalies"]
        })

    return result


@app.get("/monitor/endpoints")
async def top_endpoints(limit: int = 30):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT path, COUNT(*) as total, "
            "SUM(CASE WHEN status_code>=400 THEN 1 ELSE 0 END) as errors, "
            "SUM(anomaly) as anomalies, "
            "ROUND(AVG(response_time_ms),1) as avg_ms, "
            "SUM(has_auth) as authenticated "
            "FROM traffic GROUP BY path ORDER BY total DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in await cur.fetchall()]
    for r in rows:
        r["error_rate"] = round(r["errors"] / r["total"] * 100, 1) if r["total"] else 0.0
    return rows


@app.get("/monitor/feed")
async def feed(limit: int = 200):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, timestamp, method, path, status_code, response_time_ms, "
            "has_auth, anomaly, anomaly_score, anomaly_reason "
            "FROM traffic ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in await cur.fetchall()]


@app.get("/monitor/anomalies")
async def anomalies(limit: int = 200):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, timestamp, method, path, status_code, response_time_ms, "
            "anomaly_score, anomaly_reason "
            "FROM traffic WHERE anomaly=1 ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in await cur.fetchall()]


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# ── generic external scanner ───────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    # auth: login-flow
    auth_endpoint: Optional[str] = "/auth/login"
    auth_body: Optional[dict] = None
    token_field: Optional[str] = "access_token"
    # auth: direct Bearer token
    direct_token: Optional[str] = None
    # auth: API key in request header
    api_key_header: Optional[str] = None
    api_key_value: Optional[str] = None
    # auth: API key in query parameter (e.g. ?key=… for Google APIs)
    api_key_query_param: Optional[str] = None
    api_key_query_value: Optional[str] = None
    # auth: HTTP Basic Auth
    basic_auth_user: Optional[str] = None
    basic_auth_pass: Optional[str] = None
    # extra headers sent with every request (X-Tenant-ID, X-Api-Version, etc.)
    extra_headers: Optional[dict] = None
    # api_type: "rest" (default) or "graphql"
    api_type: Optional[str] = "rest"
    # endpoint config
    bola_path: Optional[str] = "/users/{id}"
    update_path: Optional[str] = "/users/1"
    protected_path: Optional[str] = "/admin/users"
    # test selection: None = all; else list of "api1","api2","api3","api4","api5","api8"
    tests: Optional[list] = None


class SaveReportRequest(BaseModel):
    target: str
    timestamp: Optional[str] = None
    score: int = 0
    total_tests: int = 0
    total_vulnerable: int = 0
    categories: list = []
    detail: str = "brief"


async def _async_get(client: httpx.AsyncClient, url: str, headers: dict = None, params: dict = None):
    try:
        return await client.get(url, headers=headers or {}, params=params or {}, timeout=8)
    except Exception:
        return None


async def _async_post(client: httpx.AsyncClient, url: str, body: dict, headers: dict = None, params: dict = None):
    try:
        return await client.post(url, json=body, headers=headers or {}, params=params or {}, timeout=8)
    except Exception:
        return None


_SENSITIVE_PATHS = [
    "/debug/config", "/debug", "/admin", "/admin/users",
    "/internal", "/metrics", "/actuator/env",
    "/swagger", "/docs", "/openapi.json", "/.env",
]

_ADMIN_PATHS = {"/admin", "/admin/users", "/admin/orders", "/admin/config"}

# ── CVE data for save-report HTML generation ───────────────────────────────────
_CVE_DB_M = {
    "API1:2023 - Broken Object Level Authorization": {
        "cves": ["CVE-2019-14234","CVE-2020-7927","CVE-2021-21302"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "severity": "HIGH",
        "description": "The API retrieves data based on a client-supplied identifier without verifying that the requesting user is authorised to access that specific object.",
        "fixes": ["Verify ownership on every request: check current_user.id == resource.owner_id before returning data.","Use unpredictable UUIDs instead of sequential integer IDs to reduce guessability.","Apply an authorization middleware/dependency that enforces ownership rather than repeating checks per endpoint.","Write integration tests that log in as User A and attempt to access User B's resources — expect 403."],
        "impact": "Any authenticated user can enumerate all sequential object IDs and exfiltrate every record in the system — user profiles, orders, messages, or payment details — without requiring elevated privileges. In regulated environments this constitutes a mandatory-notification data breach under GDPR/HIPAA.",
        "poc_steps": ["Authenticate as a low-privilege user (e.g., alice) and capture the returned JWT token.","Call GET /users/1 — confirm your own profile is returned.","Change the path ID to /users/2 — the server returns another user's full profile with no ownership check.","Automate: for i in range(1, 10000): GET /users/{i} — the entire user table is now exfiltrable."],
        "code_before": '@app.get("/users/{user_id}")\nasync def get_user(user_id: int, token=Depends(decode_token)):\n    user = db.get(user_id)  # no ownership check\n    if not user:\n        raise HTTPException(404)\n    return user',
        "code_after": '@app.get("/users/{user_id}")\nasync def get_user(user_id: int, current=Depends(get_current_user)):\n    if user_id != current.id:  # ownership enforced\n        raise HTTPException(status_code=403, detail="Forbidden")\n    return db.get(user_id)',
    },
    "API2:2023 - Broken Authentication": {
        "cves": ["CVE-2018-1000531","CVE-2022-21449","CVE-2021-27958"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        "severity": "CRITICAL",
        "description": "Authentication mechanisms are implemented incorrectly, allowing attackers to forge tokens, brute-force credentials, or bypass authentication entirely.",
        "fixes": ["Load JWT secrets from environment variables — never hard-code them in source code.","Always set an expiry claim (exp) in JWTs; 15–30 minutes is typical for access tokens.","Rate-limit login endpoints to 5 attempts per minute per IP and implement account lockout.","Use a well-audited library and verify the alg header to prevent algorithm confusion attacks."],
        "impact": "A forged JWT grants persistent, unrestricted API access under any identity — including admin — without knowing a password. Hard-coded secrets rarely rotate, so a single source-code leak compromises every user account across all environments permanently.",
        "poc_steps": ["Identify the JWT signing algorithm from the token header (e.g., alg: HS256).","Try the well-known weak key 'secret': jose.jwt.encode({'sub':'1','role':'admin'}, 'secret', 'HS256').","Send the forged token to any protected endpoint — a 200 response confirms the secret is compromised.","With a valid admin token, call GET /admin/users, PUT /users/{id}, DELETE /users/{id} freely."],
        "code_before": "SECRET = 'secret'  # hard-coded, committed to version control\n\ndef decode_token(token: str):\n    return jose.jwt.decode(token, SECRET, algorithms=['HS256'])\n    # no expiry check",
        "code_after": "import os\nSECRET = os.environ['JWT_SECRET']  # from .env or secret manager\n\ndef decode_token(token: str):\n    payload = jose.jwt.decode(token, SECRET, algorithms=['HS256'])\n    if payload.get('exp', 0) < time.time():\n        raise HTTPException(401, 'Token expired')\n    return payload",
    },
    "API3:2023 - Broken Object Property Level Authorization": {
        "cves": ["CVE-2012-2676","CVE-2022-32532","CVE-2021-41079"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "severity": "HIGH",
        "description": "The API accepts more fields than intended, allowing clients to modify properties they should never control — such as role or balance.",
        "fixes": ["Define strict input schemas that explicitly list allowed fields (email, password only for profile updates).","Never pass user input directly to ORM .update() calls — always use an allowlist.","Treat privilege fields (role, is_admin, balance) as server-controlled — strip them from all client input models.","Return a separate response schema that omits sensitive fields like password hash."],
        "impact": "Any authenticated user can self-promote to administrator, set their account balance to an arbitrary value, or overwrite other users' sensitive fields. Mass assignment bypasses the entire RBAC model in a single API call.",
        "poc_steps": ["Log in as a regular user and obtain a JWT token.","Send PUT /users/1 with body {\"email\": \"alice@x.com\", \"role\": \"admin\", \"balance\": 999999}.","If the response echoes role: 'admin' and balance: 999999, mass assignment is confirmed.","Now call GET /admin/users — as a self-promoted admin the endpoint returns all user records."],
        "code_before": "class UserUpdate(BaseModel):\n    email: str\n    password: str\n    role: str       # client can set any role\n    balance: float  # client controls their balance\n\n@app.put('/users/{uid}')\nasync def update(uid: int, body: UserUpdate, ...):\n    db.update(uid, **body.dict())",
        "code_after": "class UserUpdate(BaseModel):\n    email: str      # only user-editable fields\n    password: str\n    # role and balance are NOT in this schema\n\n@app.put('/users/{uid}')\nasync def update(uid: int, body: UserUpdate, ...):\n    db.update(uid, email=body.email, password=hash(body.password))",
    },
    "API4:2023 - Unrestricted Resource Consumption": {
        "cves": ["CVE-2019-11324","CVE-2020-26258","CVE-2021-25742"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "severity": "MEDIUM",
        "description": "The API does not limit the rate or volume of requests, enabling brute-force attacks, credential stuffing, and denial-of-service.",
        "fixes": ["Apply per-IP rate limiting on authentication endpoints (e.g., slowapi for FastAPI).","Apply per-user rate limiting on resource endpoints to prevent data scraping.","Set maximum request body sizes and reject oversized payloads early.","Implement exponential backoff or temporary IP bans after repeated failures."],
        "impact": "Without rate limiting an attacker can attempt millions of password combinations per hour using credential stuffing tools (Hydra, Burp Intruder), enumerate valid usernames, or saturate the server to cause denial of service — all using publicly available tooling.",
        "poc_steps": ["Send 12 rapid POST /auth/login requests with an incorrect password — observe no 429 response.","Run: for i in range(10000): POST /auth/login {username:'alice', password:'guess'+str(i)}","With no delay between requests, a 6-character password is brutable in under 1 hour.","Confirm fix: add a 5/min rate limit and re-run — a 429 should appear after the 5th attempt."],
        "code_before": "@app.post('/auth/login')\nasync def login(body: LoginRequest):\n    user = db.get_by_username(body.username)\n    if not user or user.password != body.password:\n        raise HTTPException(401)  # unlimited attempts, no lockout",
        "code_after": "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.post('/auth/login')\n@limiter.limit('5/minute')\nasync def login(request: Request, body: LoginRequest):\n    user = db.get_by_username(body.username)\n    if not user or user.password != body.password:\n        raise HTTPException(401)",
    },
    "API5:2023 - Broken Function Level Authorization": {
        "cves": ["CVE-2021-41773","CVE-2022-22947","CVE-2020-14882"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        "severity": "HIGH",
        "description": "Administrative or privileged endpoints are accessible to regular users because the API checks authentication but not the user's role or permissions.",
        "fixes": ["Default to deny — every endpoint must explicitly declare the required role/permission.","Use a shared authorization dependency/guard that verifies role on every admin route.","Keep admin functionality on a separate service or subdomain with network-level controls.","Audit all routes regularly to ensure no admin path is reachable without explicit role validation."],
        "impact": "Any authenticated user can invoke administrator-only functions: listing all user accounts, modifying arbitrary records, accessing billing data, or changing system settings. The only requirement is knowing the endpoint path — often exposed in JS bundles, API docs, or Shodan results.",
        "poc_steps": ["Authenticate as a regular (non-admin) user and capture the JWT.","Send GET /admin/users with the regular user token.","If the API returns a list of all users (200 OK), function-level authorization is absent.","Attempt POST /admin/users/{id}/promote — if it succeeds the attacker now has an admin peer."],
        "code_before": "@app.get('/admin/users')\nasync def list_users(token=Depends(decode_token)):\n    # checks authentication only — not the user's role\n    return db.all_users()",
        "code_after": "def require_admin(current=Depends(get_current_user)):\n    if current.role != 'admin':\n        raise HTTPException(403, 'Admin only')\n    return current\n\n@app.get('/admin/users')\nasync def list_users(admin=Depends(require_admin)):\n    return db.all_users()  # role enforced by dependency",
    },
    "API8:2023 - Security Misconfiguration": {
        "cves": ["CVE-2021-44228","CVE-2020-1938","CVE-2019-0232"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "severity": "MEDIUM",
        "description": "The API exposes sensitive information through debug endpoints, verbose error messages, permissive CORS, or publicly accessible API documentation.",
        "fixes": ["Remove all debug/development endpoints before deploying to production — use ENV flags to gate them.","Configure CORS to allow only known, trusted origins; never use wildcard (*) with credentialed requests.","Return generic error messages — never reveal whether a username exists or a password is wrong.","Disable interactive API documentation (Swagger UI, ReDoc) in production environments."],
        "impact": "Debug endpoints routinely expose JWT signing secrets, database connection strings, internal IP addresses, and API keys in a single unauthenticated GET request. A leaked JWT_SECRET enables admin token forgery across every user and environment without any further exploitation.",
        "poc_steps": ["Without any authentication, send GET /debug/config.","If the response contains 'JWT_SECRET', 'DB_PASSWORD', or internal hostnames — misconfiguration confirmed.","Use the leaked JWT_SECRET to forge admin tokens: jwt.encode({'sub':'1','role':'admin'}, leaked_secret).","Combine with CORS wildcard: any web page can now call the API as an authenticated admin."],
        "code_before": "import os\n\n@app.get('/debug/config')\nasync def debug():  # no auth, no ENV check\n    return {\n        'jwt_secret': SECRET,\n        'db_url': DB_URL,\n        'env': dict(os.environ)\n    }",
        "code_after": "ENV = os.getenv('ENV', 'production')\n\n@app.get('/debug/config')\nasync def debug(admin=Depends(require_admin)):\n    if ENV != 'development':  # disabled in production\n        raise HTTPException(404)\n    return {'status': 'debug mode active'}",
    },
}


@app.post("/monitor/scan")
async def external_scan(req: ScanRequest):
    base    = req.target.rstrip("/")
    results: list = []
    token   = req.direct_token or ""
    user_id = 1
    _run    = set(req.tests) if req.tests else {
        "api1","api2","api3","api4","api5","api8",
        "api7","api9",
        "ext_verb","ext_traversal","ext_injection","ext_redirect",
        "ext_xxe","ext_crlf","ext_cmd",
        "pii","graphql_scan",
    }

    # ── Build auth parameters ────────────────────────────────────────────────────
    # Query params appended to every authenticated request (e.g. ?key=… for Google)
    _q_params: dict = {}
    if req.api_key_query_param and req.api_key_query_value:
        _q_params[req.api_key_query_param] = req.api_key_query_value

    # Base headers included in every authenticated request (extra_headers + basic auth)
    _base_hdrs: dict = dict(req.extra_headers or {})
    if req.basic_auth_user is not None and req.basic_auth_pass is not None:
        _cred = _b64.b64encode(
            f"{req.basic_auth_user}:{req.basic_auth_pass}".encode()
        ).decode()
        _base_hdrs["Authorization"] = f"Basic {_cred}"

    # eff_hdrs: full authenticated headers (base + api-key header + bearer token)
    eff_hdrs: dict = dict(_base_hdrs)
    if req.api_key_header and req.api_key_value:
        eff_hdrs[req.api_key_header] = req.api_key_value
    if token:
        eff_hdrs["Authorization"] = f"Bearer {token}"
        try:
            _pld = _json.loads(_b64.b64decode(token.split(".")[1] + "=="))
            user_id = int(_pld.get("sub", 1))
        except Exception:
            pass

    pre_scan = {
        "target_reachable": False,
        "reachable_status": None,
        "auth_provided": bool(
            req.direct_token or req.api_key_header or req.auth_body
            or req.api_key_query_param or req.basic_auth_user
        ),
        "auth_valid": None,   # True | False | None (unknown)
        "auth_message": "No credentials provided — only unauthenticated tests will run.",
        "api_type": req.api_type or "rest",
    }

    async with httpx.AsyncClient(follow_redirects=True) as client:

        # Closures: authenticated GET/POST (includes _q_params + _base_hdrs)
        async def _aget(path, *, hdrs=None):
            merged = {**_base_hdrs, **(hdrs or {})}
            return await _async_get(client, base + path, headers=merged, params=_q_params)

        async def _apost(path, body, *, hdrs=None):
            merged = {**_base_hdrs, **(hdrs or {})}
            return await _async_post(client, base + path, body, headers=merged, params=_q_params)

        # ── Phase 1: Target reachability ────────────────────────────────────────
        for _rp in ["/", ""]:
            _rr = await _async_get(client, base + _rp)
            if _rr is not None:
                pre_scan["target_reachable"] = True
                pre_scan["reachable_status"] = _rr.status_code
                break
        if not pre_scan["target_reachable"]:
            return JSONResponse({
                "target": req.target,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                "score": 0, "total_tests": 0, "total_vulnerable": 0,
                "categories": [],
                "pre_scan": {**pre_scan,
                             "auth_message": "Scan aborted — target unreachable. "
                                             "Check the URL and confirm the service is running."},
            })

        # ── Phase 2: Auth acquisition + validation ───────────────────────────────
        if not token and req.auth_body and req.auth_endpoint:
            # Login flow: POST credentials → get token
            r_login = await _async_post(client, base + req.auth_endpoint, req.auth_body)
            if r_login and r_login.status_code == 200:
                try:
                    token = r_login.json().get(req.token_field or "access_token", "")
                except Exception:
                    pass
            if token:
                eff_hdrs["Authorization"] = f"Bearer {token}"
                try:
                    _pld = _json.loads(_b64.b64decode(token.split(".")[1] + "=="))
                    user_id = int(_pld.get("sub", 1))
                except Exception:
                    pass
                pre_scan["auth_valid"] = True
                pre_scan["auth_message"] = "Login flow: token acquired successfully."
            else:
                _sc = r_login.status_code if r_login else "no response"
                pre_scan["auth_valid"] = False
                pre_scan["auth_message"] = (
                    f"Login flow failed (HTTP {_sc}) — wrong credentials or wrong auth endpoint. "
                    "Auth-dependent tests (BOLA, mass assignment, function auth) will be skipped."
                )

        elif eff_hdrs:
            # Token / API-key mode: validate by probing endpoints.
            # Strategy: find an endpoint that returns 401 without auth (auth-gated),
            # then check if OUR credentials get through it.
            _probe_paths = []
            if req.bola_path:
                _probe_paths.append(req.bola_path.replace("{id}", "1"))
            _probe_paths += ["/user", "/me", "/profile", "/api/v1/user",
                             req.auth_endpoint or "", "/health", "/"]
            _probe_paths = [p for p in _probe_paths if p]

            _auth_probed = False
            for _pp in _probe_paths:
                # Step A: probe WITHOUT auth — skip public endpoints
                _r_open = await _async_get(client, base + _pp)
                if _r_open is None or _r_open.status_code == 404:
                    continue  # endpoint doesn't exist, try next
                if _r_open.status_code == 200:
                    continue  # endpoint is public — can't distinguish valid from invalid creds here

                # Step B: this endpoint requires auth — probe WITH our credentials
                _r_auth = await _aget(_pp, hdrs=eff_hdrs)
                if _r_auth is None:
                    continue
                _sc2 = _r_auth.status_code
                if _sc2 == 401:
                    pre_scan["auth_valid"] = False
                    pre_scan["auth_message"] = (
                        f"Credentials rejected (401 on {_pp}). "
                        "Token is invalid, expired, or does not belong to this API. "
                        "Auth-dependent tests will be skipped."
                    )
                elif _sc2 in (200, 204, 206):
                    pre_scan["auth_valid"] = True
                    pre_scan["auth_message"] = f"Credentials valid (HTTP {_sc2} on {_pp})."
                elif _sc2 == 403:
                    pre_scan["auth_valid"] = True
                    pre_scan["auth_message"] = (
                        f"Credentials accepted (403 on {_pp}) — "
                        "authenticated but this scope/path is restricted."
                    )
                else:
                    continue  # inconclusive status, try next path
                _auth_probed = True
                break

            if not _auth_probed:
                pre_scan["auth_valid"] = None
                pre_scan["auth_message"] = (
                    "Could not find an auth-gated endpoint to validate credentials against "
                    "(all probed paths returned 404 or are publicly accessible). "
                    "Tests will run but results may be unreliable."
                )

        # Gate auth-dependent tests: skip entirely if auth is definitively invalid
        _auth_hdrs = eff_hdrs if pre_scan["auth_valid"] is not False else {}

        # ── SPA detection: probe a guaranteed-nonexistent path ───────────────────
        # Single-Page Apps serve the same index.html shell (HTTP 200) for EVERY
        # route, letting client-side JS handle routing + auth. So a 200 on /admin
        # proves nothing. We detect this by requesting a random path that cannot
        # exist; if it also returns 200, the site is a SPA and path enumeration
        # is inconclusive.
        import hashlib as _hashlib
        _spa_detected   = False
        _spa_baseline_len = 0
        _spa_baseline_sig = ""
        try:
            _rnd = "/zz-nonexistent-" + _hashlib.md5(base.encode()).hexdigest()[:10] + "-404probe"
            _rp  = await _async_get(client, base + _rnd)
            if _rp is not None and _rp.status_code == 200:
                _spa_detected     = True
                _spa_baseline_len = len(_rp.content)
                # Signature: collapse whitespace, ignore route-specific URLs
                _norm = _re.sub(r"\s+", " ", (_rp.text or "")).strip()
                _norm = _re.sub(r"https?://[^\s\"'<>]+", "", _norm)
                _spa_baseline_sig = _hashlib.md5(_norm.encode()).hexdigest()
        except Exception:
            pass

        def _body_sig(r) -> str:
            _n = _re.sub(r"\s+", " ", (r.text or "")).strip()
            _n = _re.sub(r"https?://[^\s\"'<>]+", "", _n)
            return _hashlib.md5(_n.encode()).hexdigest()

        # ── API8 / API5: sensitive path enumeration ─────────────────────────────
        def _sensitive_path_result(r) -> tuple:
            """
            Returns (is_vulnerable, actual_description).
            Only flags a path as exposed when genuine unauthenticated content is
            served — not a login page, not a SPA shell, not an error page.
            """
            if r.status_code != 200:
                return False, f"{r.status_code} (access denied or not found)"

            body_lower = (r.text or "").lower()
            ct         = r.headers.get("content-type", "").lower()
            size       = len(r.content)

            # SPA shell check: identical (or near-identical) to the 404-probe shell
            if _spa_detected:
                if _body_sig(r) == _spa_baseline_sig or abs(size - _spa_baseline_len) <= 64:
                    return False, (f"200 — SPA shell ({size} bytes), identical to the "
                                   f"nonexistent-path response. Auth is client-side; "
                                   f"not a real exposure.")

            # Redirected to a login page after following redirects
            final_path = str(r.url).lower()
            if any(kw in final_path for kw in ("/login", "/signin", "/auth/login",
                                                "/sign-in", "/account/login")):
                return False, "200 — redirected to login page (access is protected)"

            # Body contains login-form indicators
            _LOGIN_SIGS = [
                'type="password"', "type='password'",
                'name="password"', 'id="password"',
                "forgot password", "remember me",
                "sign in", "log in", "please login",
                "you must be logged", "authentication required",
                "unauthorized", "login required",
            ]
            if sum(1 for s in _LOGIN_SIGS if s in body_lower) >= 1:
                return False, "200 — login form detected (content is gated)"

            # Genuinely exposed — categorise the response
            if "application/json" in ct:
                return True, f"200 JSON — {size} bytes served without authentication"
            elif "text/html" in ct:
                return True, f"200 HTML — {size} bytes, no login form / SPA shell detected"
            else:
                return True, f"200 {ct.split(';')[0]} — {size} bytes without authentication"

        if "api8" in _run or "api5" in _run:
            if _spa_detected:
                results.append({
                    "test": "Application type detection",
                    "request": f"GET {_rnd} (nonexistent path probe)",
                    "expected": "404 for nonexistent paths",
                    "actual": (f"200 — Single-Page App detected. Every route returns the "
                               f"same {_spa_baseline_len}-byte shell. Path-based access "
                               f"tests are inconclusive; use API discovery (HAR / Capture) "
                               f"to find the real backend endpoints."),
                    "severity": "LOW",
                    "vulnerable": False,
                    "category": "API8:2023 - Security Misconfiguration",
                })
            for path in _SENSITIVE_PATHS:
                r = await _async_get(client, base + path)
                if r is None:
                    continue
                exposed, actual_msg = _sensitive_path_result(r)
                cat = ("API5:2023 - Broken Function Level Authorization"
                       if path in _ADMIN_PATHS else "API8:2023 - Security Misconfiguration")
                results.append({
                    "test": f"Sensitive path: {path}",
                    "request": f"GET {path} (no auth)",
                    "expected": "401, 403, 404, or login redirect",
                    "actual": actual_msg,
                    "severity": "HIGH",
                    "vulnerable": exposed,
                    "category": cat,
                })

        # ── API8: CORS wildcard ──────────────────────────────────────────────────
        if "api8" in _run:
            for probe_path in ["/health", "/"]:
                r = await _async_get(client, base + probe_path,
                                     headers={"Origin": "http://evil.example.com"})
                if r:
                    acao = r.headers.get("access-control-allow-origin", "")
                    results.append({
                        "test": "CORS wildcard header",
                        "request": f"GET {probe_path} (Origin: evil.example.com)",
                        "expected": "No wildcard ACAO",
                        "actual": f"ACAO: {acao or '(none)'}",
                        "severity": "MEDIUM",
                        "vulnerable": acao == "*",
                        "category": "API8:2023 - Security Misconfiguration",
                    })
                    break

            # ── API8: Security headers audit ─────────────────────────────────────
            # These are hardening RECOMMENDATIONS, not exploitable flaws. A missing
            # header means "best practice not applied", so severity is LOW and the
            # wording makes clear it is advisory, not a breach.
            _SEC_HDRS = [
                ("x-content-type-options",  "nosniff", "LOW",
                 "blocks MIME-sniffing attacks"),
                ("x-frame-options",          None,      "LOW",
                 "prevents clickjacking via iframes"),
                ("content-security-policy",  None,      "LOW",
                 "mitigates XSS / injection"),
                ("referrer-policy",          None,      "LOW",
                 "controls referrer leakage"),
            ]
            if base.startswith("https://"):
                _SEC_HDRS.append(("strict-transport-security", None, "MEDIUM",
                                  "enforces HTTPS-only connections"))
            for probe_path in ["/health", "/", "/api"]:
                r = await _async_get(client, base + probe_path)
                if r is not None:
                    for hdr_name, expected_val, sev, why in _SEC_HDRS:
                        actual = r.headers.get(hdr_name, "")
                        present = (actual.lower() == expected_val.lower()
                                   if expected_val else bool(actual))
                        results.append({
                            "test": f"Hardening header: {hdr_name}",
                            "request": f"GET {probe_path}",
                            "expected": f"present ({why})",
                            "actual": (actual if present else
                                       f"not set — recommended: add this header to {why}"),
                            "severity": sev,
                            "vulnerable": not present,
                            "category": "API8:2023 - Security Misconfiguration (hardening)",
                        })
                    break

            # ── API8: OpenAPI / Swagger schema exposure ──────────────────────────
            _SCHEMA_PATHS = [
                "/openapi.json", "/swagger.json", "/api-docs",
                "/redoc", "/swagger-ui.html", "/v1/openapi.json",
            ]
            for sp in _SCHEMA_PATHS:
                r = await _async_get(client, base + sp)
                if r and r.status_code == 200:
                    results.append({
                        "test": f"API schema publicly exposed: {sp}",
                        "request": f"GET {sp} (no auth)",
                        "expected": "404 or 401 — schema not public",
                        "actual": f"200 — schema accessible ({len(r.content)} bytes)",
                        "severity": "MEDIUM",
                        "vulnerable": True,
                        "category": "API8:2023 - Security Misconfiguration",
                    })

            # ── API8: Verbose error / stack trace detection ───────────────────────
            _LEAK_KW = [
                "traceback", "exception", "stack", "sqlstate",
                "syntax error", 'file "', "at line", "undefined method", "null pointer",
            ]
            _ep = req.auth_endpoint or "/auth/login"
            for bad_body in [
                {"username": "' OR '1'='1; --", "password": "x"},
                {"username": None, "password": None},
            ]:
                r2 = await _async_post(client, base + _ep, bad_body)
                if r2 and r2.status_code >= 400:
                    body_text = r2.text.lower()
                    leaks = [kw for kw in _LEAK_KW if kw in body_text]
                    if leaks:
                        results.append({
                            "test": "Verbose error — internal details exposed",
                            "request": f"POST {_ep} (malformed payload)",
                            "expected": "Generic error message only",
                            "actual": f"Response leaks: {', '.join(leaks[:3])}",
                            "severity": "MEDIUM",
                            "vulnerable": True,
                            "category": "API8:2023 - Security Misconfiguration",
                        })
                        break

        # ── API4: rate limiting ──────────────────────────────────────────────────
        if "api4" in _run:
            _rate_ep = req.auth_endpoint or "/auth/login"
            got_429 = False
            for _ in range(12):
                r = await _async_post(client, base + _rate_ep,
                                      {"username": "__probe__", "password": "x"})
                if r and r.status_code == 429:
                    got_429 = True
                    break
            results.append({
                "test": f"Rate limiting on {_rate_ep}",
                "request": f"POST {_rate_ep} x12 rapid (wrong creds)",
                "expected": "429 after repeated failures",
                "actual": "429 received" if got_429 else "No 429 — unlimited attempts",
                "severity": "MEDIUM",
                "vulnerable": not got_429,
                "category": "API4:2023 - Unrestricted Resource Consumption",
            })
            await asyncio.sleep(0.3)

        # ── API2: JWT weak secret + alg:none bypass ──────────────────────────────
        if "api2" in _run:
            _jwt_probe = base + req.bola_path.replace("{id}", "1")
            # Check if this endpoint actually requires auth first
            _r_open = await _async_get(client, _jwt_probe)
            _jwt_endpoint_gated = _r_open is not None and _r_open.status_code in (401, 403)

            try:
                from jose import jwt as jose_jwt
                forged = jose_jwt.encode(
                    {"sub": "1", "username": "alice", "role": "admin"},
                    "secret", algorithm="HS256",
                )
                r = await _aget(req.bola_path.replace("{id}", "1"),
                                hdrs={"Authorization": f"Bearer {forged}"})
                if r is not None:
                    _vuln = r.status_code == 200 and _jwt_endpoint_gated
                    results.append({
                        "test": "JWT weak secret — forge token with key 'secret'",
                        "request": f"GET {req.bola_path.replace('{id}', '1')} (forged JWT, key='secret')",
                        "expected": "401 or 403 (forged token rejected)",
                        "actual": (str(r.status_code) if _jwt_endpoint_gated
                                   else f"{r.status_code} (endpoint is public — result not meaningful)"),
                        "severity": "CRITICAL",
                        "vulnerable": _vuln,
                        "category": "API2:2023 - Broken Authentication",
                    })
            except ImportError:
                pass

            try:
                _hdr_b64 = _b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
                _pld_b64 = _b64.urlsafe_b64encode(
                    b'{"sub":"1","username":"alice","role":"admin"}'
                ).rstrip(b'=').decode()
                alg_none_tok = f"{_hdr_b64}.{_pld_b64}."
                r_alg = await _aget(req.bola_path.replace("{id}", "1"),
                                    hdrs={"Authorization": f"Bearer {alg_none_tok}"})
                if r_alg is not None:
                    _vuln_alg = r_alg.status_code == 200 and _jwt_endpoint_gated
                    results.append({
                        "test": "JWT algorithm confusion — alg:none (unsigned token)",
                        "request": f"GET {req.bola_path.replace('{id}', '1')} (JWT alg=none, no signature)",
                        "expected": "401 — unsigned tokens must be rejected",
                        "actual": (str(r_alg.status_code) if _jwt_endpoint_gated
                                   else f"{r_alg.status_code} (endpoint is public — result not meaningful)"),
                        "severity": "CRITICAL",
                        "vulnerable": _vuln_alg,
                        "category": "API2:2023 - Broken Authentication",
                    })
            except Exception:
                pass

        # ── API1: BOLA — only meaningful when auth works + endpoint is auth-gated ─
        if "api1" in _run and _auth_hdrs.get("Authorization"):
            other_id = 1 if user_id != 1 else 2
            _bola_url = base + req.bola_path.replace("{id}", str(other_id))

            # Check if the endpoint is auth-gated at all
            _r_open = await _async_get(client, _bola_url)
            _bola_endpoint_public = _r_open is not None and _r_open.status_code == 200
            _bola_endpoint_missing = _r_open is not None and _r_open.status_code == 404

            if _bola_endpoint_missing:
                results.append({
                    "test": "BOLA — access another user's resource",
                    "request": f"GET {req.bola_path.replace('{id}', str(other_id))}",
                    "expected": "403",
                    "actual": "404 — path does not exist on this API",
                    "severity": "HIGH",
                    "vulnerable": False,
                    "category": "API1:2023 - Broken Object Level Authorization",
                })
            elif _bola_endpoint_public:
                results.append({
                    "test": "BOLA — access another user's resource",
                    "request": f"GET {req.bola_path.replace('{id}', str(other_id))} (no auth)",
                    "expected": "401 or 403 (resource is private)",
                    "actual": "200 without any credentials — endpoint is publicly accessible",
                    "severity": "HIGH",
                    "vulnerable": False,
                    "category": "API1:2023 - Broken Object Level Authorization",
                })
            else:
                r = await _aget(req.bola_path.replace("{id}", str(other_id)), hdrs=_auth_hdrs)
                status = r.status_code if r else 0
                results.append({
                    "test": "BOLA — access another user's resource",
                    "request": f"GET {req.bola_path.replace('{id}', str(other_id))} (as user #{user_id})",
                    "expected": "403",
                    "actual": str(status),
                    "severity": "HIGH",
                    "vulnerable": status == 200,
                    "category": "API1:2023 - Broken Object Level Authorization",
                })

            # ID enumeration — skip if endpoint is public or missing
            if not _bola_endpoint_missing and not _bola_endpoint_public:
                bola_hits = []
                for probe_id in range(1, 6):
                    if probe_id == user_id:
                        continue
                    r2 = await _aget(req.bola_path.replace("{id}", str(probe_id)), hdrs=_auth_hdrs)
                    if r2 and r2.status_code == 200:
                        bola_hits.append(probe_id)
                results.append({
                    "test": "BOLA — ID enumeration range (IDs 1-5)",
                    "request": f"GET {req.bola_path} for IDs 1-5",
                    "expected": "All non-owned IDs return 403",
                    "actual": (f"IDs {bola_hits} returned 200 (unauthorised access)"
                               if bola_hits else "All non-owned IDs returned 4xx"),
                    "severity": "HIGH",
                    "vulnerable": bool(bola_hits),
                    "category": "API1:2023 - Broken Object Level Authorization",
                })

        # ── API5: Function Level Auth ────────────────────────────────────────────
        if "api5" in _run and _auth_hdrs.get("Authorization"):
            _r_open5 = await _async_get(client, base + req.protected_path)
            if _r_open5 is not None and _r_open5.status_code == 404:
                results.append({
                    "test": "Function auth — regular user calls admin endpoint",
                    "request": f"GET {req.protected_path}",
                    "expected": "403",
                    "actual": "404 — path does not exist on this API",
                    "severity": "HIGH",
                    "vulnerable": False,
                    "category": "API5:2023 - Broken Function Level Authorization",
                })
            elif _r_open5 is not None:
                r = await _aget(req.protected_path, hdrs=_auth_hdrs)
                if r is not None:
                    results.append({
                        "test": "Function auth — regular user calls admin endpoint",
                        "request": f"GET {req.protected_path} (regular user token)",
                        "expected": "403",
                        "actual": str(r.status_code),
                        "severity": "HIGH",
                        "vulnerable": r.status_code == 200,
                        "category": "API5:2023 - Broken Function Level Authorization",
                    })

        # ── API3: Mass assignment ────────────────────────────────────────────────
        if "api3" in _run and _auth_hdrs.get("Authorization"):
            try:
                r = await client.put(
                    base + req.update_path,
                    json={"role": "admin", "balance": 999999},
                    headers={**_base_hdrs, **_auth_hdrs, "Content-Type": "application/json"},
                    params=_q_params,
                    timeout=8,
                )
                if r.status_code in (200, 201):
                    try:
                        body = r.json()
                        user_data = body.get("user", body)
                        escalated = (user_data.get("role") == "admin"
                                     or user_data.get("balance") == 999999)
                    except Exception:
                        escalated = False
                    results.append({
                        "test": "Mass assignment — privilege escalation",
                        "request": f"PUT {req.update_path} {{role:'admin', balance:999999}}",
                        "expected": "400 or 403 (fields rejected)",
                        "actual": f"200 — fields {'accepted' if escalated else 'rejected'}",
                        "severity": "HIGH",
                        "vulnerable": escalated,
                        "category": "API3:2023 - Broken Object Property Level Authorization",
                    })
            except Exception:
                pass

        # ── GraphQL-specific tests ───────────────────────────────────────────────
        if (req.api_type or "rest") == "graphql" and "api8" in _run:
            _gql_ep = req.bola_path if req.bola_path and not "{id}" in req.bola_path else "/graphql"

            # Introspection enabled (security misconfiguration)
            _intro_q = {"query": "{__schema{queryType{name}}}"}
            _ri = await _apost(_gql_ep, _intro_q)
            if _ri is not None:
                _intro_on = (_ri.status_code == 200 and
                             "queryType" in _ri.text and "__schema" in _ri.text)
                results.append({
                    "test": "GraphQL introspection enabled",
                    "request": f"POST {_gql_ep} {{__schema{{queryType{{name}}}}}}",
                    "expected": "400 or disabled in production",
                    "actual": f"{_ri.status_code} — {'schema exposed' if _intro_on else 'not exposed'}",
                    "severity": "MEDIUM",
                    "vulnerable": _intro_on,
                    "category": "API8:2023 - Security Misconfiguration",
                })

            # Batch query attack — can bypass per-operation rate limits
            _batch_q = [{"query": "{__typename}"}, {"query": "{__typename}"}]
            _rb = await _apost(_gql_ep, _batch_q)  # type: ignore
            if _rb is not None:
                _batch_ok = _rb.status_code == 200 and isinstance(_rb.json() if _rb.content else None, list)
                try:
                    _batch_ok = isinstance(_rb.json(), list)
                except Exception:
                    _batch_ok = False
                results.append({
                    "test": "GraphQL batch query accepted",
                    "request": f"POST {_gql_ep} [array of queries]",
                    "expected": "400 — batching disabled or limited",
                    "actual": f"{_rb.status_code} — {'batching accepted' if _batch_ok else 'not accepted'}",
                    "severity": "MEDIUM",
                    "vulnerable": _batch_ok,
                    "category": "API8:2023 - Security Misconfiguration",
                })

            # Field suggestion info disclosure — error messages reveal schema
            _bad_q = {"query": "{user{doesNotExistField}}"}
            _rfs = await _apost(_gql_ep, _bad_q)
            if _rfs is not None and _rfs.status_code in (200, 400):
                _suggests = "did you mean" in _rfs.text.lower()
                results.append({
                    "test": "GraphQL field suggestion disclosure",
                    "request": f"POST {_gql_ep} (invalid field name)",
                    "expected": "No schema hints in error messages",
                    "actual": f"{_rfs.status_code} — {'suggestions exposed' if _suggests else 'no suggestions'}",
                    "severity": "LOW",
                    "vulnerable": _suggests,
                    "category": "API8:2023 - Security Misconfiguration",
                })

            # Depth limit — deeply nested query (resource consumption)
            if "api4" in _run:
                _depth = "a{" * 10 + "__typename" + "}" * 10
                _rdepth = await _apost(_gql_ep, {"query": "{" + _depth + "}"})
                if _rdepth is not None:
                    _depth_ok = _rdepth.status_code == 200 and "data" in _rdepth.text
                    results.append({
                        "test": "GraphQL query depth limit",
                        "request": f"POST {_gql_ep} (10-level nested query)",
                        "expected": "400 — depth limit enforced",
                        "actual": f"{_rdepth.status_code} — {'executed (no depth limit)' if _depth_ok else 'rejected'}",
                        "severity": "MEDIUM",
                        "vulnerable": _depth_ok,
                        "category": "API4:2023 - Unrestricted Resource Consumption",
                    })

        # ── API7:2023: Server-Side Request Forgery (SSRF) ────────────────────
        if "api7" in _run:
            _ssrf_hit = False
            _ssrf_payloads = [
                "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                "http://127.0.0.1:22",                        # internal SSH
                "http://localhost:6379",                       # Redis
                "http://0.0.0.0:80",
            ]
            for _sp in _ssrf_payloads:
                for _param in ["url", "callback", "redirect", "dest", "target", "fetch"]:
                    try:
                        r = await _async_get(client, base + f"/?{_param}={_sp}")
                        if r and r.status_code in (200, 500) and any(
                            kw in r.text.lower() for kw in ["ami-id", "instance", "redis", "ssh", "connection refused"]
                        ):
                            results.append({
                                "test": f"SSRF via ?{_param}= parameter",
                                "request": f"GET /?{_param}={_sp}",
                                "expected": "400 or ignored — no internal service response",
                                "actual": f"{r.status_code} — internal service fingerprint in response",
                                "severity": "CRITICAL",
                                "vulnerable": True,
                                "category": "API7:2023 - Server-Side Request Forgery",
                            })
                            _ssrf_hit = True
                            break
                    except Exception:
                        continue
                if _ssrf_hit:
                    break
            if not _ssrf_hit:
                results.append({
                    "test": "SSRF via URL/callback/redirect parameters",
                    "request": "GET /?url=http://169.254.169.254/... (and common variants)",
                    "expected": "No internal service response",
                    "actual": "No SSRF indicators detected",
                    "severity": "CRITICAL",
                    "vulnerable": False,
                    "category": "API7:2023 - Server-Side Request Forgery",
                })

        # ── API9:2023: Improper Inventory / Shadow APIs ───────────────────────
        if "api9" in _run:
            _shadow_paths = [
                "/v0", "/v0/users", "/api/v0", "/api/v0/users",
                "/api/internal", "/api/admin/internal",
                "/api/test", "/api/debug",
                "/api/v1/users/export", "/api/v1/admin/dump",
                "/api/beta", "/api/legacy", "/api/old",
            ]
            _shadow_found = []
            for _shp in _shadow_paths:
                try:
                    r = await _async_get(client, base + _shp, headers=_auth_hdrs)
                    if r and r.status_code not in (404, 405, 501, 502, 503):
                        _shadow_found.append(f"{_shp} ({r.status_code})")
                except Exception:
                    continue
            results.append({
                "test": "Shadow / undocumented API endpoints",
                "request": f"GET /v0, /api/internal, /api/test, /api/beta (13 probes)",
                "expected": "404 for all undocumented paths",
                "actual": (f"Active: {', '.join(_shadow_found[:4])}" if _shadow_found
                           else "No undocumented endpoints found"),
                "severity": "HIGH",
                "vulnerable": bool(_shadow_found),
                "category": "API9:2023 - Improper Inventory Management",
            })

        # ── Beyond-OWASP: HTTP Verb Tampering ────────────────────────────────
        if "ext_verb" in _run:
            for method_name, endpoint in [("DELETE", "/health"), ("TRACE", "/"), ("PATCH", "/users/1")]:
                try:
                    r = await client.request(method_name, base + endpoint, timeout=6)
                    status = r.status_code
                except Exception:
                    continue
                results.append({
                    "test": f"HTTP verb tampering: {method_name} {endpoint}",
                    "request": f"{method_name} {endpoint}",
                    "expected": "405 Method Not Allowed",
                    "actual": str(status),
                    "severity": "MEDIUM",
                    "vulnerable": status not in (405, 404, 501, 403),
                    "category": "CWE-650 - HTTP Verb Tampering",
                })

        # ── Beyond-OWASP: Path Traversal ──────────────────────────────────────
        if "ext_traversal" in _run:
            _trav_payloads = [
                "/../../../etc/passwd",
                "/%2F..%2F..%2Fetc%2Fpasswd",
                "/static/..%2F..%2F..%2Fetc%2Fshadow",
            ]
            _trav_hit = False
            for payload in _trav_payloads:
                try:
                    r = await _async_get(client, base + payload)
                    if r and r.status_code == 200 and ("root:" in r.text or "daemon:" in r.text):
                        results.append({
                            "test": "Path traversal — system file exposed",
                            "request": f"GET {payload}",
                            "expected": "404 or 400",
                            "actual": "200 — /etc/passwd content in response",
                            "severity": "CRITICAL",
                            "vulnerable": True,
                            "category": "CVE-2021-41773 / CWE-22 - Path Traversal",
                        })
                        _trav_hit = True
                        break
                except Exception:
                    continue
            if not _trav_hit:
                results.append({
                    "test": "Path traversal — system file exposure",
                    "request": "GET /../../../etc/passwd (encoded variants)",
                    "expected": "404 or 400",
                    "actual": "Not vulnerable — traversal payloads rejected",
                    "severity": "CRITICAL",
                    "vulnerable": False,
                    "category": "CVE-2021-41773 / CWE-22 - Path Traversal",
                })

        # ── Beyond-OWASP: SQL Injection ────────────────────────────────────────
        if "ext_injection" in _run:
            _SQL_ERRORS = ["sql", "syntax error", "mysql", "sqlite", "postgres", "ora-", "sqlstate"]
            import urllib.parse as _urlparse
            _sqli_hit = False
            for _sqli_payload in ["' OR '1'='1", "1 OR 1=1--", "' UNION SELECT 1,2,3--"]:
                _enc = _urlparse.quote(_sqli_payload, safe="")
                try:
                    r = await _async_get(client, base + "/users/" + _enc,
                                         headers=_auth_hdrs)
                    if r and r.status_code == 500:
                        _leaks = [kw for kw in _SQL_ERRORS if kw in r.text.lower()]
                        if _leaks:
                            results.append({
                                "test": "SQL injection (error-based detection)",
                                "request": f"GET /users/{_sqli_payload}",
                                "expected": "400 or 422 (input sanitised)",
                                "actual": f"500 — SQL keywords in response: {', '.join(_leaks[:3])}",
                                "severity": "CRITICAL",
                                "vulnerable": True,
                                "category": "CVE-2019-14234 / CWE-89 - SQL Injection",
                            })
                            _sqli_hit = True
                            break
                except Exception:
                    continue
            if not _sqli_hit:
                results.append({
                    "test": "SQL injection (error-based detection)",
                    "request": "GET /users/' OR '1'='1 (and variants)",
                    "expected": "400 or 422",
                    "actual": "No SQL error detected",
                    "severity": "CRITICAL",
                    "vulnerable": False,
                    "category": "CVE-2019-14234 / CWE-89 - SQL Injection",
                })

        # ── Beyond-OWASP: XXE Injection (CWE-611) ────────────────────────────
        if "ext_xxe" in _run:
            _xxe_payload = (
                '<?xml version="1.0"?><!DOCTYPE foo ['
                '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<root>&xxe;</root>'
            )
            _xxe_hit = False
            for _ep in [req.auth_endpoint or "/auth/login", "/"]:
                try:
                    r = await client.post(base + _ep,
                                          content=_xxe_payload.encode(),
                                          headers={**_base_hdrs, "Content-Type": "application/xml"},
                                          timeout=7)
                    if r and ("root:" in r.text or "daemon:" in r.text):
                        results.append({
                            "test": "XXE injection — file disclosure",
                            "request": f"POST {_ep} (XML with SYSTEM entity /etc/passwd)",
                            "expected": "400 — XML parser should reject external entities",
                            "actual": "200 — /etc/passwd contents in response",
                            "severity": "CRITICAL",
                            "vulnerable": True,
                            "category": "CVE-2019-0811 / CWE-611 - XXE Injection",
                        })
                        _xxe_hit = True
                        break
                except Exception:
                    continue
            if not _xxe_hit:
                results.append({
                    "test": "XXE injection — file disclosure",
                    "request": "POST /auth/login (XML SYSTEM entity for /etc/passwd)",
                    "expected": "400 — external entity processing disabled",
                    "actual": "No XXE file disclosure detected",
                    "severity": "CRITICAL",
                    "vulnerable": False,
                    "category": "CVE-2019-0811 / CWE-611 - XXE Injection",
                })

        # ── Beyond-OWASP: CRLF / HTTP Response Splitting (CWE-93) ────────────
        if "ext_crlf" in _run:
            _crlf_payload = "%0d%0aX-Injected: hacked%0d%0a"
            _crlf_hit = False
            try:
                r = await client.get(base + f"/?q={_crlf_payload}test",
                                      follow_redirects=False, timeout=6)
                if r and "x-injected" in r.headers:
                    results.append({
                        "test": "CRLF injection — HTTP header injection",
                        "request": f"GET /?q=%0d%0aX-Injected: hacked",
                        "expected": "No injected header in response",
                        "actual": "X-Injected header present — CRLF accepted",
                        "severity": "HIGH",
                        "vulnerable": True,
                        "category": "CVE-2019-9740 / CWE-93 - CRLF Header Injection",
                    })
                    _crlf_hit = True
            except Exception:
                pass
            if not _crlf_hit:
                results.append({
                    "test": "CRLF injection — HTTP header injection",
                    "request": "GET /?q=%0d%0aX-Injected: hacked",
                    "expected": "No injected header in response",
                    "actual": "CRLF sequence correctly sanitised",
                    "severity": "HIGH",
                    "vulnerable": False,
                    "category": "CVE-2019-9740 / CWE-93 - CRLF Header Injection",
                })

        # ── Beyond-OWASP: Command Injection (CWE-78) ─────────────────────────
        if "ext_cmd" in _run:
            _cmd_payloads = [";id", "| id", "$(id)", "`id`", "&& id"]
            _cmd_hit = False
            import urllib.parse as _uparse2
            for _cp in _cmd_payloads:
                _enc_cp = _uparse2.quote(_cp, safe="")
                try:
                    r = await _async_get(client, base + f"/users/{_enc_cp}")
                    if r and any(kw in r.text for kw in ["uid=", "root", "nobody", "www-data"]):
                        results.append({
                            "test": "Command injection (OS command execution)",
                            "request": f"GET /users/{_cp}",
                            "expected": "400 — shell metacharacters rejected",
                            "actual": f"OS command output in response (uid= detected)",
                            "severity": "CRITICAL",
                            "vulnerable": True,
                            "category": "CVE-2014-6271 / CWE-78 - Command Injection",
                        })
                        _cmd_hit = True
                        break
                except Exception:
                    continue
            if not _cmd_hit:
                results.append({
                    "test": "Command injection (OS command execution)",
                    "request": "GET /users/;id  (and ;| $ ` variants)",
                    "expected": "400 — metacharacters rejected",
                    "actual": "No command execution detected",
                    "severity": "CRITICAL",
                    "vulnerable": False,
                    "category": "CVE-2014-6271 / CWE-78 - Command Injection",
                })

        # ── Beyond-OWASP: Open Redirect ────────────────────────────────────────
        if "ext_redirect" in _run:
            _evil_url = "http://evil.attacker.example.com"
            _redir_hit = False
            for _rp in ["redirect", "url", "next", "return", "goto", "redir"]:
                try:
                    r = await client.get(base + f"/?{_rp}={_evil_url}",
                                         follow_redirects=False, timeout=6)
                    _loc = r.headers.get("location", "")
                    if "evil.attacker.example.com" in _loc:
                        results.append({
                            "test": f"Open redirect via ?{_rp}= parameter",
                            "request": f"GET /?{_rp}={_evil_url}",
                            "expected": "No external redirect",
                            "actual": f"302 → {_loc}",
                            "severity": "MEDIUM",
                            "vulnerable": True,
                            "category": "CVE-2019-11229 / CWE-601 - Open Redirect",
                        })
                        _redir_hit = True
                        break
                except Exception:
                    continue
            if not _redir_hit:
                results.append({
                    "test": "Open redirect via redirect/url/next parameters",
                    "request": f"GET /?redirect={_evil_url} (and variants)",
                    "expected": "No external redirect",
                    "actual": "No open redirect detected",
                    "severity": "MEDIUM",
                    "vulnerable": False,
                    "category": "CVE-2019-11229 / CWE-601 - Open Redirect",
                })

    # ── PII / sensitive data detection ──────────────────────────────────────────
    if "pii" in _run:
        import re as _re_pii
        _PII_PATTERNS = [
            ("Email address",       _re_pii.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
            ("Phone number",        _re_pii.compile(r"(?:\+?\d{1,3}[\-.\s]?)?\(?\d{3}\)?[\-.\s]?\d{3}[\-.\s]?\d{4}")),
            ("Credit card number",  _re_pii.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")),
            ("US Social Security",  _re_pii.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
            ("AWS Access Key",      _re_pii.compile(r"AKIA[0-9A-Z]{16}")),
            ("Password in response",_re_pii.compile(r'"password"\s*:\s*"[^"]{3,}"')),
        ]
        _pii_paths = ["/api/users", "/users", "/api/user", "/profile", "/api/profile",
                      "/api/me", "/me", "/api/customers", "/api/accounts"]
        _pii_found = []
        _pii_at    = None
        for _pp in _pii_paths:
            try:
                _rp = await _aget(_pp, hdrs=_auth_hdrs)
                if _rp and _rp.status_code == 200 and len(_rp.content) > 10:
                    _body = _rp.text
                    _hits = []
                    for _name, _pat in _PII_PATTERNS:
                        _m = _pat.findall(_body)
                        if _m:
                            _hits.append(f"{_name} (×{len(_m)})")
                    if _hits:
                        _pii_found = _hits
                        _pii_at    = _pp
                        break
            except Exception:
                continue
        results.append({
            "test": f"PII / sensitive data in API responses",
            "request": f"GET {_pii_at or _pii_paths[0]} (authenticated)",
            "expected": "Response must not contain unnecessary PII",
            "actual": (f"PII detected at {_pii_at}: {'; '.join(_pii_found[:4])}"
                       if _pii_found else "No PII patterns detected in sampled responses"),
            "severity": "HIGH",
            "vulnerable": bool(_pii_found),
            "category": "CWE-312 / GDPR - PII Exposure in API Response",
        })

    # ── GraphQL scan (probes even for REST targets) ───────────────────────────
    if "graphql_scan" in _run and (req.api_type or "rest") == "rest":
        for _gql_path in ["/graphql", "/api/graphql", "/v1/graphql"]:
            try:
                _gr = await _apost(_gql_path, {"query": "{ __schema { types { name } } }"})
                if _gr and _gr.status_code == 200 and "__schema" in _gr.text:
                    results.append({
                        "test": f"GraphQL introspection enabled at {_gql_path}",
                        "request": f"POST {_gql_path} (introspection query)",
                        "expected": "404 or introspection disabled",
                        "actual": f"200 — full schema returned ({len(_gr.content)} bytes)",
                        "severity": "MEDIUM",
                        "vulnerable": True,
                        "category": "API9:2023 - Improper Inventory Management",
                    })
                    break
            except Exception:
                continue

    # Group results by category
    buckets: dict = {}
    for t in results:
        cat = t["category"]
        if cat not in buckets:
            buckets[cat] = {"category": cat, "tests": [], "vulnerable_count": 0, "total": 0}
        buckets[cat]["tests"].append({k: v for k, v in t.items() if k != "category"})
        buckets[cat]["total"] += 1
        if t["vulnerable"]:
            buckets[cat]["vulnerable_count"] += 1

    _COMPLIANCE_MAP_M = {
        "API1:2023 - Broken Object Level Authorization":          {"pci_dss":["6.2.4","8.2.3"],    "gdpr":["Art. 5(1)(f)","Art. 32"],   "iso27001":["A.9.4.1","A.14.2.5"]},
        "API2:2023 - Broken Authentication":                      {"pci_dss":["8.2.1","8.3.1"],    "gdpr":["Art. 32(1)(b)"],            "iso27001":["A.9.4.3","A.10.1.1"]},
        "API3:2023 - Broken Object Property Level Authorization": {"pci_dss":["6.2.4"],            "gdpr":["Art. 5(1)(c)","Art. 25"],   "iso27001":["A.14.2.5","A.18.1.3"]},
        "API4:2023 - Unrestricted Resource Consumption":          {"pci_dss":["6.2.4","6.3.1"],    "gdpr":["Art. 32"],                  "iso27001":["A.12.6.1","A.17.2.1"]},
        "API5:2023 - Broken Function Level Authorization":        {"pci_dss":["7.1.1","7.2.1"],    "gdpr":["Art. 32(4)"],               "iso27001":["A.9.2.3","A.9.4.1"]},
        "API7:2023 - Server-Side Request Forgery":                {"pci_dss":["6.2.4","6.3.3"],    "gdpr":["Art. 32"],                  "iso27001":["A.13.1.3","A.14.2.5"]},
        "API8:2023 - Security Misconfiguration":                  {"pci_dss":["6.3.3","6.4.1"],    "gdpr":["Art. 32"],                  "iso27001":["A.14.1.3","A.18.1.3"]},
        "API9:2023 - Improper Inventory Management":              {"pci_dss":["6.3.3"],            "gdpr":["Art. 32"],                  "iso27001":["A.12.6.1"]},
        "CWE-312 / GDPR - PII Exposure in API Response":         {"pci_dss":["3.4.1","4.2.1"],    "gdpr":["Art. 5","Art. 17","Art. 25","Art. 32","Art. 83(4)"], "iso27001":["A.18.1.4","A.8.2.3"]},
        "CVE-2021-41773 / CWE-22 - Path Traversal":              {"pci_dss":["6.2.4"],            "gdpr":["Art. 32"],                  "iso27001":["A.14.2.5"]},
        "CVE-2019-14234 / CWE-89 - SQL Injection":               {"pci_dss":["6.2.4"],            "gdpr":["Art. 32"],                  "iso27001":["A.14.2.5"]},
        "CVE-2014-6271 / CWE-78 - Command Injection":            {"pci_dss":["6.2.4"],            "gdpr":["Art. 32"],                  "iso27001":["A.14.2.5"]},
    }
    grouped = list(buckets.values())
    for g in grouped:
        for key, cval in _COMPLIANCE_MAP_M.items():
            if g["category"] == key or g["category"].startswith(key.split(" - ")[0]):
                g["compliance"] = cval
                break

    total_v = sum(g["vulnerable_count"] for g in grouped)
    total_t = sum(g["total"] for g in grouped)
    score   = round((1 - total_v / total_t) * 100) if total_t else 100

    return JSONResponse({
        "target":           req.target,
        "timestamp":        datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "score":            score,
        "total_tests":      total_t,
        "total_vulnerable": total_v,
        "categories":       grouped,
        "pre_scan":         pre_scan,
    })


@app.post("/monitor/scan/sarif")
async def scan_sarif(req: ScanRequest):
    """Run a full scan and return the results as a SARIF 2.1.0 document."""
    scan_resp = await external_scan(req)
    data = _json.loads(scan_resp.body)
    categories = data.get("categories", [])

    seen: set = set()
    rules = []
    for cat in categories:
        rid = cat["category"].replace(" ", "-").replace("/", "-")[:64]
        if rid not in seen:
            seen.add(rid)
            rules.append({
                "id": rid,
                "name": cat["category"].split(" - ")[0],
                "shortDescription": {"text": cat["category"].split(" - ", 1)[-1]},
                "helpUri": "https://owasp.org/API-Security/",
            })

    sarif_results = []
    for cat in categories:
        rid = cat["category"].replace(" ", "-").replace("/", "-")[:64]
        for t in cat.get("tests", []):
            if not t.get("vulnerable"):
                continue
            sarif_results.append({
                "ruleId": rid,
                "level": "error" if t.get("severity") in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f"{t['test']}: {t['actual']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": req.target, "uriBaseId": "TARGETROOT"}}}],
                "properties": {"severity": t.get("severity"), "compliance": cat.get("compliance", {})},
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "MazAPI Scanner", "version": "2.0.0", "rules": rules}},
            "results": sarif_results,
            "properties": {"target": req.target, "scannedAt": datetime.utcnow().isoformat()},
        }],
    }
    return JSONResponse(sarif, media_type="application/sarif+json")


class WebhookConfig(BaseModel):
    webhook_url: str
    target: str
    score: float
    total_tests: int
    total_vulnerable: int
    categories: list = []


@app.post("/monitor/scan/notify")
async def send_scan_webhook(cfg: WebhookConfig):
    """POST scan results to a Slack/Teams webhook URL."""
    import httpx as _httpx_wh
    vulns    = [t for cat in cfg.categories for t in cat.get("tests", []) if t.get("vulnerable")]
    critical = [t for t in vulns if t.get("severity") == "CRITICAL"]
    payload  = {
        "source": "MazAPI Scanner (monitoring service)",
        "target": cfg.target,
        "score":  cfg.score,
        "scanned_at": datetime.utcnow().isoformat(),
        "summary": f"{cfg.total_vulnerable}/{cfg.total_tests} tests vulnerable",
        "critical": len(critical),
        "text": f"*MazAPI Alert* — `{cfg.target}`\nScore: *{cfg.score}%* | Vulnerable: {cfg.total_vulnerable}/{cfg.total_tests} | Critical: {len(critical)}",
        "findings": [{"test": t["test"], "severity": t.get("severity"), "actual": t.get("actual")} for t in vulns[:10]],
    }
    try:
        async with _httpx_wh.AsyncClient() as c:
            r = await c.post(cfg.webhook_url, json=payload, timeout=10)
        return {"ok": True, "status": r.status_code}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


class PostmanRequest(BaseModel):
    target: str
    endpoints: dict = {}


@app.post("/monitor/export/postman")
async def export_postman(req: PostmanRequest):
    """Generate a Postman collection from a discovered endpoint map."""
    host = req.target.replace("http://","").replace("https://","").rstrip("/")
    items = []
    for path, data in req.endpoints.items():
        method = (data.get("methods") or ["GET"])[0]
        items.append({
            "name": f"{method} {path}",
            "request": {
                "method": method,
                "header": [{"key": "Authorization", "value": "Bearer {{bearerToken}}"}],
                "url": {"raw": req.target + path, "host": [host], "path": [p for p in path.split("/") if p]},
            },
            "response": [],
        })
    collection = {
        "info": {
            "name": f"MazAPI — {req.target}",
            "description": f"Discovered by MazAPI Scanner on {datetime.utcnow().isoformat()}",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
        "variable": [{"key": "baseUrl", "value": req.target}, {"key": "bearerToken", "value": ""}],
    }
    return JSONResponse(collection)


@app.post("/monitor/export/openapi")
async def export_openapi(req: PostmanRequest):
    """Generate an OpenAPI 3.0 spec from a discovered endpoint map."""
    paths = {}
    for path, data in req.endpoints.items():
        oa_path = path.replace("{id}", "{id}")
        paths[oa_path] = {}
        for method in (data.get("methods") or ["get"]):
            paths[oa_path][method.lower()] = {
                "summary": f"{method} {path}",
                "security": [{"bearerAuth": []}] if data.get("authRequired") else [],
                "responses": {"200": {"description": "Success"}, "401": {"description": "Unauthorized"}},
            }
    spec = {
        "openapi": "3.0.3",
        "info": {"title": f"MazAPI Discovery — {req.target}", "version": "1.0.0",
                 "description": f"Auto-discovered by MazAPI Scanner on {datetime.utcnow().isoformat()}"},
        "servers": [{"url": req.target}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": paths,
    }
    return JSONResponse(spec)


@app.get("/monitor/scan/capture")
async def playwright_capture(
    url: str,
    username:      Optional[str] = None,
    password:      Optional[str] = None,
    auth_endpoint: Optional[str] = None,
    token_field:   Optional[str] = None,
):
    """
    Headless browser capture + multi-strategy login + OpenAPI discovery + path probing.
    Login tries 12+ endpoint variants and 5 credential field structures automatically.
    """
    try:
        from playwright.async_api import async_playwright
        _pw_ok = True
    except ImportError:
        _pw_ok = False

    from urllib.parse import urlparse
    import re as _re3

    parsed_base = urlparse(url)
    base_url    = f"{parsed_base.scheme}://{parsed_base.netloc}"
    endpoints: set = set()
    tokens: list   = []
    api_keys: list = []
    requests_intercepted = 0
    pw_note = ""
    login_steps: list = []   # audit trail shown to user

    # ── Helper: recursively scan any JSON object for a JWT string ─────────────
    def _find_jwt(obj, _hint_field: str = "", _depth: int = 0) -> str:
        if _depth > 4:
            return ""
        if isinstance(obj, str):
            if _re3.match(r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.', obj):
                return obj
        elif isinstance(obj, dict):
            # Priority: check hinted field name first
            for k in ([_hint_field] if _hint_field else []) + [
                "access_token", "token", "jwt", "id_token", "auth_token",
                "accessToken", "jwtToken", "authToken", "bearer",
                "sessionToken", "userToken", "api_token",
            ]:
                if k and obj.get(k):
                    found = _find_jwt(obj[k], "", _depth + 1)
                    if found:
                        return found
            # Full scan of all values
            for v in obj.values():
                found = _find_jwt(v, "", _depth + 1)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj[:5]:
                found = _find_jwt(item, "", _depth + 1)
                if found:
                    return found
        return ""

    # ── Phase 1: Playwright headless browser capture ──────────────────────────
    if _pw_ok:
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage",
                          "--disable-setuid-sandbox", "--disable-gpu"]
                )
                ctx  = await browser.new_context()
                page = await ctx.new_page()

                async def on_request(req):
                    nonlocal requests_intercepted
                    requests_intercepted += 1
                    auth = req.headers.get("authorization", "")
                    if auth.lower().startswith("bearer "):
                        tok = auth[7:].strip()
                        if tok and tok not in tokens:
                            tokens.append(tok)
                    for hk in ("x-api-key", "x-auth-token", "api-key"):
                        val = req.headers.get(hk, "")
                        if val and not any(k["header"] == hk for k in api_keys):
                            api_keys.append({"header": hk, "value": val})
                    try:
                        p      = urlparse(req.url)
                        path_n = _re3.sub(r"/\d+", "/{id}", p.path)
                        if p.netloc == parsed_base.netloc and len(path_n) > 1:
                            endpoints.add(path_n)
                    except Exception:
                        pass

                page.on("request", on_request)

                # ── Strategy A: Multi-endpoint API login ──────────────────────
                login_token  = ""
                login_ep_used = ""
                if username and password:
                    # Build list of endpoints to probe — user hint first, then common patterns
                    _ep_candidates = []
                    if auth_endpoint:
                        _ep_candidates.append(auth_endpoint)
                    for _ep in [
                        "/auth/login", "/api/auth/login", "/api/login",
                        "/login", "/signin", "/api/signin",
                        "/api/v1/auth/login", "/api/v1/login", "/api/v2/login",
                        "/user/login", "/users/login", "/account/login",
                        "/auth/signin", "/api/auth/signin", "/auth/token",
                    ]:
                        if _ep not in _ep_candidates:
                            _ep_candidates.append(_ep)

                    # Credential body variants — try email field as well as username
                    _cred_variants = [
                        {"username": username, "password": password},
                        {"email": username,    "password": password},
                        {"user": username,     "password": password},
                        {"login": username,    "password": password},
                        {"identifier": username, "password": password},
                    ]

                    async with httpx.AsyncClient(follow_redirects=True, timeout=6) as _lc:
                        for _ep in _ep_candidates:
                            if login_token:
                                break
                            for _creds in _cred_variants:
                                try:
                                    _lr = await _lc.post(base_url + _ep, json=_creds)
                                    login_steps.append(f"POST {_ep} ({list(_creds.keys())[0]}={username[:6]}…) → {_lr.status_code}")
                                    if _lr.status_code in (200, 201):
                                        try:
                                            _tok = _find_jwt(_lr.json(), token_field or "")
                                            if _tok:
                                                login_token   = _tok
                                                login_ep_used = _ep
                                                break
                                        except Exception:
                                            pass
                                except Exception as _e:
                                    login_steps.append(f"POST {_ep} → error ({type(_e).__name__})")
                                    break  # endpoint unreachable, skip remaining variants

                    if login_token:
                        tokens.insert(0, login_token)
                        await ctx.set_extra_http_headers({"Authorization": f"Bearer {login_token}"})
                        pw_note = f"API login OK via {login_ep_used}. "
                    else:
                        # ── Strategy B: Navigate to login pages, fill HTML form ─
                        _form_pages = list(dict.fromkeys([
                            url,
                            base_url + "/login",
                            base_url + "/signin",
                            base_url + "/auth/login",
                            base_url + "/account/login",
                            base_url + "/sign-in",
                        ]))
                        _form_done = False
                        for _lp in _form_pages:
                            if _form_done:
                                break
                            try:
                                await page.goto(_lp, wait_until="domcontentloaded", timeout=10000)
                                pwd_sel = await page.query_selector("input[type='password']")
                                if not pwd_sel:
                                    continue
                                # Fill credential field — target by name/type precisely to avoid
                                # honeypot fields (common in Laravel/anti-bot forms).
                                # Priority: named email/username fields first; never fill
                                # type=text fields that lack a recognisable name.
                                _filled_user = False
                                for _usr_sel_q in [
                                    "input[name='email']",
                                    "input[name='username']",
                                    "input[name='user']",
                                    "input[name='login']",
                                    "input[name='identifier']",
                                    "input[type='email']",
                                    "input[id='email']",
                                    "input[id='username']",
                                ]:
                                    _usr_sel = await page.query_selector(_usr_sel_q)
                                    if _usr_sel:
                                        _vis = await _usr_sel.is_visible()
                                        if _vis:
                                            await _usr_sel.fill(username)
                                            _filled_user = True
                                            break

                                if not _filled_user:
                                    login_steps.append(f"No clear email/username field at {_lp} — skipping to avoid honeypot")
                                    continue

                                await pwd_sel.fill(password)

                                # Submit
                                _submit = await page.query_selector(
                                    "button[type='submit'], input[type='submit']"
                                )
                                if not _submit:
                                    _submit = await page.query_selector(
                                        "button:has-text('Login'), button:has-text('Sign in'), "
                                        "button:has-text('Log in'), button:has-text('Continue')"
                                    )
                                if _submit:
                                    await _submit.click()
                                else:
                                    await pwd_sel.press("Enter")

                                await page.wait_for_load_state("networkidle", timeout=12000)

                                # Check if login succeeded: URL changed or no password field visible
                                new_url = page.url
                                still_on_login = await page.query_selector("input[type='password']")
                                if still_on_login:
                                    login_steps.append(f"Form at {_lp} → still on login page (wrong credentials or 2FA required)")
                                else:
                                    login_steps.append(f"Form login OK at {_lp} → redirected to {new_url}")
                                    pw_note = f"HTML form login succeeded at {_lp}. "
                                    _form_done = True

                                    # Capture session cookies (Laravel / session-based sites)
                                    _cookies = await ctx.cookies()
                                    for _ck in _cookies:
                                        if _ck["name"].lower() in (
                                            "laravel_session", "session", "auth", "remember_token",
                                            "connect.sid", "phpsessid", "asp.net_sessionid",
                                        ):
                                            api_keys.append({
                                                "header": f"Cookie: {_ck['name']}",
                                                "value":  _ck["value"][:60],
                                            })
                                            login_steps.append(f"Session cookie captured: {_ck['name']}")

                            except Exception as _fe:
                                login_steps.append(f"Form at {_lp} → {type(_fe).__name__}: {str(_fe)[:60]}")
                                continue

                        if not _form_done:
                            pw_note = (
                                "Login could not be automated. Common reasons: "
                                "(1) Wrong credentials. "
                                "(2) Site uses Google/OAuth SSO — cannot be scripted. "
                                "(3) CAPTCHA or 2FA required. "
                                "Tip: Log in manually in your browser, export a HAR file "
                                "from DevTools → Network, then use Import HAR instead."
                            )

                # ── Navigate (authenticated) and capture traffic ──────────────
                try:
                    await page.goto(url, wait_until="networkidle", timeout=20000)
                except Exception:
                    pass
                # Also intercept any tokens sent by the page after login
                for tok in tokens:
                    if tok not in tokens[:1]:
                        tokens.insert(0, tok)
                await browser.close()

            pw_note = (pw_note or "") + f"Browser intercepted {requests_intercepted} requests."
        except Exception as e:
            pw_note = f"Browser capture error: {e}"
    else:
        pw_note = "Playwright not available — running discovery only."

    # ── Phase 2: OpenAPI / Swagger schema discovery ───────────────────────────
    auth_endpoint = "/auth/login"
    async with httpx.AsyncClient(follow_redirects=True, timeout=6) as client:
        for schema_path in ["/openapi.json", "/swagger.json", "/api-docs",
                             "/v1/openapi.json", "/api/openapi.json"]:
            try:
                r = await client.get(base_url + schema_path)
                if r.status_code == 200:
                    schema = r.json()
                    for p in schema.get("paths", {}).keys():
                        endpoints.add(p)
                    break
            except Exception:
                continue

        # ── Phase 3: Common path probing ─────────────────────────────────────
        probe_paths = [
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/auth/login", "/auth/token",
            "/users", "/api/users", "/v1/users",
            "/orders", "/api/orders",
            "/products", "/api/products",
            "/health", "/api/health",
        ]
        for pp in probe_paths:
            try:
                r = await client.get(base_url + pp)
                if r.status_code not in (404, 502, 503, 504):
                    endpoints.add(pp)
                    if "login" in pp or "token" in pp:
                        auth_endpoint = pp
            except Exception:
                continue

    path_list = sorted(endpoints)[:60]
    bola_path = "/users/{id}"
    update_path = "/users/1"
    protected_path = "/admin/users"
    for p in path_list:
        if "{id}" in p and ("user" in p.lower() or "order" in p.lower()):
            bola_path   = p
            update_path = p.replace("{id}", "1")
            break
    for p in path_list:
        if "admin" in p.lower():
            protected_path = p.replace("{id}", "1")
            break

    return {
        "base_url":              base_url,
        "token":                 tokens[0] if tokens else "",
        "api_keys":              api_keys[:3],
        "paths":                 path_list,
        "total_paths":           len(path_list),
        "bola_path":             bola_path,
        "update_path":           update_path,
        "protected_path":        protected_path,
        "auth_endpoint":         auth_endpoint,
        "requests_intercepted":  requests_intercepted,
        "note":                  pw_note,
        "login_steps":           login_steps,
        "auth_type":             "bearer" if tokens else ("cookie" if api_keys else "none"),
    }


@app.post("/monitor/scan/import-har")
async def import_har(request: Request):
    """
    Parse a HAR (HTTP Archive) file and extract API discovery data.
    Accepts raw HAR JSON in the request body.
    Returns: base_url, token, endpoints, auth_header, request_schemas
    """
    try:
        har = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON — expected a HAR file")

    entries = har.get("log", {}).get("entries", [])
    if not entries:
        raise HTTPException(400, "HAR file contains no network entries")

    from urllib.parse import urlparse
    endpoints: set   = set()
    tokens: list     = []
    api_keys: list   = []
    base_candidates: dict = {}   # origin → count
    schemas: list    = []        # {method, path, body_sample}
    auth_endpoint    = None

    for entry in entries:
        req  = entry.get("request", {})
        resp = entry.get("response", {})
        url  = req.get("url", "")
        if not url:
            continue
        try:
            parsed   = urlparse(url)
            origin   = f"{parsed.scheme}://{parsed.netloc}"
            path     = parsed.path
            method   = req.get("method", "GET").upper()
            status   = resp.get("status", 0)
        except Exception:
            continue

        # Count origins to find the dominant API base
        base_candidates[origin] = base_candidates.get(origin, 0) + 1

        # Collect paths that look like API routes
        if any(seg in path for seg in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/",
                                        "/auth/", "/users", "/orders", "/products"]):
            endpoints.add(path)

        # Extract auth tokens from request headers
        for hdr in req.get("headers", []):
            name  = hdr.get("name",  "").lower()
            value = hdr.get("value", "")
            if name == "authorization":
                if value.lower().startswith("bearer "):
                    tok = value[7:].strip()
                    if tok and tok not in tokens:
                        tokens.append(tok)
                elif value.lower().startswith("basic "):
                    pass  # skip basic creds
            if name in ("x-api-key", "x-auth-token", "api-key", "apikey"):
                if value and value not in api_keys:
                    api_keys.append({"header": hdr["name"], "value": value})

        # Detect the login endpoint (POST that returns 200 with a body containing "token")
        if method == "POST" and status == 200:
            try:
                resp_content = resp.get("content", {}).get("text", "")
                if resp_content and any(kw in resp_content for kw in
                                        ["access_token", "token", "jwt", "bearer"]):
                    auth_endpoint = path
            except Exception:
                pass

        # Capture request body sample for schema hints
        if method in ("POST", "PUT", "PATCH") and len(schemas) < 5:
            post_data = req.get("postData", {})
            body_text = post_data.get("text", "")
            if body_text and len(body_text) < 500:
                try:
                    _json.loads(body_text)  # only collect valid JSON
                    schemas.append({"method": method, "path": path,
                                    "body_sample": body_text[:200]})
                except Exception:
                    pass

    # Pick the most-seen origin as the base URL
    base_url = max(base_candidates, key=base_candidates.get) if base_candidates else ""

    # Strip base_url prefix from collected paths
    path_list = sorted({p for p in endpoints})[:60]

    # Auto-detect BOLA path (first path with an integer segment)
    bola_path = "/users/{id}"
    for p in path_list:
        import re as _re2
        if _re2.search(r"/\d+", p):
            bola_path = _re2.sub(r"/\d+", "/{id}", p)
            break

    return {
        "base_url":      base_url,
        "token":         tokens[0] if tokens else "",
        "all_tokens":    tokens[:5],
        "api_keys":      api_keys[:3],
        "paths":         path_list,
        "total_paths":   len(path_list),
        "auth_endpoint": auth_endpoint or "/auth/login",
        "bola_path":     bola_path,
        "schemas":       schemas,
        "entries_parsed": len(entries),
    }


@app.get("/monitor/scan/discover")
async def discover_schema(target: str):
    """
    Discover API endpoints from a website URL using three strategies:
      1. OpenAPI / Swagger documentation (most accurate)
      2. HTML + JS file crawling — regex-scan fetch/axios/XHR calls in JS bundles
      3. Common path probing — /api, /api/v1, /api/v2, /graphql, etc.
    """
    base = target.rstrip("/")
    discovered: set  = set()
    schema_info: dict = {"found": False, "schema_path": None,
                         "api_title": "", "api_version": ""}
    sources: dict = {"openapi": False, "js_crawl": False, "path_probe": False}

    async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:

        # ── Strategy 1: OpenAPI / Swagger documentation ───────────────────────
        for path in ["/openapi.json", "/swagger.json", "/api-docs",
                     "/v1/openapi.json", "/api/openapi.json",
                     "/swagger/v1/swagger.json", "/api/swagger.json"]:
            try:
                r = await client.get(base + path)
                if r.status_code == 200:
                    try:
                        schema = r.json()
                        paths  = list(schema.get("paths", {}).keys())
                        info   = schema.get("info", {})
                        schema_info = {
                            "found":       True,
                            "schema_path": path,
                            "api_title":   info.get("title", ""),
                            "api_version": info.get("version", ""),
                        }
                        for p in paths[:80]:
                            discovered.add(p)
                        sources["openapi"] = True
                    except Exception:
                        schema_info = {"found": True, "schema_path": path,
                                       "api_title": "", "api_version": ""}
                        sources["openapi"] = True
                    break
            except Exception:
                continue

        # ── Strategy 2: HTML fetch + linked JS crawl ──────────────────────────
        js_urls: set = set()
        try:
            r = await client.get(base + "/", timeout=6)
            if r.status_code == 200 and "html" in r.headers.get("content-type", ""):
                html = r.text
                # Collect <script src="..."> URLs
                for m in _re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html):
                    src = m.group(1)
                    if src.startswith("//"):
                        src = "https:" + src
                    elif not src.startswith("http"):
                        src = base + ("" if src.startswith("/") else "/") + src
                    if any(ext in src for ext in [".js", ".mjs", ".bundle", ".chunk"]):
                        js_urls.add(src)
                # Also scan inline scripts for API patterns
                for m in _re.finditer(r'["\`](/(?:api|v\d+|graphql|rest|service)[^\s"\'`?#]{1,80})',
                                       html):
                    discovered.add(m.group(1))
        except Exception:
            pass

        # Scan each JS file for fetch/axios/XHR patterns
        _API_PATS = [
            r'fetch\s*\(\s*["\`]([/][^\s"\'`?#]{3,80})',
            r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\`]([/][^\s"\'`?#]{3,80})',
            r'\.open\s*\(\s*["\']\w+["\'][,\s]+["\`]([/][^\s"\'`?#]{3,80})',
            r'(?:url|endpoint|path|route)\s*[:=]\s*["\`]([/][^\s"\'`?#]{3,80})',
            r'["\`](/(?:api|v\d+|graphql|rest|service)[^\s"\'`?#]{1,80})',
        ]
        for js_url in list(js_urls)[:12]:
            try:
                jr = await client.get(js_url, timeout=5)
                if jr.status_code == 200:
                    js_text = jr.text
                    for pat in _API_PATS:
                        for m in _re.finditer(pat, js_text):
                            p = m.group(1).rstrip("\"'`")
                            if 3 < len(p) < 100 and not p.startswith("//"):
                                discovered.add(p)
                    if len(discovered) > 5:
                        sources["js_crawl"] = True
            except Exception:
                continue

        # ── Strategy 3: Common path probing ──────────────────────────────────
        _PROBE_PATHS = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/rest", "/service",
            "/api/users", "/api/products", "/api/orders", "/api/auth",
            "/v1/users", "/v2/users",
            "/api/health", "/api/status",
        ]
        for probe in _PROBE_PATHS:
            try:
                r = await client.get(base + probe, timeout=4)
                if r.status_code not in (404, 502, 503, 504):
                    discovered.add(probe)
                    sources["path_probe"] = True
            except Exception:
                continue

    path_list = sorted(discovered)
    return {
        **schema_info,
        "paths":       path_list[:80],
        "total_paths": len(path_list),
        "sources":     sources,
    }


_SCAN_UI_HTML_V2 = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MazAPI Scanner</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700;800&family=Fira+Code:wght@400;500&display=swap');

:root {
  --bg: #090d16;
  --surf: #111827;
  --surf-alt: #1f293d;
  --border: rgba(255, 255, 255, 0.08);
  --border-glow: rgba(99, 102, 241, 0.4);
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --blue: #6366f1;
  --green: #10b981;
  --red: #ef4444;
  --yellow: #f59e0b;
  --orange: #f97316;
  --purple: #8b5cf6;
  --accent-dim: rgba(99, 102, 241, 0.08);
  --radius: 12px;
  --shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
  --font-title: 'Outfit', sans-serif;
  --font-body: 'Inter', sans-serif;
}

[data-theme="light"] {
  --bg: #f8fafc;
  --surf: #ffffff;
  --surf-alt: #f1f5f9;
  --border: rgba(148, 163, 184, 0.2);
  --border-glow: rgba(79, 70, 229, 0.3);
  --text: #0f172a;
  --text-muted: #64748b;
  --blue: #4f46e5;
  --green: #059669;
  --red: #dc2626;
  --yellow: #d97706;
  --orange: #ea580c;
  --purple: #7c3aed;
  --accent-dim: rgba(79, 70, 229, 0.06);
  --shadow: 0 4px 20px rgba(149, 157, 165, 0.1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font-body);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  transition: background 0.2s, color 0.2s;
}

nav {
  background: var(--surf);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
  padding: 0 24px;
  display: flex;
  align-items: center;
  gap: 20px;
  height: 60px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 1px 2px rgba(0,0,0,0.05);
}
nav .logo {
  color: var(--green);
  font-family: var(--font-title);
  font-weight: 800;
  font-size: 1.25em;
  letter-spacing: -0.02em;
}
nav a {
  color: var(--text-muted);
  font-size: 0.9em;
  text-decoration: none;
  font-weight: 600;
  transition: color 0.15s;
}
nav a:hover {
  color: var(--blue);
}

.wrap { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
h1 {
  font-family: var(--font-title);
  color: var(--text);
  font-weight: 800;
  font-size: 2.2em;
  margin-bottom: 8px;
  letter-spacing: -0.02em;
}
.sub {
  color: var(--text-muted);
  font-size: 0.95em;
  margin-bottom: 24px;
  line-height: 1.5;
}

.card {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px;
  margin-bottom: 24px;
  box-shadow: var(--shadow);
  transition: border-color 0.2s, box-shadow 0.2s;
}
.card:hover {
  border-color: var(--border-glow);
}
.card h2 {
  font-family: var(--font-title);
  font-size: 1em;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--blue);
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
@media (max-width: 768px) {
  .row { grid-template-columns: 1fr; gap: 0; }
}
.field { margin-bottom: 18px; }
.field label {
  display: block;
  font-size: 0.85em;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 8px;
}
.field input, .field textarea, .field select, .settings-card input {
  width: 100%;
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  padding: 10px 14px;
  font-size: 0.9em;
  font-family: inherit;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.field input:focus, .field textarea:focus, .field select:focus, .settings-card input:focus {
  outline: none;
  border-color: var(--blue);
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
}
.hint {
  font-size: 0.78em;
  color: var(--text-muted);
  margin-top: 6px;
  line-height: 1.4;
}

.auth-tabs {
  display: flex;
  gap: 8px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 20px;
  overflow-x: auto;
}
.auth-tab {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  cursor: pointer;
  padding: 10px 16px;
  font-size: 0.88em;
  font-weight: 500;
  transition: all 0.2s;
  font-family: inherit;
  white-space: nowrap;
}
.auth-tab:hover {
  color: var(--text);
  background: rgba(255,255,255,.02);
}
.auth-tab.active {
  color: var(--blue);
  border-bottom-color: var(--blue);
  font-weight: 600;
}

.disc-row { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
.btn-disc {
  background: var(--accent-dim);
  border: 1px solid var(--border);
  color: var(--blue);
  border-radius: 8px;
  padding: 8px 16px;
  font-size: 0.85em;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.2s;
}
.btn-disc:hover {
  background: rgba(99, 102, 241, 0.15);
  border-color: var(--blue);
}

.test-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 600px) {
  .test-grid { grid-template-columns: 1fr; }
}
.test-lbl {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 14px;
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}
.test-lbl:hover {
  border-color: var(--blue);
  background: var(--surf);
}
.test-lbl input[type=checkbox] {
  margin-top: 3px;
  flex-shrink: 0;
  accent-color: var(--blue);
  cursor: pointer;
  width: 16px;
  height: 16px;
}
.cat-name {
  display: block;
  font-size: 0.9em;
  font-weight: 600;
  color: var(--text);
}
.cat-desc {
  display: block;
  font-size: 0.78em;
  color: var(--text-muted);
  margin-top: 4px;
  line-height: 1.4;
}

.link-btn {
  background: none;
  border: none;
  color: var(--blue);
  cursor: pointer;
  font-size: 0.85em;
  font-weight: 600;
  text-decoration: underline;
  padding: 4px;
  font-family: inherit;
}
.link-btn:hover {
  color: var(--green);
}

.btn {
  padding: 10px 24px;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.9em;
  font-weight: 600;
  font-family: inherit;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.btn-primary {
  background: linear-gradient(135deg, var(--green) 0%, #059669 100%);
  color: #fff;
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.2);
}
.btn-primary:hover {
  background: linear-gradient(135deg, #10b981 0%, #047857 100%);
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(16, 185, 129, 0.3);
}
.btn-primary:disabled {
  opacity: .5;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

#status-bar {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 20px;
  margin: 20px 0;
  font-size: 0.9em;
  box-shadow: var(--shadow);
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--text);
}
.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid var(--border);
  border-top-color: var(--blue);
  border-radius: 50%;
  animation: spin .7s linear infinite;
  vertical-align: middle;
  margin-right: 8px;
}
@keyframes spin { to { transform: rotate(360deg); } }

.score-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}
@media (max-width: 768px) {
  .score-row { grid-template-columns: 1fr 1fr; }
}
.scard {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  text-align: center;
  box-shadow: var(--shadow);
  transition: transform 0.2s;
}
.scard:hover {
  transform: translateY(-2px);
}
.scard .num {
  font-family: var(--font-title);
  font-size: 2.2em;
  font-weight: 800;
  line-height: 1.1;
}
.scard .lbl {
  color: var(--text-muted);
  font-size: 0.82em;
  margin-top: 6px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.red { color: var(--red); }
.green { color: var(--green); }
.blue { color: var(--blue); }
.yellow { color: var(--yellow); }

.cat-block {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 16px;
  overflow: hidden;
  box-shadow: var(--shadow);
}
.cat-hdr {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  background: var(--surf-alt);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.cat-hdr h3 {
  font-family: var(--font-title);
  font-size: 1.05em;
  font-weight: 700;
  color: var(--text);
}
.badge {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 0.78em;
  font-weight: 700;
}
.bv {
  background: rgba(239, 68, 68, 0.08);
  color: var(--red);
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.bs {
  background: rgba(16, 185, 129, 0.08);
  color: var(--green);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
.sev-CRITICAL { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid var(--red); }
.sev-HIGH { background: rgba(244, 63, 94, 0.15); color: var(--red); border: 1px solid var(--red); }
.sev-MEDIUM { background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid var(--yellow); }
.sev-LOW { background: rgba(99, 102, 241, 0.15); color: var(--blue); border: 1px solid var(--blue); }

table { width: 100%; border-collapse: collapse; }
th {
  background: var(--surf-alt);
  padding: 12px 16px;
  text-align: left;
  font-size: 0.75em;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  font-size: 0.88em;
  word-break: break-word;
}
code {
  background: var(--surf-alt);
  padding: 3px 6px;
  border-radius: 4px;
  font-size: 0.85em;
  font-family: 'Fira Code', Consolas, monospace;
}
.vY { color: var(--red); font-weight: 700; white-space: nowrap; }
.vN { color: var(--green); white-space: nowrap; }

.cve-panel {
  padding: 20px;
  border-top: 1px solid var(--border);
  background: var(--surf-alt);
}
.cve-panel h4 {
  color: var(--text-muted);
  font-size: 0.78em;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 12px;
  font-weight: 700;
}
.cve-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 14px;
  align-items: center;
}
.cve-badge {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 0.8em;
  font-family: 'Fira Code', monospace;
  color: var(--blue);
  text-decoration: none;
  transition: all 0.2s;
}
.cve-badge:hover {
  border-color: var(--blue);
  background: var(--accent-dim);
}
.owasp-link {
  font-size: 0.82em;
  color: var(--text-muted);
  text-decoration: none;
  margin-left: auto;
  font-weight: 500;
}
.owasp-link:hover { color: var(--blue); }
.vuln-desc {
  font-size: 0.88em;
  color: var(--text-muted);
  margin-bottom: 14px;
  line-height: 1.6;
}
.fixes ol { padding-left: 20px; }
.fixes li {
  font-size: 0.88em;
  color: var(--text);
  line-height: 1.65;
  padding: 3px 0;
}

.export-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 20px;
  margin-top: 20px;
  flex-wrap: wrap;
  box-shadow: var(--shadow);
}
.btn-save {
  padding: 8px 16px;
  border: 1px solid;
  border-radius: 8px;
  font-size: 0.85em;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.2s;
}
.btn-save-brief {
  background: rgba(16, 185, 129, 0.08);
  color: var(--green);
  border-color: rgba(16, 185, 129, 0.3);
}
.btn-save-brief:hover {
  background: rgba(16, 185, 129, 0.15);
  border-color: var(--green);
}
.btn-save-detail {
  background: rgba(99, 102, 241, 0.08);
  color: var(--blue);
  border-color: rgba(99, 102, 241, 0.3);
}
.btn-save-detail:hover {
  background: rgba(99, 102, 241, 0.15);
  border-color: var(--blue);
}

.presets {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 16px;
  align-items: center;
}
.preset {
  background: var(--surf-alt);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 20px;
  padding: 6px 16px;
  cursor: pointer;
  font-size: 0.82em;
  font-weight: 500;
  transition: all 0.2s;
  font-family: inherit;
}
.preset:hover {
  border-color: var(--blue);
  color: var(--blue);
  background: var(--surf);
}

.api-type-btn {
  background: var(--surf-alt);
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 8px;
  padding: 8px 20px;
  cursor: pointer;
  font-size: 0.85em;
  font-weight: 600;
  transition: all 0.2s;
  font-family: inherit;
}
.api-type-btn:hover { color: var(--text); }
.api-type-btn.active {
  background: var(--accent-dim);
  border-color: var(--blue);
  color: var(--blue);
}

#help-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.5);
  backdrop-filter: blur(4px);
  z-index: 998;
  display: none;
  cursor: pointer;
}
#help-overlay.open { display: block; }
#help-panel {
  position: fixed;
  top: 0;
  right: -460px;
  width: 440px;
  max-width: 96vw;
  height: 100vh;
  background: var(--surf);
  border-left: 1px solid var(--border);
  z-index: 999;
  overflow: hidden;
  transition: right .28s cubic-bezier(.4,0,.2,1);
  display: flex;
  flex-direction: column;
  box-shadow: -8px 0 32px rgba(0,0,0,0.2);
}
#help-panel.open { right: 0; }
.hp-hdr {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky;
  top: 0;
  background: var(--surf);
  z-index: 1;
  flex-shrink: 0;
}
.hp-hdr h2 {
  flex: 1;
  font-family: var(--font-title);
  font-size: 1.15em;
  color: var(--text);
  font-weight: 700;
}
.hp-hdr-icon { font-size: 1.4em; }
.hp-close {
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 1.2em;
  padding: 6px 10px;
  border-radius: 6px;
  transition: all 0.2s;
}
.hp-close:hover { color: var(--text); background: var(--surf-alt); }
.hp-search {
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.hp-search input {
  width: 100%;
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  padding: 10px 14px;
  font-size: 0.9em;
  font-family: inherit;
  transition: all 0.2s;
}
.hp-search input:focus { outline: none; border-color: var(--blue); }
.hp-body { padding: 20px 24px; flex: 1; overflow-y: auto; }
.faq-section {
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 10px;
  overflow: hidden;
  transition: all 0.2s;
  background: var(--surf-alt);
}
.faq-section:hover { border-color: var(--border-glow); }
.faq-q {
  width: 100%;
  background: none;
  border: none;
  padding: 14px 18px;
  text-align: left;
  cursor: pointer;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  color: var(--text);
  font-size: 0.92em;
  font-weight: 600;
  font-family: inherit;
  line-height: 1.4;
  transition: all 0.2s;
}
.faq-q:hover { background: rgba(255,255,255,.02); }
.faq-q.open { color: var(--blue); }
.faq-icon {
  color: var(--text-muted);
  font-size: 0.8em;
  flex-shrink: 0;
  margin-top: 4px;
  transition: transform .2s ease;
}
.faq-q.open .faq-icon { transform: rotate(180deg); color: var(--blue); }
.faq-a {
  display: none;
  padding: 0 18px 16px;
  font-size: 0.88em;
  color: var(--text-muted);
  line-height: 1.65;
  border-top: 1px solid var(--border);
  background: var(--surf);
}
.faq-a.open { display: block; }
.faq-a p { margin-bottom: 8px; }
.faq-a p:last-child { margin-bottom: 0; }
.faq-step {
  background: var(--surf-alt);
  border-radius: 6px;
  padding: 8px 12px;
  margin: 8px 0;
  font-family: monospace;
  font-size: 0.85em;
  color: var(--text);
  border-left: 3px solid var(--blue);
}
.faq-tag {
  display: inline-block;
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 6px;
  font-family: monospace;
  font-size: 0.82em;
  color: var(--blue);
  margin: 0 2px;
}
.faq-warn {
  background: rgba(245, 158, 11, 0.08);
  border-left: 3px solid var(--yellow);
  border-radius: 6px;
  padding: 8px 12px;
  margin: 8px 0;
  font-size: 0.85em;
  color: var(--yellow);
}
.faq-tip {
  background: rgba(16, 185, 129, 0.08);
  border-left: 3px solid var(--green);
  border-radius: 6px;
  padding: 8px 12px;
  margin: 8px 0;
  font-size: 0.85em;
  color: var(--green);
}
.faq-divider {
  font-family: var(--font-title);
  font-size: 0.78em;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--text-muted);
  margin: 20px 0 10px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}

#capture-status-box {
  display: none;
  border-radius: 8px;
  padding: 16px;
  margin: 12px 0;
  border: 2px solid rgba(16, 185, 129, 0.4);
  background: rgba(16, 185, 129, 0.05);
  animation: capPulse 1.8s ease-in-out infinite;
}
#capture-status-box.error {
  border-color: rgba(239, 68, 68, 0.4);
  background: rgba(239, 68, 68, 0.05);
  animation: none;
}
#capture-status-box.done {
  border-color: rgba(16, 185, 129, 0.4);
  background: rgba(16, 185, 129, 0.05);
  animation: none;
}
@keyframes capPulse {
  0%, 100% { border-color: rgba(16, 185, 129, 0.3); box-shadow: none; }
  50% { border-color: rgba(16, 185, 129, 0.8); box-shadow: 0 0 12px rgba(16, 185, 129, 0.15); }
}
#capture-status-main { font-size: 1.05em; font-weight: 700; color: var(--green); }
#capture-status-box.error #capture-status-main { color: var(--red); }
#capture-status-box.done #capture-status-main { color: var(--green); }
#capture-status-detail { font-size: 0.83em; color: var(--text-muted); margin-top: 6px; line-height: 1.5; }
#capture-login-steps {
  font-size: 0.8em;
  font-family: monospace;
  color: var(--text-muted);
  margin-top: 8px;
  max-height: 100px;
  overflow-y: auto;
  background: var(--surf-alt);
  border-radius: 6px;
  padding: 8px 12px;
  border: 1px solid var(--border);
  display: none;
}
#btn-stop-capture {
  margin-top: 10px;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.4);
  color: var(--red);
  border-radius: 6px;
  padding: 8px 16px;
  font-size: 0.85em;
  cursor: pointer;
  font-family: inherit;
  display: none;
  transition: all 0.2s;
}
#btn-stop-capture:hover { background: rgba(239, 68, 68, 0.2); }

.capture-locked input:not(#cap-username):not(#cap-password):not(#cap-auth-ep):not(#cap-token-field),
.capture-locked textarea,
.capture-locked .btn-disc:not(#btn-stop-capture),
.capture-locked .preset,
.capture-locked .api-type-btn,
.capture-locked label[style*="cursor:pointer"] {
  pointer-events: none; opacity: .45;
}

.step-pane { display: none; }
.step-pane.active { display: block; }
.wizard-bar {
  display: flex;
  align-items: center;
  margin-bottom: 30px;
  background: var(--surf);
  border: 1px solid var(--border);
  padding: 16px 20px;
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow-x: auto;
}
.ws {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  transition: all 0.2s;
  flex-shrink: 0;
}
.ws:hover { opacity: .8; }
.ws-circle {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  border: 2px solid var(--border);
  color: var(--text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.85em;
  font-weight: 700;
  flex-shrink: 0;
  transition: all 0.2s;
  background: var(--surf-alt);
}
.ws-lbl {
  font-size: 0.85em;
  color: var(--text-muted);
  white-space: nowrap;
  font-weight: 600;
  transition: all 0.2s;
}
.ws-line {
  flex: 1;
  height: 2px;
  background: var(--border);
  margin: 0 16px;
  min-width: 24px;
  transition: background 0.3s;
}
.ws.active .ws-circle {
  border-color: var(--blue);
  color: #fff;
  background: var(--blue);
  box-shadow: 0 0 10px rgba(99, 102, 241, 0.4);
}
.ws.active .ws-lbl { color: var(--text); font-weight: 700; }
.ws.done .ws-circle { border-color: var(--green); background: var(--green); color: #fff; }
.ws.done .ws-lbl { color: var(--green); }
.ws.reachable .ws-circle { border-color: var(--blue); color: var(--blue); }
.ws.reachable .ws-lbl { color: var(--blue); }
.ws.reachable:hover .ws-circle { background: rgba(99, 102, 241, 0.15); }
.ws-line.done { background: var(--green); }

.step-nav { display: flex; align-items: center; gap: 12px; margin-top: 24px; }
.btn-next {
  background: linear-gradient(135deg, var(--blue) 0%, #4f46e5 100%);
  color: #fff;
  border: none;
  border-radius: 8px;
  padding: 10px 24px;
  font-size: 0.9em;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.2s;
  box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
}
.btn-next:hover {
  background: linear-gradient(135deg, #818cf8 0%, #4338ca 100%);
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(99, 102, 241, 0.3);
}
.btn-back {
  background: none;
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 8px;
  padding: 10px 20px;
  font-size: 0.9em;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.2s;
}
.btn-back:hover { border-color: var(--blue); color: var(--blue); background: var(--surf-alt); }
#help-btn {
  background: var(--accent-dim);
  border: 1px solid var(--border);
  color: var(--blue);
  border-radius: 50%;
  width: 32px;
  height: 32px;
  cursor: pointer;
  font-size: 0.95em;
  font-weight: 700;
  font-family: inherit;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: all 0.2s;
}
#help-btn:hover { border-color: var(--blue); background: rgba(99, 102, 241, 0.15); transform: translateY(-1px); }

.info-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 50%;
  font-size: .75em;
  color: var(--text-muted);
  cursor: pointer;
  margin-left: 6px;
  vertical-align: middle;
  flex-shrink: 0;
  transition: all 0.2s;
}
.info-icon:hover { border-color: var(--blue); color: var(--blue); }
.card-num {
  display: inline-block;
  background: var(--accent-dim);
  color: var(--blue);
  border-radius: 4px;
  font-size: .75em;
  font-weight: 700;
  padding: 2px 8px;
  margin-right: 8px;
  vertical-align: middle;
}
.prescan-ok { color: var(--green); font-weight: 600; }
.prescan-warn { color: var(--yellow); font-weight: 600; }
.prescan-err { color: var(--red); font-weight: 600; }

.compliance-row { font-size: 0.8em; color: var(--text-muted); margin-top: 8px; line-height: 1.7; }
.comp-chip {
  display: inline-block;
  background: var(--accent-dim);
  color: var(--blue);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 8px;
  margin-right: 6px;
  font-size: .88em;
}
.evidence-block { margin-top: 10px; }
.evidence-block summary { font-size: 0.85em; color: var(--blue); cursor: pointer; user-select: none; font-weight: 600; }
.evidence-pre {
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  margin-top: 8px;
  font-family: 'Fira Code', monospace;
  font-size: 0.82em;
  white-space: pre-wrap;
  color: var(--text);
  word-break: break-all;
  overflow-x: auto;
}
.fp-row { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.fp-btn {
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.8em;
  cursor: pointer;
  background: var(--surf-alt);
  color: var(--text-muted);
  font-family: inherit;
  transition: all 0.2s;
}
.fp-btn:hover { border-color: var(--blue); color: var(--blue); }
.fp-btn.active { background: var(--accent-dim); border-color: var(--blue); color: var(--blue); }
.reg-badge {
  display: inline-block;
  border: 1px solid;
  border-radius: 4px;
  padding: 2px 8px;
  font-size: 0.75em;
  font-weight: 700;
  margin-left: 8px;
  vertical-align: middle;
}
.result-fp { opacity: .55; }
.history-block {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 20px;
  margin-bottom: 12px;
  box-shadow: var(--shadow);
}
.history-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.settings-card {
  background: var(--surf-alt);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 18px;
}
.settings-card h3 {
  font-size: 0.8em;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--text-muted);
  margin-bottom: 12px;
}

/* Theme float toggle button in header */
.theme-toggle-btn {
  margin-left: auto;
  background: var(--surf-alt);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 99px;
  height: 32px;
  padding: 0 16px;
  cursor: pointer;
  font-size: 0.85em;
  font-weight: 600;
  font-family: inherit;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 1px 2px rgba(0,0,0,0.05);
}
.theme-toggle-btn:hover {
  border-color: var(--blue);
  background: var(--accent-dim);
  color: var(--blue);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(99, 102, 241, 0.12);
}
.theme-toggle-btn:active {
  transform: translateY(0);
}

/* CSS overrides for hardcoded inline styles */
.sub[style*="color:#3fb950"] {
  color: var(--green) !important;
}
.card > div[style*="dashed"] {
  border: 1px dashed var(--border) !important;
}
div[style*="dashed"] div[style*="color:#8b949e"] {
  color: var(--text-muted) !important;
}
#capture-auth-details > div {
  background: var(--surf-alt) !important;
  border-color: var(--border) !important;
}
#capture-auth-details input {
  background: var(--surf) !important;
  border-color: var(--border) !important;
  color: var(--text) !important;
}
.settings-card input {
  background: var(--surf-alt) !important;
  border-color: var(--border) !important;
  color: var(--text) !important;
}

/* SVG dynamic gradient & shape fills */
#spr stop:first-child { stop-color: var(--green) !important; }
#spr stop:last-child { stop-color: var(--blue) !important; }
#swv stop { stop-color: var(--green) !important; }
svg path[stroke="#dde3ec"] { stroke: var(--text) !important; }
svg circle[fill="#00d4ff"] { fill: var(--green) !important; }
svg circle[fill="#7c3aed"] { fill: var(--blue) !important; }
</style>
</style>
</head>
<body>
<div id="help-overlay"></div>
<div id="help-panel">
  <div class="hp-hdr">
    <span class="hp-hdr-icon">❓</span>
    <h2>Help &amp; FAQ</h2>
    <button class="hp-close" id="help-close">&#10005;</button>
  </div>
  <div class="hp-search">
    <input type="text" id="faq-search" placeholder="Search questions…">
  </div>
  <div class="hp-body" id="faq-body">

    <div class="faq-divider">Getting Started</div>

    <div class="faq-section" data-keywords="credentials json login auth body browser devtools network">
      <button class="faq-q" id="fq-1">How do I find the login credentials (JSON) in my browser? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-1">
        <p>You need to capture what the app sends when you log in:</p>
        <div class="faq-step">1. Open your web app in Chrome / Edge / Firefox</div>
        <div class="faq-step">2. Press <b>F12</b> to open Developer Tools</div>
        <div class="faq-step">3. Click the <b>Network</b> tab</div>
        <div class="faq-step">4. Log in to the app normally</div>
        <div class="faq-step">5. Find the request called <b>login</b>, <b>token</b>, or <b>auth</b></div>
        <div class="faq-step">6. Click it → open the <b>Payload</b> or <b>Request Body</b> tab</div>
        <div class="faq-step">7. You will see JSON like:<br><span class="faq-tag">{"username":"alice","password":"alice123"}</span></div>
        <div class="faq-tip">Copy that JSON exactly into the <b>Auth Body (JSON)</b> field and set the <b>Auth Endpoint</b> to the path (e.g. /auth/login).</div>
      </div>
    </div>

    <div class="faq-section" data-keywords="token bearer jwt get copy response">
      <button class="faq-q" id="fq-2">How do I get a Bearer token from my browser? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-2">
        <p>After logging in, the API responds with a token:</p>
        <div class="faq-step">1. Open DevTools → Network tab → log in</div>
        <div class="faq-step">2. Click the login request → open <b>Response</b> tab</div>
        <div class="faq-step">3. Look for a field called <b>access_token</b>, <b>token</b>, or <b>jwt</b></div>
        <div class="faq-step">4. Copy the value — it starts with <span class="faq-tag">eyJ</span></div>
        <div class="faq-step">5. Switch to <b>Bearer Token</b> auth mode and paste it</div>
        <div class="faq-warn">Tokens expire. If you get 401 errors, get a fresh token.</div>
      </div>
    </div>

    <div class="faq-section" data-keywords="auth endpoint login path url where">
      <button class="faq-q" id="fq-3">How do I find the auth endpoint? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-3">
        <p>Common patterns for the login endpoint:</p>
        <div class="faq-step">/auth/login &nbsp; /login &nbsp; /api/token</div>
        <div class="faq-step">/users/login &nbsp; /auth/token &nbsp; /signin</div>
        <p>To find the exact path: DevTools → Network → log in → right-click the request → Copy → Copy URL. Or use <b>Discover APIs</b> to auto-detect it.</p>
        <div class="faq-tip">For the lab APIs, the endpoint is <span class="faq-tag">/auth/login</span> — this is already the default.</div>
      </div>
    </div>

    <div class="faq-divider">Auth Modes</div>

    <div class="faq-section" data-keywords="auth mode login flow bearer api key query param basic which choose">
      <button class="faq-q" id="fq-4">Which auth mode should I choose? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-4">
        <p><b>Login Flow</b> — you have a username and password. The scanner logs in first, then uses the token it gets. Best choice if you have credentials.</p>
        <p><b>Bearer Token</b> — you already have a JWT / token. Paste it directly. Use when you grabbed the token from DevTools.</p>
        <p><b>API Key Header</b> — the API uses a custom header like <span class="faq-tag">X-API-Key: abc123</span>. Enter the header name and value.</p>
        <p><b>Query Param</b> — the key is in the URL: <span class="faq-tag">?key=abc123</span>. Used by Google, OpenWeather, etc.</p>
        <p><b>HTTP Basic Auth</b> — legacy APIs that use username:password as a base64 header. Enter username and password separately.</p>
        <p><b>None</b> — public APIs with no authentication. Only unauthenticated tests will run.</p>
        <div class="faq-tip">For Google Gemini: use <b>Query Param</b> mode, param name = <span class="faq-tag">key</span>.</div>
      </div>
    </div>

    <div class="faq-divider">Running Scans</div>

    <div class="faq-section" data-keywords="discover schema api find detect crawl js javascript">
      <button class="faq-q" id="fq-5">How does Discover APIs work? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-5">
        <p>Click <b>Discover APIs</b> after entering the target URL. The scanner tries three strategies:</p>
        <div class="faq-step"><b>1. OpenAPI / Swagger docs</b> — checks /openapi.json, /swagger.json, /api-docs, etc.</div>
        <div class="faq-step"><b>2. JavaScript analysis</b> — fetches the page HTML, finds linked .js files, scans them for fetch() / axios / XHR calls</div>
        <div class="faq-step"><b>3. Path probing</b> — tries /api, /api/v1, /api/v2, /graphql, /rest, and 10+ common paths</div>
        <p>Found endpoints are shown below the button and automatically fill the BOLA Path, Update Path, and Protected Path fields.</p>
        <div class="faq-warn">For lab APIs, enter the Docker name like <span class="faq-tag">http://vulnerable-api:8000</span>, not localhost.</div>
      </div>
    </div>

    <div class="faq-section" data-keywords="tests skipped skip why auth dependent">
      <button class="faq-q" id="fq-6">Why are some tests being skipped? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-6">
        <p>Tests marked <b>auth-dependent</b> — BOLA, Mass Assignment, and Function Level Auth — need a valid token to run.</p>
        <p>They are skipped when:</p>
        <div class="faq-step">&#x2022; You chose <b>None</b> auth mode</div>
        <div class="faq-step">&#x2022; Your credentials were rejected (401 from the login endpoint)</div>
        <div class="faq-step">&#x2022; The login endpoint path is wrong</div>
        <p>Check the <b>Pre-Scan Validation</b> section at the top of the results for the exact reason.</p>
      </div>
    </div>

    <div class="faq-section" data-keywords="bola path template id what">
      <button class="faq-q" id="fq-7">What is the BOLA Path / {id} template? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-7">
        <p>BOLA (Broken Object Level Authorization) tests whether you can access another user's resource.</p>
        <p>The <b>BOLA Path</b> field takes a path template with <span class="faq-tag">{id}</span> as a placeholder:</p>
        <div class="faq-step">/users/{id} &nbsp; → &nbsp; scanner tries /users/1, /users/2, /users/3…</div>
        <div class="faq-step">/orders/{id} &nbsp; → &nbsp; tries order IDs belonging to other users</div>
        <p>A secure API returns <b>403 Forbidden</b> when you access another user's resource. A vulnerable API returns 200 with the data.</p>
      </div>
    </div>

    <div class="faq-divider">Understanding Results</div>

    <div class="faq-section" data-keywords="score result pass fail percentage mean">
      <button class="faq-q" id="fq-8">What does the security score mean? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-8">
        <p>Score = (Secure tests ÷ Total tests) × 100%</p>
        <div class="faq-step">100% — All tested categories are secure &#x2705;</div>
        <div class="faq-step">0% — Every tested category is vulnerable &#x274C;</div>
        <p><b>SECURE (green)</b> = The API correctly blocked the attack<br>
           <b>VULNERABLE (red)</b> = The API has this flaw — it needs to be fixed</p>
        <div class="faq-warn">A score below 100% means there are real security issues. Each red result is a vulnerability an attacker could exploit.</div>
      </div>
    </div>

    <div class="faq-section" data-keywords="bola what is broken object level authorization">
      <button class="faq-q" id="fq-9">What is BOLA? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-9">
        <p><b>Broken Object Level Authorization</b> — the #1 API vulnerability (OWASP 2023).</p>
        <p>Example: You are logged in as User 1. Can you do <span class="faq-tag">GET /users/2</span> and see User 2's data? You should get 403. If you get 200, the API is vulnerable.</p>
        <p>The scanner logs in as a real user, then requests another user's resource using their token. A 200 response means BOLA is present.</p>
      </div>
    </div>

    <div class="faq-section" data-keywords="mass assignment role admin what is">
      <button class="faq-q" id="fq-10">What is mass assignment? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-10">
        <p>When an API accepts more fields in a request than it should, allowing an attacker to overwrite protected properties.</p>
        <div class="faq-step">Scanner sends: PUT /users/1 {"role":"admin","balance":999999}</div>
        <p>A secure API ignores unknown fields (allowlist validation). A vulnerable API writes them to the database, making the attacker an admin.</p>
      </div>
    </div>

    <div class="faq-section" data-keywords="beyond owasp extra verb tampering traversal injection redirect">
      <button class="faq-q" id="fq-11">What are the Beyond OWASP tests? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-11">
        <p>These are common vulnerabilities outside the OWASP API Top 10 but still important:</p>
        <div class="faq-step"><b>Verb Tampering</b> — tries DELETE/TRACE on GET-only endpoints. Expect 405.</div>
        <div class="faq-step"><b>Path Traversal</b> — tries /../../../etc/passwd and encoded variants. Expect 404.</div>
        <div class="faq-step"><b>SQL Injection</b> — sends SQL chars in URL params. Looks for SQL error keywords in 500 responses.</div>
        <div class="faq-step"><b>Open Redirect</b> — tests ?redirect= and ?url= params for external 3xx redirects.</div>
      </div>
    </div>

    <div class="faq-divider">Reports &amp; Export</div>

    <div class="faq-section" data-keywords="report save export download brief detailed">
      <button class="faq-q" id="fq-12">How do I save a scan report? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-12">
        <p>After the scan completes, scroll to the bottom of the results and click:</p>
        <div class="faq-step"><b>Save Brief Report</b> — summary table with pass/fail per test</div>
        <div class="faq-step"><b>Save Detailed Report</b> — includes CVE IDs, OWASP links, fix guidance</div>
        <p>Reports are saved to the monitoring service at <span class="faq-tag">/reports</span> and appear in the <b>Monitor Dashboard → Reports</b> tab.</p>
      </div>
    </div>

    <div class="faq-section" data-keywords="google gemini api key external real">
      <button class="faq-q" id="fq-13">How do I scan the Google Gemini API? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-13">
        <p>Click the <b>Google Gemini API</b> preset — it fills in everything automatically.</p>
        <div class="faq-step">1. Go to <b>aistudio.google.com/app/apikey</b> and create a free key</div>
        <div class="faq-step">2. Paste your key into the <b>API Key Value</b> field</div>
        <div class="faq-step">3. Click <b>Run Scan</b></div>
        <p>The scanner uses Query Param auth (<span class="faq-tag">?key=…</span>). Auth-dependent tests (BOLA, mass assignment) are skipped since Gemini is a public API.</p>
      </div>
    </div>

    <div class="faq-section" data-keywords="lab docker vulnerable hardened localhost">
      <button class="faq-q" id="fq-14">How do I scan the lab APIs? <span class="faq-icon">&#9660;</span></button>
      <div class="faq-a" id="fa-14">
        <p>Use the quick preset buttons at the top of the page. They fill all fields automatically:</p>
        <div class="faq-step"><b>Vulnerable API (lab)</b> — tests the intentionally broken API at port 8000</div>
        <div class="faq-step"><b>Hardened API (lab)</b> — tests the secured API at port 8001</div>
        <div class="faq-warn">Use Docker container names (e.g. <span class="faq-tag">http://vulnerable-api:8000</span>), not localhost — scans run inside the container network.</div>
        <div class="faq-tip">Compare both scores side-by-side to see the impact of each security fix.</div>
      </div>
    </div>

  </div>
</div>

<nav>
  <span class="logo">MazAPI Scanner</span>
  <a href="/dashboard">&#128200; Monitor</a>
  <a href="http://localhost:8000/ui" target="_blank">&#128722; Shop App</a>
  <a href="http://localhost:8000/docs" target="_blank">&#128196; API Docs</a>
  <button class="theme-toggle-btn" id="theme-toggle-btn" onclick="toggleTheme()" title="Toggle Theme">☀️ Light</button>
  <button type="button" id="help-btn" title="Help &amp; FAQ">?</button>
</nav>
<div class="wrap">
  <div style="text-align:center;margin-bottom:16px">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="80" height="80" style="display:inline-block;margin-bottom:12px">
      <defs>
        <linearGradient id="spr" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#00d4ff"/><stop offset="100%" stop-color="#7c3aed"/></linearGradient>
        <linearGradient id="swv" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="#00d4ff" stop-opacity="0"/><stop offset="20%" stop-color="#00d4ff"/><stop offset="80%" stop-color="#00d4ff"/><stop offset="100%" stop-color="#00d4ff" stop-opacity="0"/></linearGradient>
        <filter id="sgl"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        <filter id="ssg"><feGaussianBlur stdDeviation="1.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <polygon points="100,24 161,59 161,129 100,164 39,129 39,59" fill="url(#spr)" fill-opacity="0.14"/>
      <polygon points="100,24 161,59 161,129 100,164 39,129 39,59" fill="none" stroke="url(#spr)" stroke-width="2.5" filter="url(#sgl)"/>
      <polygon points="100,44 143,69 143,119 100,144 57,119 57,69" fill="none" stroke="url(#spr)" stroke-width="0.8" opacity="0.22"/>
      <circle cx="100" cy="44" r="3" fill="#00d4ff" opacity="0.45"/>
      <circle cx="143" cy="69" r="2.5" fill="#7c3aed" opacity="0.45"/>
      <circle cx="143" cy="119" r="2.5" fill="#7c3aed" opacity="0.45"/>
      <circle cx="100" cy="144" r="3" fill="#00d4ff" opacity="0.45"/>
      <circle cx="57" cy="119" r="2.5" fill="#7c3aed" opacity="0.45"/>
      <circle cx="57" cy="69" r="2.5" fill="#7c3aed" opacity="0.45"/>
      <circle cx="68"  cy="65" r="5.5" fill="#00d4ff" opacity="0.9" filter="url(#ssg)"/>
      <circle cx="100" cy="96" r="5.5" fill="#00d4ff" opacity="0.8" filter="url(#ssg)"/>
      <circle cx="132" cy="65" r="5.5" fill="#00d4ff" opacity="0.9" filter="url(#ssg)"/>
      <path d="M68,120 L68,65 L100,96 L132,65 L132,120" fill="none" stroke="#dde3ec" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M68,120 L68,65 L100,96 L132,65 L132,120" fill="none" stroke="url(#spr)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.4"/>
      <path d="M70,145 L80,135 L90,152 L100,135 L110,152 L120,135 L130,145" fill="none" stroke="url(#swv)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" filter="url(#ssg)"/>
      <circle cx="80" cy="135" r="2.5" fill="#00d4ff" opacity="0.9"/>
      <circle cx="90" cy="152" r="2" fill="#00d4ff" opacity="0.55"/>
      <circle cx="100" cy="135" r="2.5" fill="#00d4ff" opacity="0.9"/>
      <circle cx="110" cy="152" r="2" fill="#00d4ff" opacity="0.55"/>
      <circle cx="120" cy="135" r="2.5" fill="#00d4ff" opacity="0.9"/>
    </svg>
    <h1>MazAPI Scanner</h1>
    <p class="sub">Multi-standard API vulnerability scanner — OWASP API Top 10, MITRE ATT&amp;CK, CWE. Four-step wizard, 15 test categories, no source code needed.</p>
    <p class="sub" style="color:#3fb950;font-size:.82em;margin-top:6px">&#128274; Runs entirely on your machine. No user data is stored remotely or sent to any MazAPI server. The only requests made are the security tests sent to the target you choose to scan.</p>
  </div>

  <!-- Wizard step indicator -->
  <div class="wizard-bar" id="wizard-bar">
    <div class="ws active" data-step="1" id="ws-1"><div class="ws-circle">1</div><div class="ws-lbl">Target</div></div>
    <div class="ws-line" id="wl-1"></div>
    <div class="ws" data-step="2" id="ws-2"><div class="ws-circle">2</div><div class="ws-lbl">Auth</div></div>
    <div class="ws-line" id="wl-2"></div>
    <div class="ws" data-step="3" id="ws-3"><div class="ws-circle">3</div><div class="ws-lbl">Endpoints</div></div>
    <div class="ws-line" id="wl-3"></div>
    <div class="ws" data-step="4" id="ws-4"><div class="ws-circle">4</div><div class="ws-lbl">Tests &amp; Run</div></div>
  </div>

  <!-- ── Step 1: Target ─────────────────────────────────── -->
  <div id="step-1" class="step-pane active">
    <div class="presets">
      <span style="font-size:.82em;color:#8b949e">Quick presets:</span>
      <button type="button" class="preset" id="preset-vulnerable">Vulnerable API (lab)</button>
      <button type="button" class="preset" id="preset-hardened">Hardened API (lab)</button>
      <button type="button" class="preset" id="preset-gemini">Google Gemini API</button>
      <button type="button" class="preset" id="preset-graphql">GraphQL API</button>
      <button type="button" class="preset" id="preset-external">External REST API</button>
    </div>
    <p class="hint" style="margin-bottom:20px">Lab services: use Docker names like <code>http://vulnerable-api:8000</code>. External: enter the full URL. Presets fill everything automatically.</p>
    <div class="card">
      <h2>Target URL</h2>
      <div class="field">
        <label for="f-target">Base URL *
          <span class="info-icon" onclick="openHelp('fq-14')" title="Click for help">i</span>
        </label>
        <input id="f-target" type="text" placeholder="https://api.example.com  or  http://vulnerable-api:8000">
        <div class="hint">The root URL of the API — no trailing slash, no path segments.</div>
      </div>
      <div style="border:1px dashed #30363d;border-radius:8px;padding:14px 16px;margin-bottom:4px">
        <div style="font-size:.79em;font-weight:700;color:#8b949e;margin-bottom:10px;text-transform:uppercase;letter-spacing:.06em">&#9889; Auto-fill from real browser session</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
          <label style="cursor:pointer">
            <input type="file" id="har-file-input" accept=".har,application/json" style="display:none">
            <span class="btn-disc" id="btn-har" style="display:inline-block;cursor:pointer">&#128229; Import HAR File</span>
          </label>
          <span style="font-size:.77em;color:#8b949e">or</span>
          <button type="button" class="btn-disc" id="btn-playwright" style="background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.4);color:#3fb950">&#129302; Capture Live Session</button>
          <button type="button" id="btn-stop-capture">&#9632; Stop</button>
        </div>
        <!-- Prominent capture status box -->
        <div id="capture-status-box">
          <div style="display:flex;align-items:center;gap:10px">
            <span class="spinner" id="capture-spinner"></span>
            <span id="capture-status-main"></span>
          </div>
          <div id="capture-status-detail"></div>
          <div id="capture-login-steps"></div>
        </div>
        <!-- Login credentials for authenticated capture -->
        <details id="capture-auth-details" style="margin-bottom:8px">
          <summary style="cursor:pointer;font-size:.8em;color:#8b949e;user-select:none;list-style:none;display:flex;align-items:center;gap:6px">
            <span id="capture-auth-arrow" style="font-size:.75em;transition:transform .2s">&#9654;</span>
            <span>Provide login credentials (if the site requires login)</span>
          </summary>
          <div style="margin-top:10px;padding:12px;background:#0d1117;border-radius:6px;border:1px solid #21262d">
            <p style="font-size:.78em;color:#8b949e;margin-bottom:10px">
              If the target requires authentication, fill these in. The headless browser will log in first,
              then capture the authenticated API calls. Leave blank for public APIs.
            </p>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
              <div>
                <label style="display:block;font-size:.77em;color:#8b949e;margin-bottom:4px">Username / Email</label>
                <input type="text" id="cap-username" placeholder="alice" style="width:100%;background:#161b22;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;padding:6px 9px;font-size:.85em;font-family:inherit">
              </div>
              <div>
                <label style="display:block;font-size:.77em;color:#8b949e;margin-bottom:4px">Password</label>
                <input type="password" id="cap-password" placeholder="••••••••" style="width:100%;background:#161b22;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;padding:6px 9px;font-size:.85em;font-family:inherit">
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
              <div>
                <label style="display:block;font-size:.77em;color:#8b949e;margin-bottom:4px">Login Endpoint</label>
                <input type="text" id="cap-auth-ep" value="/auth/login" placeholder="/auth/login" style="width:100%;background:#161b22;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;padding:6px 9px;font-size:.85em;font-family:inherit">
              </div>
              <div>
                <label style="display:block;font-size:.77em;color:#8b949e;margin-bottom:4px">Token Field in Response</label>
                <input type="text" id="cap-token-field" value="access_token" placeholder="access_token" style="width:100%;background:#161b22;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;padding:6px 9px;font-size:.85em;font-family:inherit">
              </div>
            </div>
          </div>
        </details>
        <p class="hint" style="margin-top:8px">
          <b>Import HAR:</b> DevTools &#8594; Network &#8594; right-click &#8594; <em>Save all as HAR with content</em>.
          &nbsp;&nbsp;<b>Capture Live:</b> Headless Chromium visits the page in the background (no window opens), logs in if credentials are provided, and intercepts all API calls.
        </p>
      </div>
      <h2 style="margin-top:18px;margin-bottom:8px">API Type</h2>
      <div style="display:flex;gap:8px;margin-bottom:4px">
        <button type="button" class="api-type-btn active" id="aptype-rest" data-aptype="rest">REST / JSON</button>
        <button type="button" class="api-type-btn" id="aptype-graphql" data-aptype="graphql">GraphQL</button>
      </div>
    </div>
    <div class="step-nav">
      <button class="btn-next" id="btn-next-1">Next: Authentication &#8594;</button>
    </div>
  </div>

  <!-- ── Step 2: Authentication ─────────────────────────── -->
  <div id="step-2" class="step-pane">
    <div class="card">
      <h2>Authentication
        <span class="info-icon" onclick="openHelp('fq-4')" title="Which auth mode should I use?">i</span>
      </h2>
      <p class="hint" style="margin-bottom:14px">Choose how the scanner authenticates. Select <b>None</b> to scan public endpoints only.</p>
    <div class="auth-tabs">
      <button type="button" class="auth-tab active" data-auth="login">Login Flow</button>
      <button type="button" class="auth-tab" data-auth="bearer">Bearer Token</button>
      <button type="button" class="auth-tab" data-auth="apikey">API Key Header</button>
      <button type="button" class="auth-tab" data-auth="queryparam">Query Param</button>
      <button type="button" class="auth-tab" data-auth="basicauth">Basic Auth</button>
      <button type="button" class="auth-tab" data-auth="none">None</button>
    </div>
    <div id="auth-login">
      <div class="row">
        <div class="field"><label for="f-auth-ep">Auth Endpoint</label><input id="f-auth-ep" value="/auth/login"><span class="hint">POST endpoint that returns a token</span></div>
        <div class="field"><label for="f-token-field">Token Field</label><input id="f-token-field" value="access_token"><span class="hint">Key in the JSON response</span></div>
      </div>
      <div class="field">
        <label for="f-auth-body">Credentials (JSON)
          <span class="info-icon" onclick="openHelp('fq-1')" title="How to find credentials in browser">i</span>
        </label>
        <textarea id="f-auth-body" rows="2" placeholder='{"username": "alice", "password": "alice123"}'></textarea>
        <span class="hint">JSON body sent to the auth endpoint. Find it in DevTools → Network → login request → Payload tab.</span>
      </div>
    </div>
    <div id="auth-bearer" style="display:none">
      <div class="field">
        <label for="f-direct-token">Bearer Token
          <span class="info-icon" onclick="openHelp('fq-2')" title="How to get a token from your browser">i</span>
        </label>
        <input id="f-direct-token" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...">
        <span class="hint">Paste a JWT from DevTools → Network → login response → access_token field.</span>
      </div>
    </div>
    <div id="auth-apikey" style="display:none">
      <div class="row">
        <div class="field"><label for="f-api-key-header">Header Name</label><input id="f-api-key-header" placeholder="X-API-Key"><span class="hint">e.g. X-API-Key, Authorization</span></div>
        <div class="field"><label for="f-api-key-value">Key Value</label><input id="f-api-key-value" placeholder="sk-..."><span class="hint">Sent as the header value</span></div>
      </div>
    </div>
    <div id="auth-queryparam" style="display:none">
      <div class="row">
        <div class="field"><label for="f-qp-name">Parameter Name</label><input id="f-qp-name" value="key" placeholder="key"><span class="hint">e.g. key, api_key, token</span></div>
        <div class="field"><label for="f-qp-value">Parameter Value</label><input id="f-qp-value" placeholder="AIzaSy..."><span class="hint">Appended to every request as ?name=value</span></div>
      </div>
    </div>
    <div id="auth-basicauth" style="display:none">
      <div class="row">
        <div class="field"><label for="f-basic-user">Username</label><input id="f-basic-user" placeholder="admin"><span class="hint">Encoded as Authorization: Basic base64(user:pass)</span></div>
        <div class="field"><label for="f-basic-pass">Password</label><input id="f-basic-pass" type="password" placeholder="password"></div>
      </div>
    </div>
    <div id="auth-none" style="display:none">
      <p class="hint" style="padding:8px 0">Only unauthenticated tests run: sensitive paths, CORS, security headers, schema exposure, rate-limit probing, and JWT forgery attempts.</p>
    </div>
    <div class="field" style="margin-top:14px">
      <label for="f-extra-headers">Extra Headers (JSON) <span style="font-weight:400;text-transform:none;letter-spacing:0">— optional</span></label>
      <textarea id="f-extra-headers" rows="2" placeholder='{"X-Tenant-ID": "acme", "X-Api-Version": "2024-01"}'></textarea>
      <span class="hint">Sent with every request — use for multi-tenant APIs, versioning headers, or any required custom header.</span>
    </div>
    </div><!-- /card -->
    <div class="step-nav">
      <button class="btn-back" id="btn-back-2">&#8592; Back</button>
      <button class="btn-next" id="btn-next-2">Next: Endpoints &#8594;</button>
    </div>
  </div><!-- /step-2 -->

  <!-- ── Step 3: Endpoint Configuration ────────────────── -->
  <div id="step-3" class="step-pane">
  <div class="card">
    <h2>Endpoint Configuration
      <span class="info-icon" onclick="openHelp('fq-5')" title="How does Discover APIs work?">i</span>
    </h2>
    <div class="disc-row">
      <button type="button" class="btn-disc" id="btn-discover">&#128269; Discover APIs</button>
      <span id="discover-msg" class="hint"></span>
    </div>
    <div class="row">
      <div class="field">
        <label for="f-bola">BOLA Path Template
          <span class="info-icon" onclick="openHelp('fq-7')" title="What is the BOLA path?">i</span>
        </label>
        <input id="f-bola" value="/users/{id}">
        <span class="hint">Use <code>{id}</code> as a placeholder — scanner substitutes other users' IDs</span>
      </div>
      <div class="field"><label for="f-update">Update Path (mass assignment)</label><input id="f-update" value="/users/1"><span class="hint">PUT endpoint that accepts a user body</span></div>
    </div>
    <div class="row">
      <div class="field"><label for="f-protected">Protected / Admin Path</label><input id="f-protected" value="/admin/users"><span class="hint">Endpoint only admins should access</span></div>
      <div class="field"><label for="f-rate-ep">Rate-limit Probe Endpoint</label><input id="f-rate-ep" value="/auth/login"><span class="hint">Also used for verbose-error and injection tests</span></div>
    </div>
  </div><!-- /card -->
  <div class="step-nav">
    <button class="btn-back" id="btn-back-3">&#8592; Back</button>
    <button class="btn-next" id="btn-next-3">Next: Select Tests &#8594;</button>
  </div>
  </div><!-- /step-3 -->

  <!-- ── Step 4: Tests & Run ────────────────────────────── -->
  <div id="step-4" class="step-pane">
  <div class="card">
    <h2>Select Tests
      <span class="info-icon" onclick="openHelp('fq-11')" title="What are the Beyond OWASP tests?">i</span>
    </h2>
    <div class="test-grid">
      <label class="test-lbl"><input type="checkbox" id="t-api1" checked><div><span class="cat-name">API1 · BOLA</span><span class="cat-desc">Object-level access: scanner logs in as User 1 and tries to access User 2's resource</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api2" checked><div><span class="cat-name">API2 · Authentication</span><span class="cat-desc">JWT weak secret + alg:none bypass + expired token acceptance</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api3" checked><div><span class="cat-name">API3 · Mass Assignment</span><span class="cat-desc">PUT with extra fields (role=admin, balance=999999) — checks allowlist enforcement</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api4" checked><div><span class="cat-name">API4 · Rate Limiting</span><span class="cat-desc">12 rapid login failures — expects HTTP 429 after threshold</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api5" checked><div><span class="cat-name">API5 · Function Auth</span><span class="cat-desc">Regular-user token on admin routes — expects 403 Forbidden</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api7" checked><div><span class="cat-name">API7 · SSRF</span><span class="cat-desc">?url/callback/fetch params pointing to 169.254.169.254 and internal services</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api8" checked><div><span class="cat-name">API8 · Misconfiguration</span><span class="cat-desc">CORS, security headers, schema exposure, verbose errors, sensitive paths</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api9" checked><div><span class="cat-name">API9 · Shadow APIs</span><span class="cat-desc">Probes /v0, /api/internal, /api/test, /api/beta — undocumented endpoints</span></div></label>
    </div>
    <div style="margin-top:16px;margin-bottom:8px;font-size:.75em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#f0883e">&#9888; Extended — CWE / MITRE / Beyond OWASP</div>
    <div class="test-grid">
      <label class="test-lbl"><input type="checkbox" id="t-ext_verb" checked><div><span class="cat-name" style="color:#f0883e">HTTP Verb Tampering</span><span class="cat-desc">DELETE/TRACE/PATCH on read-only endpoints — CVE-2010-3333 class, CWE-650</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-ext_traversal" checked><div><span class="cat-name" style="color:#f0883e">Path Traversal</span><span class="cat-desc">../../etc/passwd variants — CVE-2021-41773 (Apache), CVE-2021-42013, CWE-22</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-ext_injection" checked><div><span class="cat-name" style="color:#f0883e">SQL Injection</span><span class="cat-desc">Error-based SQLi — CVE-2019-14234 (Django), CVE-2012-1823, CWE-89</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-ext_redirect" checked><div><span class="cat-name" style="color:#f0883e">Open Redirect</span><span class="cat-desc">?redirect/url/next to external domain — CVE-2019-11229 class, CWE-601</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-ext_xxe" checked><div><span class="cat-name" style="color:#f0883e">XXE Injection</span><span class="cat-desc">XML SYSTEM entity disclosure — CVE-2019-0811, CVE-2018-8016, CWE-611</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-ext_crlf" checked><div><span class="cat-name" style="color:#f0883e">CRLF / Header Injection</span><span class="cat-desc">%0d%0a response splitting — CVE-2020-26935, CVE-2019-9740, CWE-93</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-ext_cmd" checked><div><span class="cat-name" style="color:#f0883e">Command Injection</span><span class="cat-desc">;id $(id) in URL params — CVE-2014-6271 (Shellshock), CVE-2021-44228, CWE-78</span></div></label>
    </div>
    <div style="margin-top:16px;margin-bottom:8px;font-size:.75em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#bc8cff">&#128274; Privacy &amp; Inventory</div>
    <div class="test-grid">
      <label class="test-lbl"><input type="checkbox" id="t-pii" checked><div><span class="cat-name" style="color:#bc8cff">PII / Sensitive Data Exposure</span><span class="cat-desc">Scans API responses for emails, phone numbers, credit cards, SSNs, passwords, AWS keys — GDPR Art.32 / CWE-312</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-graphql_scan" checked><div><span class="cat-name" style="color:#bc8cff">GraphQL Introspection Probe</span><span class="cat-desc">Probes /graphql, /api/graphql — introspection, depth limits, batch abuse — API9:2023</span></div></label>
    </div>
    <div style="margin-top:10px;display:flex;gap:12px">
      <button type="button" class="link-btn" id="btn-select-all">Select All</button>
      <button type="button" class="link-btn" id="btn-clear-all">Clear All</button>
    </div>
    <!-- Settings: org name + webhook -->
    <div class="settings-card" style="margin-top:18px">
      <h3>&#9881; Report &amp; Alert Settings</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div class="field" style="margin-bottom:0">
          <label>Organisation Name (for HTML report)</label>
          <input type="text" id="f-org-name" placeholder="e.g. Acme Security Team" style="background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;padding:7px 9px;font-size:.85em;font-family:inherit;width:100%">
        </div>
        <div class="field" style="margin-bottom:0">
          <label>Webhook URL (Slack / Teams)</label>
          <input type="text" id="f-webhook-url" placeholder="https://hooks.slack.com/services/…" style="background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;padding:7px 9px;font-size:.85em;font-family:inherit;width:100%">
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:14px;margin-top:20px;flex-wrap:wrap">
      <button class="btn-back" id="btn-back-4">&#8592; Back</button>
      <button type="button" class="btn btn-primary" id="scan-btn">&#9654; Run Scan</button>
      <span style="font-size:.8em;color:#8b949e">Takes 20–90 seconds depending on the target.</span>
    </div>
  </div><!-- /card step-4 -->
  </div><!-- /step-4 -->

  <div id="status-bar" style="display:none"></div>
  <div id="results" style="margin-top:16px"></div>
</div>

<script>
var CVE_DB = {
  "API1:2023 - Broken Object Level Authorization": {
    cves:["CVE-2019-14234","CVE-2020-7927","CVE-2021-21302"],
    owasp_ref:"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    severity:"HIGH",
    description:"The API retrieves data based on a client-supplied identifier without verifying that the requesting user is authorised to access that specific object.",
    fixes:["Verify ownership on every request: current_user.id == resource.owner_id.","Use unpredictable UUIDs instead of sequential integer IDs to reduce guessability.","Apply an authorization middleware that enforces ownership rather than repeating checks per endpoint.","Write integration tests that log in as User A and request User B's resources — expect 403."]
  },
  "API2:2023 - Broken Authentication": {
    cves:["CVE-2018-1000531","CVE-2022-21449","CVE-2021-27958"],
    owasp_ref:"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    severity:"CRITICAL",
    description:"Authentication mechanisms are implemented incorrectly, allowing attackers to forge tokens or bypass authentication via algorithm confusion (alg:none).",
    fixes:["Load JWT secrets from environment variables only — never hard-code them.","Always set an exp claim in JWTs; 15-30 minutes is typical.","Explicitly validate the alg header and reject tokens with alg=none or unexpected algorithms.","Rate-limit login endpoints to 5 attempts per minute per IP."]
  },
  "API3:2023 - Broken Object Property Level Authorization": {
    cves:["CVE-2012-2676","CVE-2022-32532","CVE-2021-41079"],
    owasp_ref:"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    severity:"HIGH",
    description:"The API accepts more fields than intended, allowing clients to modify properties they should never control.",
    fixes:["Define strict input schemas listing only allowed fields.","Never pass user input directly to ORM update calls — always use an allowlist.","Treat role, is_admin, and balance as server-controlled fields.","Return a response schema that excludes sensitive fields like password hash."]
  },
  "API4:2023 - Unrestricted Resource Consumption": {
    cves:["CVE-2019-11324","CVE-2020-26258","CVE-2021-25742"],
    owasp_ref:"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    severity:"MEDIUM",
    description:"The API does not limit request rate or volume, enabling brute-force and credential stuffing.",
    fixes:["Apply per-IP rate limiting on auth endpoints (5/minute).","Apply per-user rate limiting on data endpoints to prevent scraping.","Set maximum request body sizes.","Implement exponential backoff after repeated failures."]
  },
  "API5:2023 - Broken Function Level Authorization": {
    cves:["CVE-2021-41773","CVE-2022-22947","CVE-2020-14882"],
    owasp_ref:"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    severity:"HIGH",
    description:"Administrative endpoints are accessible to regular users because the API checks authentication but not the user role.",
    fixes:["Default to deny — every endpoint must declare the required role.","Use a shared authorization dependency that verifies role on every admin route.","Keep admin functionality on a separate service with network-level controls.","Audit all routes regularly."]
  },
  "API8:2023 - Security Misconfiguration": {
    cves:["CVE-2021-44228","CVE-2020-1938","CVE-2019-0232"],
    owasp_ref:"https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    severity:"MEDIUM",
    description:"The API exposes sensitive information through debug endpoints, verbose errors, permissive CORS, missing security headers, or public API documentation.",
    fixes:["Remove debug endpoints before deploying to production.","Configure CORS to allow only known origins; never use wildcard with credentialed requests.","Return generic error messages — never reveal internal details.","Disable interactive API docs in production and add all recommended security headers."]
  }
};

var PRESETS = {
  vulnerable: {
    target: "http://vulnerable-api:8000", apiType: "rest",
    authMode: "login", authEndpoint: "/auth/login", tokenField: "access_token",
    credentials: '{"username": "alice", "password": "alice123"}',
    bolaPath: "/users/{id}", updatePath: "/users/1", protectedPath: "/admin/users", rateEp: "/auth/login"
  },
  hardened: {
    target: "http://hardened-api:8001", apiType: "rest",
    authMode: "login", authEndpoint: "/auth/login", tokenField: "access_token",
    credentials: '{"username": "alice", "password": "alice123"}',
    bolaPath: "/users/{id}", updatePath: "/users/1", protectedPath: "/admin/users", rateEp: "/auth/login"
  },
  gemini: {
    target: "https://generativelanguage.googleapis.com", apiType: "rest",
    authMode: "queryparam", queryParamName: "key", queryParamValue: "",
    authEndpoint: "/v1beta/models", tokenField: "access_token", credentials: "",
    bolaPath: "/v1beta/models/{id}", updatePath: "/v1beta/models/gemini-pro",
    protectedPath: "/v1beta/models", rateEp: "/v1beta/models"
  },
  graphql: {
    target: "", apiType: "graphql",
    authMode: "bearer", authEndpoint: "/graphql", tokenField: "access_token", credentials: "",
    bolaPath: "/graphql", updatePath: "/graphql", protectedPath: "/graphql", rateEp: "/graphql"
  },
  external: {
    target: "", apiType: "rest",
    authMode: "login", authEndpoint: "/auth/login", tokenField: "access_token", credentials: "",
    bolaPath: "/users/{id}", updatePath: "/users/1", protectedPath: "/admin/users", rateEp: "/auth/login"
  }
};

var _authMode = "login";
var _apiType  = "rest";
var _lastScan = null;

function setAuthTab(mode) {
  var panels = ["login", "bearer", "apikey", "queryparam", "basicauth", "none"];
  var tabs = document.querySelectorAll(".auth-tab");
  for (var i = 0; i < tabs.length; i++) {
    var t = tabs[i];
    if (t.getAttribute("data-auth") === mode) { t.classList.add("active"); }
    else { t.classList.remove("active"); }
  }
  for (var j = 0; j < panels.length; j++) {
    var el = document.getElementById("auth-" + panels[j]);
    if (el) el.style.display = panels[j] === mode ? "block" : "none";
  }
  _authMode = mode;
}

function setApiType(type) {
  _apiType = type;
  var btns = document.querySelectorAll(".api-type-btn");
  for (var i = 0; i < btns.length; i++) {
    if (btns[i].getAttribute("data-aptype") === type) { btns[i].classList.add("active"); }
    else { btns[i].classList.remove("active"); }
  }
}

function loadPreset(name) {
  var p = PRESETS[name];
  if (!p) return;
  document.getElementById("f-target").value = p.target || "";
  document.getElementById("f-auth-ep").value = p.authEndpoint || "/auth/login";
  document.getElementById("f-token-field").value = p.tokenField || "access_token";
  document.getElementById("f-auth-body").value = p.credentials || "";
  document.getElementById("f-bola").value = p.bolaPath || "/users/{id}";
  document.getElementById("f-update").value = p.updatePath || "/users/1";
  document.getElementById("f-protected").value = p.protectedPath || "/admin/users";
  document.getElementById("f-rate-ep").value = p.rateEp || "/auth/login";
  document.getElementById("f-extra-headers").value = "";
  // Query param preset fields
  if (p.queryParamName) document.getElementById("f-qp-name").value = p.queryParamName;
  if (p.queryParamValue !== undefined) document.getElementById("f-qp-value").value = p.queryParamValue;
  setAuthTab(p.authMode || "login");
  setApiType(p.apiType || "rest");
  var discMsg = document.getElementById("discover-msg");
  if (!p.target) {
    discMsg.textContent = "Enter the target URL then click Discover Schema.";
    discMsg.style.color = "#8b949e";
  } else if (name === "gemini") {
    discMsg.textContent = "Paste your Google AI Studio API key into the Query Param value field.";
    discMsg.style.color = "#e3b341";
  } else {
    discMsg.textContent = "";
  }
}

function toggleAll(checked) {
  var ids = ["api1","api2","api3","api4","api5","api7","api8","api9",
             "ext_verb","ext_traversal","ext_injection","ext_redirect",
             "ext_xxe","ext_crlf","ext_cmd","pii","graphql_scan"];
  for (var i = 0; i < ids.length; i++) {
    var cb = document.getElementById("t-" + ids[i]);
    if (cb) cb.checked = checked;
  }
}

/* ── Scan history (localStorage) ───────────────────────────────────── */
var HIST_KEY = "mazapi_scan_history";
var FP_KEY_SCAN = "mazapi_scan_fp";

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HIST_KEY) || "[]"); } catch(e) { return []; }
}

function saveHistory(data) {
  try {
    var hist = getHistory().filter(function(h){ return h.target !== data.target; });
    hist.unshift({
      target: data.target, score: data.score,
      total: data.total_tests, vulnerable: data.total_vulnerable,
      date: new Date().toISOString(),
      results: (function(){ var out=[]; (data.categories||[]).forEach(function(c){ (c.tests||[]).forEach(function(t){ out.push({test:t.test,category:c.category,vulnerable:t.vulnerable}); }); }); return out; })()
    });
    localStorage.setItem(HIST_KEY, JSON.stringify(hist.slice(0, 10)));
  } catch(e) {}
}

function getLastScanHistory(target) {
  return getHistory().find(function(h){ return h.target === target; }) || null;
}

function getFPStore() {
  try { return JSON.parse(localStorage.getItem(FP_KEY_SCAN) || "{}"); } catch(e) { return {}; }
}

function setFP(target, testName, state) {
  var fps = getFPStore();
  var key = target + "::" + testName;
  if (state === null) delete fps[key]; else fps[key] = {state: state, date: new Date().toISOString()};
  try { localStorage.setItem(FP_KEY_SCAN, JSON.stringify(fps)); } catch(e) {}
}

function addRegressionTags(categories, lastScan) {
  if (!lastScan) return categories;
  var prev = {};
  (lastScan.results || []).forEach(function(r){ prev[r.test] = r.vulnerable; });
  categories.forEach(function(cat){
    (cat.tests || []).forEach(function(t){
      var was = prev[t.test];
      if (was === undefined)          t.regression = t.vulnerable ? "NEW" : null;
      else if (was && t.vulnerable)   t.regression = "RECURRING";
      else if (!was && t.vulnerable)  t.regression = "NEW";
      else if (was && !t.vulnerable)  t.regression = "FIXED";
      else                            t.regression = null;
    });
  });
  return categories;
}

/* ── SARIF client-side export ───────────────────────────────────────── */
function exportSARIF(data) {
  var seen = {}, rules = [], results = [];
  (data.categories||[]).forEach(function(cat){
    var rid = cat.category.replace(/[^A-Za-z0-9-]/g,"-").slice(0,64);
    if (!seen[rid]) { seen[rid]=1; rules.push({id:rid,name:cat.category.split(" - ")[0],shortDescription:{text:cat.category}}); }
    (cat.tests||[]).forEach(function(t){
      if (!t.vulnerable) return;
      results.push({ruleId:rid,level:(["CRITICAL","HIGH"].indexOf(t.severity||"")>=0)?"error":"warning",message:{text:t.test+": "+t.actual},locations:[{physicalLocation:{artifactLocation:{uri:data.target||"",uriBaseId:"TARGETROOT"}}}],properties:{severity:t.severity,compliance:cat.compliance||{}}});
    });
  });
  var sarif = {version:"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",runs:[{tool:{driver:{name:"MazAPI Scanner",version:"2.0.0",rules:rules}},results:results,properties:{target:data.target,scannedAt:new Date().toISOString()}}]};
  downloadJSON(sarif, "mazapi-" + Date.now() + ".sarif");
}

/* ── HTML report client-side ────────────────────────────────────────── */
function exportHTMLReport(data) {
  var orgName = (document.getElementById("f-org-name")||{}).value || "MazAPI Scanner";
  var sc = data.score; var color = sc>=90?"#3fb950":sc>=70?"#e3b341":"#f85149";
  var fps = getFPStore(); var target = data.target;
  var SEV = {CRITICAL:"#ff6b6b",HIGH:"#f85149",MEDIUM:"#e3b341",LOW:"#58a6ff"};
  var rows = "";
  (data.categories||[]).forEach(function(cat){
    (cat.tests||[]).forEach(function(t){
      var fp = fps[target+"::"+t.test]; var sev = SEV[t.severity]||"#8b949e"; var vuln = t.vulnerable && !fp;
      var fpBadge = fp?'<span style="background:#30363d;color:#8b949e;padding:1px 6px;border-radius:3px;font-size:.72em;margin-left:5px">'+(fp.state==="fp"?"FALSE POSITIVE":"ACCEPTED RISK")+"</span>":'';
      var regColor = {NEW:"#f85149",RECURRING:"#e3b341",FIXED:"#3fb950"}[t.regression]||"";
      var regBadge = t.regression?'<span style="border:1px solid '+regColor+';color:'+regColor+';padding:1px 5px;border-radius:3px;font-size:.7em;margin-left:5px">'+t.regression+"</span>":'';
      var comp = cat.compliance;
      var compHtml = comp?'<div style="font-size:.76em;color:#8b949e;margin-top:6px"><b style="color:#58a6ff">PCI-DSS</b> '+(comp.pci_dss||[]).join(', ')+' &nbsp;<b style="color:#58a6ff">GDPR</b> '+(comp.gdpr||[]).join(', ')+' &nbsp;<b style="color:#58a6ff">ISO 27001</b> '+(comp.iso27001||[]).join(', ')+'</div>':'';
      rows += '<div style="border-left:3px solid '+(vuln?sev:"#30363d")+';padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0;background:'+(vuln?"rgba(248,81,73,.04)":"rgba(63,185,80,.04)")+'">'
        +'<div style="display:flex;justify-content:space-between"><span style="font-weight:600;color:'+(vuln?sev:"#3fb950")+'">'+(vuln?"✗":"✓")+" "+t.test+fpBadge+regBadge+'</span><span style="font-size:.77em;color:'+sev+'">'+t.severity+'</span></div>'
        +'<div style="font-size:.77em;color:#8b949e;margin-top:2px">'+cat.category+'</div>'
        +'<div style="font-size:.82em;margin-top:4px">'+t.actual+'</div>'
        +compHtml+"</div>";
    });
  });
  var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>MazAPI Report</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui;background:#0d1117;color:#c9d1d9;padding:28px}</style></head><body>'
    +'<div style="text-align:center;margin-bottom:24px"><h1 style="color:#58a6ff;font-size:1.8em">'+orgName+'</h1><p style="color:#8b949e">API Security Scan Report</p></div>'
    +'<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">'
    +[["Score",sc+"%",color],["Vulnerable",data.total_vulnerable,"#f85149"],["Secure",(data.total_tests-data.total_vulnerable),"#3fb950"],["Tests",data.total_tests,"#58a6ff"]].map(function(x){return '<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center"><div style="font-size:1.8em;font-weight:700;color:'+x[2]+'">'+x[1]+'</div><div style="font-size:.79em;color:#8b949e;margin-top:4px">'+x[0]+'</div></div>';}).join("")
    +'</div><div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:11px 16px;margin-bottom:18px;font-size:.83em;color:#8b949e"><b style="color:#c9d1d9">Target:</b> '+data.target+' &nbsp;|&nbsp; <b style="color:#c9d1d9">Scanned:</b> '+new Date().toLocaleString()+'</div>'
    +rows
    +'<div style="text-align:center;padding:16px;color:#8b949e;font-size:.77em;border-top:1px solid #21262d;margin-top:20px">MazAPI Scanner v2.0 — CY384 API Security Project, UMaT Ghana</div></body></html>';
  var blob = new Blob([html], {type:"text/html"});
  var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "mazapi-report-"+Date.now()+".html"; a.click();
}

/* ── Postman/OpenAPI export ─────────────────────────────────────────── */
function exportPostman() {
  if (!_lastScan) return;
  fetch("/monitor/export/postman", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({target: _lastScan.target, endpoints: {}})
  }).then(function(r){return r.json();}).then(function(col){ downloadJSON(col, "mazapi-postman-"+Date.now()+".json"); });
}

function exportOpenAPI() {
  if (!_lastScan) return;
  fetch("/monitor/export/openapi", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({target: _lastScan.target, endpoints: {}})
  }).then(function(r){return r.json();}).then(function(spec){ downloadJSON(spec, "mazapi-openapi-"+Date.now()+".json"); });
}

/* ── Send webhook ───────────────────────────────────────────────────── */
function sendWebhook() {
  if (!_lastScan) return;
  var url = (document.getElementById("f-webhook-url")||{}).value || "";
  if (!url) { alert("Enter a webhook URL in the Settings section (Step 4)."); return; }
  var btn = document.getElementById("btn-webhook");
  if (btn) { btn.textContent = "Sending…"; btn.disabled = true; }
  fetch("/monitor/scan/notify", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      webhook_url: url, target: _lastScan.target, score: _lastScan.score,
      total_tests: _lastScan.total_tests, total_vulnerable: _lastScan.total_vulnerable,
      categories: _lastScan.categories
    })
  }).then(function(r){return r.json();}).then(function(){
    if (btn) { btn.textContent = "✓ Sent"; setTimeout(function(){ btn.textContent="🔔 Send Alert"; btn.disabled=false; }, 2500); }
  }).catch(function(e){
    if (btn) { btn.textContent = "✗ Failed"; setTimeout(function(){ btn.textContent="🔔 Send Alert"; btn.disabled=false; }, 2000); }
  });
}

/* ── Generic download helper ────────────────────────────────────────── */
function downloadJSON(obj, filename) {
  var blob = new Blob([JSON.stringify(obj, null, 2)], {type:"application/json"});
  var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
}

/* ── Scan history panel ─────────────────────────────────────────────── */
function renderHistoryPanel() {
  var hist = getHistory();
  if (!hist.length) return "";
  var COLOR = function(sc){ return sc>=90?"#3fb950":sc>=70?"#e3b341":"#f85149"; };
  var rows = hist.map(function(h){
    var newC = (h.results||[]).filter(function(r){ return r.regression==="NEW"; }).length;
    var fixC = (h.results||[]).filter(function(r){ return r.regression==="FIXED"; }).length;
    return '<div class="history-block"><div class="history-hdr">'
      +'<span style="font-family:monospace;font-size:.82em;color:#58a6ff">'+h.target+'</span>'
      +'<span style="font-size:1.1em;font-weight:700;color:'+COLOR(h.score)+'">'+h.score+'%</span></div>'
      +'<div style="font-size:.76em;color:#8b949e">'+new Date(h.date).toLocaleString()+' &nbsp;|&nbsp; '+h.vulnerable+'/'+h.total+' vulnerable'
      +(newC?' &nbsp;<span style="color:#f85149">+'+newC+' new</span>':'')
      +(fixC?' &nbsp;<span style="color:#3fb950">&#8722;'+fixC+' fixed</span>':'')+'</div></div>';
  }).join("");
  return '<div style="margin-top:20px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'
    +'<span style="font-size:.75em;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#8b949e">Scan History</span>'
    +'<button class="link-btn" id="btn-clear-hist" style="font-size:.76em">Clear history</button></div>'
    +rows+'</div>';
}

function discoverSchema() {
  var target = document.getElementById("f-target").value.trim();
  if (!target) {
    alert("Enter a target URL first");
    return;
  }
  var msg = document.getElementById("discover-msg");
  msg.textContent = "Discovering...";
  msg.style.color = "#8b949e";
  fetch("/monitor/scan/discover?target=" + encodeURIComponent(target))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var paths = data.paths || [];
      // Auto-fill form fields from discovered paths
      var up = null;
      for (var i = 0; i < paths.length; i++) {
        if (/\{[^}]+\}/.test(paths[i]) && /user/i.test(paths[i])) { up = paths[i]; break; }
      }
      if (!up) {
        for (var j = 0; j < paths.length; j++) {
          if (/\{[^}]+\}/.test(paths[j])) { up = paths[j]; break; }
        }
      }
      if (up) {
        document.getElementById("f-bola").value = up.replace(/\{[^}]+\}/g, "{id}");
        document.getElementById("f-update").value = up.replace(/\{[^}]+\}/g, "1");
      }
      for (var k = 0; k < paths.length; k++) {
        if (/admin/i.test(paths[k])) {
          document.getElementById("f-protected").value = paths[k].replace(/\{[^}]+\}/g, "1");
          break;
        }
      }
      if (data.total_paths > 0) {
        var srcs = data.sources || {};
        var srcList = [];
        if (srcs.openapi)    srcList.push("OpenAPI docs");
        if (srcs.js_crawl)   srcList.push("JS analysis");
        if (srcs.path_probe) srcList.push("path probing");
        var label = "✓ Discovered " + data.total_paths + " endpoint" +
                    (data.total_paths !== 1 ? "s" : "");
        if (data.api_title) label += " — " + data.api_title;
        if (srcList.length) label += " (via " + srcList.join(", ") + ")";
        msg.textContent = label;
        msg.style.color = "#3fb950";
        // Show discovered path list as tooltip/detail
        var discList = document.getElementById("discover-paths");
        if (!discList) {
          discList = document.createElement("div");
          discList.id = "discover-paths";
          discList.style.cssText = "margin-top:8px;padding:8px 10px;background:#0d1117;border:1px solid #21262d;border-radius:6px;font-size:.76em;color:#8b949e;max-height:110px;overflow-y:auto;font-family:monospace";
          msg.parentNode.insertBefore(discList, msg.nextSibling);
        }
        discList.textContent = paths.slice(0, 30).join("  ·  ") +
                               (paths.length > 30 ? "  … +" + (paths.length-30) + " more" : "");
      } else {
        msg.textContent = "No API endpoints discovered. Try entering the API base URL directly.";
        msg.style.color = "#e3b341";
      }
    })
    .catch(function(e) {
      msg.textContent = "Error: " + e.message;
      msg.style.color = "#f85149";
    });
}

function runScan() {
  var target = document.getElementById("f-target").value.trim();
  if (!target) { alert("Enter a target URL"); return; }

  var testIds = ["api1","api2","api3","api4","api5","api7","api8","api9",
                 "ext_verb","ext_traversal","ext_injection","ext_redirect",
                 "ext_xxe","ext_crlf","ext_cmd","pii","graphql_scan"];
  var tests = [];
  for (var i = 0; i < testIds.length; i++) {
    var cb = document.getElementById("t-" + testIds[i]);
    if (cb && cb.checked) tests.push(testIds[i]);
  }
  if (tests.length === 0) { alert("Select at least one test category"); return; }

  var authBody = null, directToken = null;
  var apiKeyHeader = null, apiKeyValue = null;
  var apiKeyQueryParam = null, apiKeyQueryValue = null;
  var basicAuthUser = null, basicAuthPass = null;
  var authEndpoint = document.getElementById("f-rate-ep").value || "/auth/login";
  var tokenField = "access_token";

  if (_authMode === "login") {
    authEndpoint = document.getElementById("f-auth-ep").value || "/auth/login";
    tokenField = document.getElementById("f-token-field").value || "access_token";
    var raw = (document.getElementById("f-auth-body").value || "").trim();
    if (raw) {
      try { authBody = JSON.parse(raw); }
      catch (e) { alert("Credentials must be valid JSON"); return; }
    }
  } else if (_authMode === "bearer") {
    directToken = (document.getElementById("f-direct-token").value || "").trim() || null;
  } else if (_authMode === "apikey") {
    apiKeyHeader = (document.getElementById("f-api-key-header").value || "").trim() || null;
    apiKeyValue  = (document.getElementById("f-api-key-value").value || "").trim() || null;
  } else if (_authMode === "queryparam") {
    apiKeyQueryParam = (document.getElementById("f-qp-name").value || "").trim() || null;
    apiKeyQueryValue = (document.getElementById("f-qp-value").value || "").trim() || null;
  } else if (_authMode === "basicauth") {
    basicAuthUser = (document.getElementById("f-basic-user").value || "").trim() || null;
    basicAuthPass = (document.getElementById("f-basic-pass").value || "") || null;
  }

  var extraHeaders = null;
  var ehRaw = (document.getElementById("f-extra-headers").value || "").trim();
  if (ehRaw) {
    try { extraHeaders = JSON.parse(ehRaw); }
    catch (e) { alert('Extra Headers must be valid JSON — e.g. {"X-Tenant-ID": "acme"}'); return; }
  }

  var payload = {
    target: target,
    auth_endpoint: authEndpoint,
    auth_body: authBody,
    token_field: tokenField,
    direct_token: directToken,
    api_key_header: apiKeyHeader,
    api_key_value: apiKeyValue,
    api_key_query_param: apiKeyQueryParam,
    api_key_query_value: apiKeyQueryValue,
    basic_auth_user: basicAuthUser,
    basic_auth_pass: basicAuthPass,
    extra_headers: extraHeaders,
    api_type: _apiType,
    bola_path: document.getElementById("f-bola").value,
    update_path: document.getElementById("f-update").value,
    protected_path: document.getElementById("f-protected").value,
    tests: tests
  };

  document.getElementById("scan-btn").disabled = true;
  var bar = document.getElementById("status-bar");
  bar.style.display = "block";
  bar.innerHTML = '<span class="spinner"></span>Scanning <strong>' + target + '</strong> &mdash; may take 20-40 s&hellip;';
  document.getElementById("results").innerHTML = "";

  fetch("/monitor/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  })
    .then(function(r) {
      if (!r.ok) return r.text().then(function(t) { throw new Error(t); });
      return r.json();
    })
    .then(function(data) {
      _lastScan = data;
      var prevScan = getLastScanHistory(data.target); // capture BEFORE overwriting history
      saveHistory(data);
      renderResults(data, prevScan);
      bar.style.display = "none";
    })
    .catch(function(e) {
      bar.innerHTML = '<span style="color:#f85149">Error: ' + e.message + '</span>';
    })
    .finally(function() {
      document.getElementById("scan-btn").disabled = false;
    });
}

function renderResults(data, prevScan) {
  var el = document.getElementById("results");
  var fps = getFPStore();
  var target = data.target;
  // prevScan: the scan from before this run (for regression detection)
  // When called from an FP button re-render, prevScan is undefined → no regression mutation
  if (prevScan !== undefined) addRegressionTags(data.categories, prevScan);

  var html = "";
  var SEV_COLOR = {CRITICAL:"#ff6b6b",HIGH:"#f85149",MEDIUM:"#e3b341",LOW:"#58a6ff"};
  var REG_COLOR = {NEW:"#f85149",RECURRING:"#e3b341",FIXED:"#3fb950"};

  // ── Pre-scan status banner ──────────────────────────────────────────────────
  var ps = data.pre_scan || {};
  var psColor = "#8b949e", psIcon = "?";
  if (ps.auth_valid === true)  { psColor = "#3fb950"; psIcon = "&#10003;"; }
  if (ps.auth_valid === false) { psColor = "#f85149"; psIcon = "&#10007;"; }
  var reachColor = ps.target_reachable ? "#3fb950" : "#f85149";
  var reachLabel = ps.target_reachable ? ("Reachable" + (ps.reachable_status ? " (HTTP " + ps.reachable_status + ")" : "")) : "Unreachable";
  var authLabel = "Auth: ";
  if (!ps.auth_provided) { authLabel += "None"; psColor = "#8b949e"; psIcon = ""; }
  else if (ps.auth_valid === true)  authLabel += "Valid";
  else if (ps.auth_valid === false) authLabel += "Invalid";
  else                              authLabel += "Unknown";

  html += '<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;margin-bottom:18px;font-size:.84em">'
    + '<div style="display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start">'
    + '<div><span style="color:' + reachColor + ';font-weight:700">&#10003; Target: ' + reachLabel + '</span></div>'
    + (ps.auth_provided
        ? '<div><span style="color:' + psColor + ';font-weight:700">' + psIcon + ' ' + authLabel + '</span>'
          + '<div style="color:#8b949e;font-size:.9em;margin-top:3px">' + (ps.auth_message || "") + '</div></div>'
        : '<div style="color:#8b949e">' + (ps.auth_message || "") + '</div>')
    + '</div></div>';

  // ── Score cards + regression summary ────────────────────────────────────────
  var sc = data.score >= 80 ? "green" : data.score >= 50 ? "yellow" : "red";
  var newCount = 0, fixedCount = 0;
  (data.categories||[]).forEach(function(c){ (c.tests||[]).forEach(function(t){ if(t.regression==="NEW") newCount++; if(t.regression==="FIXED") fixedCount++; }); });
  html += '<div class="score-row">'
    + '<div class="scard"><div class="num ' + sc + '">' + data.score + '%</div><div class="lbl">Security Score</div></div>'
    + '<div class="scard"><div class="num blue">' + data.total_tests + '</div><div class="lbl">Tests Run</div></div>'
    + '<div class="scard"><div class="num red">' + data.total_vulnerable + '</div><div class="lbl">Vulnerable</div></div>'
    + '<div class="scard"><div class="num green">' + (data.total_tests - data.total_vulnerable) + '</div><div class="lbl">Passed</div></div>'
    + '</div>';
  if (newCount || fixedCount) {
    html += '<div style="text-align:center;font-size:.8em;color:#8b949e;margin-bottom:10px">'
      + (newCount  ? '<span style="color:#f85149;margin-right:10px">&#9650; ' + newCount  + ' new finding' + (newCount >1?"s":"") + '</span>' : "")
      + (fixedCount? '<span style="color:#3fb950">&#9660; '                   + fixedCount + ' finding' + (fixedCount>1?"s":"") + ' fixed</span>' : "")
      + '</div>';
  }
  html += '<p style="color:#8b949e;font-size:.83em;margin-bottom:16px">Target: <code>' + data.target + '</code> &nbsp;|&nbsp; ' + data.timestamp + '</p>';

  // ── Category blocks ──────────────────────────────────────────────────────────
  for (var ci = 0; ci < data.categories.length; ci++) {
    var cat = data.categories[ci];
    var cve = CVE_DB[cat.category] || null;
    var comp = cat.compliance || null;
    var catVuln = cat.vulnerable_count > 0;

    // Compliance row for category header
    var compBadges = comp ? '<div class="compliance-row" style="margin-top:8px;padding:0 18px 10px">'
      + '<span class="comp-chip">PCI-DSS</span>' + (comp.pci_dss||[]).join(", ") + ' &nbsp;'
      + '<span class="comp-chip">GDPR</span>' + (comp.gdpr||[]).join(", ") + ' &nbsp;'
      + '<span class="comp-chip">ISO 27001</span>' + (comp.iso27001||[]).join(", ")
      + '</div>' : '';

    html += '<div class="cat-block"><div class="cat-hdr"><h3>' + cat.category + '</h3>'
      + '<div style="display:flex;gap:8px;flex-wrap:wrap">'
      + (cve ? '<span class="badge sev-' + cve.severity + '">' + cve.severity + '</span>' : '')
      + '<span class="badge ' + (catVuln ? 'bv' : 'bs') + '">' + cat.vulnerable_count + '/' + cat.total + ' Vulnerable</span>'
      + '</div></div>'
      + compBadges;

    // Per-test rows (expanded, not just a table)
    html += '<div style="padding:0 8px 8px">';
    for (var ti = 0; ti < cat.tests.length; ti++) {
      var t = cat.tests[ti];
      var fp = fps[target + "::" + t.test];
      var sev = SEV_COLOR[t.severity] || "#8b949e";
      var isVuln = t.vulnerable && !fp;
      var fpBadge = fp ? '<span style="background:#30363d;color:#8b949e;padding:1px 6px;border-radius:3px;font-size:.71em;margin-left:5px">' + (fp.state==="fp"?"FALSE POSITIVE":"ACCEPTED RISK") + '</span>' : '';
      var regBadge = t.regression ? '<span class="reg-badge" style="color:' + (REG_COLOR[t.regression]||"#8b949e") + ';border-color:' + (REG_COLOR[t.regression]||"#8b949e") + '">' + t.regression + '</span>' : '';

      // Evidence panel
      var NL = String.fromCharCode(10);
      var evHtml = "";
      if (t.evidence) {
        var evText = t.evidence.request.method + ' ' + t.evidence.request.url;
        if (t.evidence.request.body) evText += NL + 'Body: ' + t.evidence.request.body;
        evText += NL + '→ HTTP ' + t.evidence.response.status;
        if (t.evidence.response.snippet) evText += NL + t.evidence.response.snippet;
        evHtml = '<details class="evidence-block"><summary>Evidence</summary>'
          + '<pre class="evidence-pre">' + evText + '</pre></details>';
      }

      // False positive controls (only for vulnerable findings)
      var fpBtns = "";
      if (t.vulnerable) {
        fpBtns = '<div class="fp-row">'
          + '<button class="fp-btn js-fp' + (fp&&fp.state==="fp"?" active":"") + '" data-target="' + encodeURIComponent(target) + '" data-test="' + encodeURIComponent(t.test) + '" data-state="' + (fp&&fp.state==="fp"?"remove":"fp") + '">'
          + (fp&&fp.state==="fp"?"&#10003; Unmark":"&#9872; False Positive") + '</button>'
          + '<button class="fp-btn js-fp' + (fp&&fp.state==="risk"?" active":"") + '" data-target="' + encodeURIComponent(target) + '" data-test="' + encodeURIComponent(t.test) + '" data-state="' + (fp&&fp.state==="risk"?"remove":"risk") + '">'
          + (fp&&fp.state==="risk"?"&#10003; Unmark":"&#128737; Accept Risk") + '</button>'
          + '</div>';
      }

      html += '<div class="' + (fp ? 'result-fp' : '') + '" style="border-left:3px solid '+(isVuln?sev:"#30363d")+';padding:9px 12px;margin:5px 0;border-radius:0 5px 5px 0;background:'+(isVuln?"rgba(248,81,73,.05)":"rgba(63,185,80,.03)")+'">'
        + '<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:4px">'
        + '<span style="font-weight:600;font-size:.87em;color:'+(isVuln?sev:"#3fb950")+'">'+(isVuln?"&#10007;":"&#10003;")+" "+t.test+fpBadge+regBadge+'</span>'
        + '<span style="font-size:.76em;color:'+sev+';font-weight:700">'+t.severity+'</span></div>'
        + '<div style="font-size:.78em;color:#8b949e;margin-top:2px"><code>' + t.request + '</code></div>'
        + '<div style="font-size:.82em;margin-top:4px">' + t.actual + '</div>'
        + evHtml + fpBtns + '</div>';
    }
    html += '</div>'; // /per-test rows

    if (cve && catVuln) {
      var badges2 = '';
      for (var bi = 0; bi < cve.cves.length; bi++) {
        badges2 += '<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/' + cve.cves[bi] + '" target="_blank">' + cve.cves[bi] + '</a>';
      }
      var fixItems2 = '';
      for (var fi2 = 0; fi2 < cve.fixes.length; fi2++) {
        fixItems2 += '<li>' + cve.fixes[fi2] + '</li>';
      }
      html += '<div class="cve-panel"><h4>CVE References &amp; Remediation</h4>'
        + '<div class="cve-row">' + badges2
        + '<a class="owasp-link" href="' + cve.owasp_ref + '" target="_blank">OWASP Reference &#x2192;</a>'
        + '</div><p class="vuln-desc">' + cve.description + '</p>'
        + '<div class="fixes"><ol>' + fixItems2 + '</ol></div></div>';
    }
    html += '</div>'; // /cat-block
  }

  // ── Export bar ───────────────────────────────────────────────────────────────
  html += '<div class="export-bar" style="flex-wrap:wrap;gap:8px">'
    + '<span style="font-size:.82em;color:#8b949e;margin-right:4px">Export:</span>'
    + '<button type="button" class="btn-save btn-save-brief js-save" data-detail="brief">&#128196; Brief Report</button>'
    + '<button type="button" class="btn-save btn-save-detail js-save" data-detail="detailed">&#128196; Detailed Report</button>'
    + '<button type="button" class="btn-save" style="background:rgba(188,140,255,.1);color:#bc8cff;border-color:rgba(188,140,255,.4)" id="btn-sarif-dl">&#8675; SARIF</button>'
    + '<button type="button" class="btn-save" style="background:rgba(88,166,255,.1);color:#58a6ff;border-color:rgba(88,166,255,.4)" id="btn-html-dl">&#8675; HTML Report</button>'
    + '<button type="button" class="btn-save" style="background:rgba(63,185,80,.1);color:#3fb950;border-color:rgba(63,185,80,.4)" id="btn-webhook">&#128276; Send Alert</button>'
    + '<span id="save-msg" style="font-size:.82em;margin-left:4px"></span></div>';

  // ── Scan history panel ───────────────────────────────────────────────────────
  html += renderHistoryPanel();

  el.innerHTML = html;

  // Wire FP buttons (re-renders on click)
  el.querySelectorAll(".js-fp").forEach(function(btn){
    btn.addEventListener("click", function(){
      var tgt = decodeURIComponent(btn.getAttribute("data-target"));
      var tn  = decodeURIComponent(btn.getAttribute("data-test"));
      var st  = btn.getAttribute("data-state");
      setFP(tgt, tn, st === "remove" ? null : st);
      renderResults(data); // re-render with updated FP store
    });
  });

  // Wire new export buttons
  var sarifBtn = document.getElementById("btn-sarif-dl");
  if (sarifBtn) sarifBtn.addEventListener("click", function(){ exportSARIF(data); });
  var htmlBtn = document.getElementById("btn-html-dl");
  if (htmlBtn) htmlBtn.addEventListener("click", function(){ exportHTMLReport(data); });
  var whBtn = document.getElementById("btn-webhook");
  if (whBtn) whBtn.addEventListener("click", sendWebhook);
  var clrHistBtn = document.getElementById("btn-clear-hist");
  if (clrHistBtn) clrHistBtn.addEventListener("click", function(){
    try { localStorage.removeItem(HIST_KEY); } catch(e){}
    renderResults(data);
  });
}

function saveReport(detail) {
  if (!_lastScan) return;
  var msg = document.getElementById("save-msg");
  if (!msg) return;
  msg.style.color = "#8b949e";
  msg.textContent = "Saving...";
  fetch("/monitor/save-report", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      target: _lastScan.target,
      timestamp: _lastScan.timestamp,
      score: _lastScan.score,
      total_tests: _lastScan.total_tests,
      total_vulnerable: _lastScan.total_vulnerable,
      categories: _lastScan.categories,
      detail: detail
    })
  })
    .then(function(r) {
      if (!r.ok) return r.text().then(function(t) { throw new Error(t); });
      return r.json();
    })
    .then(function(res) {
      msg.innerHTML = 'Saved! <a href="/monitor/reports/' + res.html_file + '" target="_blank" style="color:#58a6ff;font-weight:600">View Report &#x2192;</a>';
    })
    .catch(function(e) {
      msg.style.color = "#f85149";
      msg.textContent = "Error: " + e.message;
    });
}

// ── Wizard navigation ─────────────────────────────────────────────────────────
var _currentStep = 1;
var _maxStep     = 1;   // highest step ever reached — used for free navigation
var _totalSteps  = 4;

function gotoStep(n) {
  // Validate only when moving forward beyond already-visited steps
  if (n > _maxStep) {
    if (_currentStep === 1 || (n > 1 && _maxStep < 1)) {
      var t = (document.getElementById("f-target").value || "").trim();
      if (!t) {
        document.getElementById("f-target").focus();
        document.getElementById("f-target").style.borderColor = "#f85149";
        setTimeout(function(){ document.getElementById("f-target").style.borderColor = ""; }, 1800);
        var sb = document.getElementById("status-bar");
        sb.style.display = "block";
        sb.innerHTML = '<span style="color:#f85149">&#9888; Enter a target URL before continuing.</span>';
        return;
      }
      if (!t.startsWith("http://") && !t.startsWith("https://")) {
        var sb = document.getElementById("status-bar");
        sb.style.display = "block";
        sb.innerHTML = '<span style="color:#e3b341">&#9888; URL should start with http:// or https://</span>';
      }
    }
  }

  _currentStep = n;
  if (n > _maxStep) _maxStep = n;

  // show/hide panes
  for (var i = 1; i <= _totalSteps; i++) {
    var pane = document.getElementById("step-" + i);
    if (pane) pane.classList.toggle("active", i === n);
  }

  // update step indicator circles + reachable styling
  for (var i = 1; i <= _totalSteps; i++) {
    var ws = document.getElementById("ws-" + i);
    if (!ws) continue;
    ws.classList.remove("active", "done", "reachable");
    if (i === n)          ws.classList.add("active");
    else if (i < n)       ws.classList.add("done");
    else if (i <= _maxStep) ws.classList.add("reachable");  // visited but not current

    var circle = ws.querySelector(".ws-circle");
    if (circle) {
      if (i < n && i <= _maxStep) circle.innerHTML = "&#10003;";  // ✓ for done+visited
      else                         circle.textContent = String(i);
    }

    // cursor: pointer for any reachable step
    ws.style.cursor = (i <= _maxStep) ? "pointer" : "default";
    ws.style.opacity = (i <= _maxStep || i === n) ? "1" : "0.45";
  }

  // update connector lines
  for (var i = 1; i <= _totalSteps - 1; i++) {
    var line = document.getElementById("wl-" + i);
    if (line) line.classList.toggle("done", i < n);
  }
  window.scrollTo({top: 0, behavior: "smooth"});
}

// ── FAQ Help panel ────────────────────────────────────────────────────────────
function openHelp(targetId) {
  document.getElementById("help-overlay").classList.add("open");
  document.getElementById("help-panel").classList.add("open");
  if (targetId) {
    setTimeout(function() {
      var btn = document.getElementById(targetId);
      if (btn) {
        var answerId = targetId.replace("fq-", "fa-");
        // open this section
        btn.classList.add("open");
        var ans = document.getElementById(answerId);
        if (ans) ans.classList.add("open");
        btn.scrollIntoView({behavior: "smooth", block: "center"});
      }
    }, 250);
  }
}
function closeHelp() {
  document.getElementById("help-overlay").classList.remove("open");
  document.getElementById("help-panel").classList.remove("open");
}
function toggleFaq(btn) {
  var answerId = btn.id.replace("fq-", "fa-");
  var ans = document.getElementById(answerId);
  var isOpen = btn.classList.contains("open");
  // close all others
  var allBtns = document.querySelectorAll(".faq-q");
  var allAnss = document.querySelectorAll(".faq-a");
  for (var i = 0; i < allBtns.length; i++) allBtns[i].classList.remove("open");
  for (var i = 0; i < allAnss.length; i++) allAnss[i].classList.remove("open");
  if (!isOpen) {
    btn.classList.add("open");
    if (ans) ans.classList.add("open");
  }
}
function faqSearch(val) {
  var v = val.toLowerCase().trim();
  var sections = document.querySelectorAll(".faq-section");
  sections.forEach(function(sec) {
    if (!v) { sec.style.display = ""; return; }
    var kw = (sec.getAttribute("data-keywords") || "").toLowerCase();
    var qText = (sec.querySelector(".faq-q") || {}).textContent || "";
    var aText = (sec.querySelector(".faq-a") || {}).textContent || "";
    sec.style.display = (kw.includes(v) || qText.toLowerCase().includes(v) || aText.toLowerCase().includes(v)) ? "" : "none";
  });
}

function toggleTheme() {
  var current = document.documentElement.getAttribute("data-theme") || "dark";
  var next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("mazapiTheme", next);
  var btn = document.getElementById("theme-toggle-btn");
  if (btn) {
    btn.textContent = next === "light" ? "🌙 Dark" : "☀️ Light";
  }
}

document.addEventListener("DOMContentLoaded", function() {
  // Theme initialization
  var initialTheme = localStorage.getItem("mazapiTheme") || "dark";
  document.documentElement.setAttribute("data-theme", initialTheme);
  var themeBtn = document.getElementById("theme-toggle-btn");
  if (themeBtn) {
    themeBtn.textContent = initialTheme === "light" ? "🌙 Dark" : "☀️ Light";
  }
  // ── HAR file import ─────────────────────────────────────────────────────────
  document.getElementById("har-file-input").addEventListener("change", function(e) {
    var file = e.target.files[0];
    if (!file) return;
    showCaptureStatus("&#128229; Parsing " + file.name + "…", "Reading HAR entries…", "running");
    lockStep1(true);
    var reader = new FileReader();
    reader.onload = function(ev) {
      var harJson;
      try { harJson = JSON.parse(ev.target.result); } catch(err) {
        lockStep1(false);
        showCaptureStatus("&#10060; HAR parse error", "Not valid JSON / HAR format: " + err.message, "error");
        return;
      }
      fetch("/monitor/scan/import-har", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(harJson)
      })
      .then(function(r){ return r.json(); })
      .then(function(d) {
        lockStep1(false);
        if (d.base_url) document.getElementById("f-target").value = d.base_url;
        if (d.token)    document.getElementById("f-direct-token").value = d.token;
        if (d.auth_endpoint) { document.getElementById("f-auth-ep").value = d.auth_endpoint; document.getElementById("f-rate-ep").value = d.auth_endpoint; }
        if (d.bola_path) { document.getElementById("f-bola").value = d.bola_path; document.getElementById("f-update").value = d.bola_path.replace("{id}","1"); }
        if (d.token) setAuthTab("bearer");
        var srcs = [];
        if (d.token) srcs.push("&#10003; bearer token");
        if (d.api_keys && d.api_keys.length) srcs.push("&#10003; API key (" + d.api_keys[0].header + ")");
        showCaptureStatus(
          "&#10003; HAR imported — <b>" + d.total_paths + " endpoints</b> from " + d.entries_parsed + " requests",
          srcs.length ? srcs.join(" &nbsp;·&nbsp; ") : "No auth token detected in HAR headers.",
          "done"
        );
        if (d.paths && d.paths.length) {
          var discList = document.getElementById("discover-paths");
          if (!discList) { discList = document.createElement("div"); discList.id = "discover-paths"; discList.style.cssText = "margin-top:8px;padding:7px 10px;background:#0d1117;border:1px solid #21262d;border-radius:6px;font-size:.76em;color:#8b949e;max-height:80px;overflow-y:auto;font-family:monospace"; document.getElementById("capture-status-box").after(discList); }
          discList.textContent = d.paths.slice(0,30).join("  ·  ") + (d.paths.length>30 ? "  …+" + (d.paths.length-30) + " more" : "");
        }
        setTimeout(function(){ gotoStep(2); }, 400);
      })
      .catch(function(err){ lockStep1(false); showCaptureStatus("&#10060; Error", err.message, "error"); });
    };
    reader.readAsText(file);
  });
  document.getElementById("btn-har").addEventListener("click", function(){
    document.getElementById("har-file-input").click();
  });

  // Toggle arrow on capture-auth details open/close
  var capDetails = document.getElementById("capture-auth-details");
  if (capDetails) {
    capDetails.addEventListener("toggle", function() {
      var arrow = document.getElementById("capture-auth-arrow");
      if (arrow) arrow.style.transform = capDetails.open ? "rotate(90deg)" : "";
    });
  }

  // ── Capture status helpers ────────────────────────────────────────────────
  var _captureAbort = null;

  function showCaptureStatus(main, detail, state) {
    // state: "running" | "done" | "error"
    var box = document.getElementById("capture-status-box");
    var mainEl   = document.getElementById("capture-status-main");
    var detailEl = document.getElementById("capture-status-detail");
    var spinner  = document.getElementById("capture-spinner");
    var stopBtn  = document.getElementById("btn-stop-capture");
    box.style.display = "block";
    box.className = state === "error" ? "error" : (state === "done" ? "done" : "");
    mainEl.innerHTML  = main;
    detailEl.innerHTML = detail || "";
    spinner.style.display  = (state === "running") ? "inline-block" : "none";
    stopBtn.style.display  = (state === "running") ? "inline-block" : "none";
  }

  function hideCaptureStatus() {
    document.getElementById("capture-status-box").style.display = "none";
    document.getElementById("capture-login-steps").style.display = "none";
  }

  function lockStep1(locked) {
    var step1 = document.getElementById("step-1");
    if (locked) step1.classList.add("capture-locked");
    else        step1.classList.remove("capture-locked");
  }

  function fillFromCapture(d) {
    if (d.base_url)       document.getElementById("f-target").value    = d.base_url;
    if (d.auth_endpoint)  document.getElementById("f-auth-ep").value   = d.auth_endpoint;
    if (d.auth_endpoint)  document.getElementById("f-rate-ep").value   = d.auth_endpoint;
    if (d.bola_path)      document.getElementById("f-bola").value      = d.bola_path;
    if (d.update_path)    document.getElementById("f-update").value    = d.update_path;
    if (d.protected_path) document.getElementById("f-protected").value = d.protected_path;
    if (d.token) {
      document.getElementById("f-direct-token").value = d.token;
      setAuthTab("bearer");
    }
    if (d.paths && d.paths.length) {
      var discList = document.getElementById("discover-paths");
      if (!discList) {
        discList = document.createElement("div");
        discList.id = "discover-paths";
        discList.style.cssText = "margin-top:8px;padding:7px 10px;background:#0d1117;border:1px solid #21262d;border-radius:6px;font-size:.76em;color:#8b949e;max-height:80px;overflow-y:auto;font-family:monospace";
        document.getElementById("capture-status-box").after(discList);
      }
      discList.textContent = d.paths.slice(0,30).join("  ·  ") + (d.paths.length>30 ? "  …+" + (d.paths.length-30) + " more" : "");
    }
  }

  // ── Stop button ──────────────────────────────────────────────────────────
  document.getElementById("btn-stop-capture").addEventListener("click", function() {
    if (_captureAbort) _captureAbort.abort();
    lockStep1(false);
    showCaptureStatus("Capture stopped.", "", "error");
    document.getElementById("btn-stop-capture").style.display = "none";
    document.getElementById("btn-playwright").disabled = false;
  });

  // ── Playwright live capture ──────────────────────────────────────────────
  document.getElementById("btn-playwright").addEventListener("click", function() {
    var target     = (document.getElementById("f-target").value    || "").trim();
    var username   = (document.getElementById("cap-username").value || "").trim();
    var password   = (document.getElementById("cap-password").value || "").trim();
    var authEp     = (document.getElementById("cap-auth-ep").value  || "").trim();
    var tokenField = (document.getElementById("cap-token-field").value || "").trim();
    if (!target) { alert("Enter the target URL above first, then click Capture."); return; }

    var hasLogin = username && password;
    var loginLabel = hasLogin ? "Logging in as <b>" + username + "</b>…" : "Scanning for API endpoints…";

    showCaptureStatus(
      "&#129302; Headless Chromium is running in the background — no browser window will open.",
      loginLabel + " This takes 15–30 seconds. <em>Do not edit the fields below until capture is complete.</em>",
      "running"
    );
    lockStep1(true);
    document.getElementById("btn-playwright").disabled = true;

    _captureAbort = new AbortController();
    var qs = "url=" + encodeURIComponent(target);
    if (hasLogin) {
      qs += "&username=" + encodeURIComponent(username)
          + "&password=" + encodeURIComponent(password);
      if (authEp)     qs += "&auth_endpoint=" + encodeURIComponent(authEp);
      if (tokenField) qs += "&token_field="   + encodeURIComponent(tokenField);
    }

    fetch("/monitor/scan/capture?" + qs, { signal: _captureAbort.signal })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        lockStep1(false);
        document.getElementById("btn-playwright").disabled = false;

        if (d.error) {
          showCaptureStatus("&#10060; Capture failed", d.error, "error");
          return;
        }

        fillFromCapture(d);

        var parts = [];
        parts.push("<b>" + (d.total_paths||0) + " endpoints</b> discovered");
        if (d.requests_intercepted > 0) parts.push(d.requests_intercepted + " browser requests captured");
        if (d.token)                    parts.push("&#10003; Bearer token captured");
        if (d.api_keys && d.api_keys.length) parts.push("&#10003; API key captured (" + d.api_keys[0].header + ")");
        if (!d.token && hasLogin)       parts.push("&#9888; No token found — see login attempts below");

        showCaptureStatus(
          (d.token ? "&#10003;" : "&#9888;") + " Capture complete",
          parts.join(" &nbsp;·&nbsp; ") + "<br><small style='color:#8b949e'>" + (d.note||"") + "</small>",
          "done"
        );

        // Show login attempt audit trail
        if (d.login_steps && d.login_steps.length) {
          var stepsEl = document.getElementById("capture-login-steps");
          stepsEl.style.display = "block";
          stepsEl.textContent   = d.login_steps.join("\\n");
        }

        if (d.total_paths > 0 || d.token) {
          setTimeout(function(){ gotoStep(2); }, 800);
        }
      })
      .catch(function(err) {
        lockStep1(false);
        document.getElementById("btn-playwright").disabled = false;
        if (err.name === "AbortError") return; // user clicked Stop
        showCaptureStatus("&#10060; Network error", err.message, "error");
      });
  });

  // Wizard nav buttons
  document.getElementById("btn-next-1").addEventListener("click", function(){ gotoStep(2); });
  document.getElementById("btn-back-2").addEventListener("click", function(){ gotoStep(1); });
  document.getElementById("btn-next-2").addEventListener("click", function(){ gotoStep(3); });
  document.getElementById("btn-back-3").addEventListener("click", function(){ gotoStep(2); });
  document.getElementById("btn-next-3").addEventListener("click", function(){ gotoStep(4); });
  document.getElementById("btn-back-4").addEventListener("click", function(){ gotoStep(3); });
  // Step indicator clicks — free navigation within visited steps
  document.querySelectorAll(".ws").forEach(function(ws) {
    ws.addEventListener("click", function(){
      var s = parseInt(ws.getAttribute("data-step"));
      if (s <= _maxStep) gotoStep(s);   // allow any previously-reached step
    });
  });
  // When a preset is selected, auto-advance if still on step 1
  ["preset-vulnerable","preset-hardened","preset-gemini","preset-graphql","preset-external"].forEach(function(id){
    var el = document.getElementById(id);
    if(el) el.addEventListener("click", function(){ setTimeout(function(){ if(_currentStep===1) gotoStep(2); }, 120); });
  });

  document.getElementById("help-btn").addEventListener("click", function() { openHelp(null); });
  document.getElementById("help-close").addEventListener("click", closeHelp);
  document.getElementById("help-overlay").addEventListener("click", closeHelp);
  document.getElementById("faq-search").addEventListener("input", function() { faqSearch(this.value); });
  var faqBtns = document.querySelectorAll(".faq-q");
  for (var i = 0; i < faqBtns.length; i++) {
    (function(b) { b.addEventListener("click", function() { toggleFaq(b); }); })(faqBtns[i]);
  }

  document.getElementById("preset-vulnerable").addEventListener("click", function() { loadPreset("vulnerable"); });
  document.getElementById("preset-hardened").addEventListener("click", function() { loadPreset("hardened"); });
  document.getElementById("preset-gemini").addEventListener("click", function() { loadPreset("gemini"); });
  document.getElementById("preset-graphql").addEventListener("click", function() { loadPreset("graphql"); });
  document.getElementById("preset-external").addEventListener("click", function() { loadPreset("external"); });

  var aptBtns = document.querySelectorAll(".api-type-btn");
  for (var i = 0; i < aptBtns.length; i++) {
    (function(btn) {
      btn.addEventListener("click", function() { setApiType(btn.getAttribute("data-aptype")); });
    })(aptBtns[i]);
  }

  var tabs = document.querySelectorAll(".auth-tab");
  for (var i = 0; i < tabs.length; i++) {
    (function(tab) {
      tab.addEventListener("click", function() { setAuthTab(tab.getAttribute("data-auth")); });
    })(tabs[i]);
  }

  document.getElementById("btn-discover").addEventListener("click", discoverSchema);
  document.getElementById("btn-select-all").addEventListener("click", function() { toggleAll(true); });
  document.getElementById("btn-clear-all").addEventListener("click", function() { toggleAll(false); });
  document.getElementById("scan-btn").addEventListener("click", runScan);

  document.getElementById("results").addEventListener("click", function(e) {
    var btn = e.target;
    while (btn && btn !== this) {
      if (btn.classList && btn.classList.contains("js-save")) {
        saveReport(btn.getAttribute("data-detail"));
        return;
      }
      btn = btn.parentNode;
    }
  });
});
</script>
</body>
</html>"""


@app.get("/scan-ui", response_class=HTMLResponse, include_in_schema=False)
async def scan_ui():
    return _SCAN_UI_HTML_V2


# ── report browser ─────────────────────────────────────────────────────────────
_REPORTS_DIR = "/reports"


@app.get("/monitor/reports")
async def list_reports():
    if not os.path.exists(_REPORTS_DIR):
        return []
    entries = []
    for jf in sorted(_glob.glob(os.path.join(_REPORTS_DIR, "*.json")), reverse=True):
        name = os.path.basename(jf)
        html_name = name.replace(".json", ".html")
        html_exists = os.path.exists(os.path.join(_REPORTS_DIR, html_name))
        info: dict = {
            "json_file": name,
            "html_file": html_name if html_exists else None,
            "modified": os.path.getmtime(jf),
        }
        try:
            with open(jf) as f:
                data = _json.load(f)
            info["target"]     = data.get("target", data.get("vulnerable_url", "—"))
            info["timestamp"]  = data.get("timestamp", "—")
            info["score"]      = data.get("score")          # scan report
            info["hard_score"] = data.get("hard_score")     # comparison report
            info["vuln_score"] = data.get("vuln_score")     # comparison report
            info["detail"]     = data.get("detail")         # brief / detailed / None
        except Exception:
            pass
        entries.append(info)
    return entries


@app.get("/monitor/reports/{filename}")
async def serve_report(filename: str):
    if not _re.match(r'^[\w\-\.]+$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = os.path.join(_REPORTS_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found")
    media = "application/json" if filename.endswith(".json") else "text/html"
    return FileResponse(path, media_type=media)


@app.delete("/monitor/reports/{filename}")
async def delete_report(filename: str):
    if not _re.match(r'^[\w\-\.]+$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename")
    base = _re.sub(r'\.(json|html)$', '', filename)
    deleted = []
    for ext in (".json", ".html"):
        p = os.path.join(_REPORTS_DIR, base + ext)
        if os.path.exists(p):
            os.remove(p)
            deleted.append(base + ext)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"deleted": deleted}


def _build_report_html(req: "SaveReportRequest") -> str:
    from html import escape as _esc
    _CSS = """
    :root {
      --bg: #090d16;
      --surf: #111827;
      --surf-alt: #1f293d;
      --border: rgba(255, 255, 255, 0.08);
      --border-glow: rgba(99, 102, 241, 0.4);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --blue: #6366f1;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
      --accent-dim: rgba(99, 102, 241, 0.08);
      --radius: 12px;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
      --font-title: 'Outfit', sans-serif;
      --font-body: 'Inter', sans-serif;
      --header-bg: linear-gradient(135deg, #1e1b4e 0%, #0f172a 100%);
      --header-text: #ffffff;
      --header-sub: #94a3b8;
    }
    [data-theme="light"] {
      --bg: #f8fafc;
      --surf: #ffffff;
      --surf-alt: #f1f5f9;
      --border: rgba(148, 163, 184, 0.2);
      --border-glow: rgba(79, 70, 229, 0.3);
      --text: #0f172a;
      --text-muted: #64748b;
      --blue: #4f46e5;
      --green: #059669;
      --red: #dc2626;
      --yellow: #d97706;
      --accent-dim: rgba(79, 70, 229, 0.06);
      --shadow: 0 4px 20px rgba(149, 157, 165, 0.1);
      --header-bg: linear-gradient(135deg, #e0e7ff 0%, #f1f5f9 100%);
      --header-text: #1e1b4e;
      --header-sub: #4f46e5;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--font-body);
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      transition: background 0.2s, color 0.2s;
    }
    .theme-float-btn {
      position: fixed; top: 16px; right: 20px; z-index: 9999;
      background: var(--surf-alt); border: 1px solid var(--border); color: var(--text);
      padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: 0.85em; font-weight: 600;
      box-shadow: var(--shadow); transition: all 0.18s; font-family: var(--font-body);
    }
    .theme-float-btn:hover { border-color: var(--blue); color: var(--blue); transform: translateY(-1px); }
    .header {
      background: var(--header-bg);
      padding: 60px 20px; text-align: center; color: var(--header-text);
      border-bottom: 1px solid var(--border);
      transition: background 0.2s, color 0.2s;
    }
    .header h1 {
      font-family: var(--font-title); font-size: 2.6em; font-weight: 800; margin-bottom: 12px;
      letter-spacing: -0.02em;
    }
    .header p { color: var(--header-sub); font-size: 1em; font-weight: 500; }
    .detail-badge {
      background: rgba(99, 102, 241, 0.15); color: var(--blue); border: 1px solid rgba(99, 102, 241, 0.4);
      padding: 4px 12px; border-radius: 20px; font-size: 0.45em; font-weight: 700;
      vertical-align: middle; margin-left: 10px; text-transform: uppercase;
      font-family: var(--font-body);
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: -50px; margin-bottom: 40px; }
    @media (max-width: 768px) {
      .cards { grid-template-columns: 1fr 1fr; margin-top: -30px; }
    }
    .card {
      background: var(--surf); border: 1px solid var(--border); border-radius: var(--radius);
      padding: 24px 16px; text-align: center; box-shadow: var(--shadow);
      transition: transform 0.2s, border-color 0.2s;
    }
    .card:hover { transform: translateY(-2px); border-color: var(--border-glow); }
    .card .num { font-family: var(--font-title); font-size: 2.4em; font-weight: 800; line-height: 1.1; }
    .card .lbl { color: var(--text-muted); font-size: 0.85em; margin-top: 6px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .red { color: var(--red); }
    .green { color: var(--green); }
    .blue { color: var(--blue); }
    .yellow { color: var(--yellow); }
    
    .cat {
      background: var(--surf); border: 1px solid var(--border); border-radius: var(--radius);
      margin-bottom: 24px; box-shadow: var(--shadow); overflow: hidden;
    }
    .cat-hdr {
      padding: 18px 24px; border-bottom: 1px solid var(--border); background: var(--surf-alt);
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    }
    .cat-hdr h2 { font-family: var(--font-title); font-size: 1.2em; font-weight: 700; color: var(--text); }
    .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.78em; font-weight: 700; }
    .bv { background: rgba(239, 68, 68, 0.08); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); }
    .bs { background: rgba(16, 185, 129, 0.08); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }
    
    .sev-CRITICAL { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid var(--red); }
    .sev-HIGH { background: rgba(244, 63, 94, 0.15); color: var(--red); border: 1px solid var(--red); }
    .sev-MEDIUM { background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid var(--yellow); }
    .sev-LOW { background: rgba(99, 102, 241, 0.15); color: var(--blue); border: 1px solid var(--blue); }
    
    table { width: 100%; border-collapse: collapse; }
    th {
      background: var(--surf-alt); padding: 14px 18px; text-align: left;
      font-size: 0.78em; color: var(--text-muted); text-transform: uppercase;
      letter-spacing: 0.05em; border-bottom: 1px solid var(--border);
    }
    td { padding: 14px 18px; border-top: 1px solid var(--border); font-size: 0.9em; word-break: break-word; }
    code {
      background: var(--surf-alt); padding: 3px 6px; border-radius: 4px;
      font-size: 0.88em; font-family: 'Fira Code', Consolas, monospace;
    }
    .vY { color: var(--red); font-weight: 700; white-space: nowrap; }
    .vN { color: var(--green); font-weight: 600; white-space: nowrap; }
    .sC { color: var(--red); }
    .sH { color: var(--red); }
    .sM { color: var(--yellow); }
    .sL { color: var(--blue); }
    
    .cve-panel { padding: 24px; border-top: 1px solid var(--border); background: var(--surf-alt); }
    .cve-panel h4 {
      color: var(--text-muted); font-size: 0.8em; text-transform: uppercase;
      letter-spacing: 0.08em; margin-bottom: 14px; font-weight: 700;
    }
    .cve-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: center; }
    .cve-badge {
      background: var(--surf); border: 1px solid var(--border); border-radius: 6px;
      padding: 4px 10px; font-size: 0.8em; font-family: 'Fira Code', monospace; color: var(--blue);
      text-decoration: none; transition: all 0.2s;
    }
    .cve-badge:hover { border-color: var(--blue); background: var(--accent-dim); }
    .owasp-link { font-size: 0.82em; color: var(--text-muted); text-decoration: none; margin-left: auto; font-weight: 500; }
    .owasp-link:hover { color: var(--blue); }
    .vuln-desc { font-size: 0.88em; color: var(--text-muted); margin-bottom: 14px; line-height: 1.6; }
    .fixes h5 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 10px; font-weight: 700; }
    .fixes ol { padding-left: 20px; }
    .fixes li { font-size: 0.9em; color: var(--text); line-height: 1.65; padding: 3px 0; }
    
    .detail-section { padding: 24px; border-top: 2px solid var(--border); background: var(--surf-alt); }
    .impact-block { margin-bottom: 20px; }
    .impact-block h4 { color: var(--yellow); font-family: var(--font-title); font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 10px; }
    .impact-block p { font-size: 0.9em; color: var(--text); line-height: 1.6; }
    .poc-block { margin-bottom: 20px; }
    .poc-block h5 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); margin-bottom: 10px; font-weight: 700; }
    .poc-block ol { padding-left: 20px; }
    .poc-block li { font-size: 0.9em; color: var(--text); line-height: 1.65; padding: 3px 0; }
    .code-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 14px; }
    @media (max-width: 768px) {
      .code-grid { grid-template-columns: 1fr; }
    }
    .code-label { font-size: 0.75em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; padding: 6px 12px; display: inline-block; border-radius: 4px 4px 0 0; }
    .vuln-lbl { background: rgba(239, 68, 68, 0.08); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); border-bottom: none; }
    .fix-lbl { background: rgba(16, 185, 129, 0.08); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); border-bottom: none; }
    pre.code-pre {
      background: var(--surf); border: 1px solid var(--border); border-radius: 0 var(--radius) var(--radius) var(--radius);
      padding: 16px; font-size: 0.85em; font-family: 'Fira Code', Consolas, monospace; color: var(--text);
      overflow-x: auto; white-space: pre; margin: 0; line-height: 1.6;
    }
    .footer {
      text-align: center; padding: 40px 20px; color: var(--text-muted); font-size: 0.85em;
      border-top: 1px solid var(--border); margin-top: 40px; font-weight: 500;
    }

    """

    total_vuln = req.total_vulnerable
    total_tests = req.total_tests
    score = req.score
    ts = req.timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    detail_badge = '<span class="detail-badge">Detailed</span>' if req.detail == "detailed" else ""

    cats_html = ""
    for cat in req.categories:
        cve = _CVE_DB_M.get(cat.get("category", ""), {})
        sev = cve.get("severity", "")
        sev_badge = f'<span class="badge sev-{sev}">{sev}</span>' if sev else ""
        vc = cat.get("vulnerable_count", 0)
        tot = cat.get("total", 0)
        vuln_cls = "bv" if vc > 0 else "bs"

        rows = ""
        for t in cat.get("tests", []):
            rc = "vY" if t.get("vulnerable") else "vN"
            sc = "s" + t.get("severity", "M")[0]
            rows += (
                f"<tr><td>{_esc(t.get('test',''))}</td>"
                f"<td><code>{_esc(t.get('request',''))}</code></td>"
                f"<td>{_esc(t.get('expected',''))}</td>"
                f"<td>{_esc(t.get('actual',''))}</td>"
                f"<td class='{sc}'>{t.get('severity','')}</td>"
                f"<td class='{rc}'>{'VULNERABLE' if t.get('vulnerable') else 'SECURE'}</td></tr>"
            )

        cve_html = ""
        if cve and vc > 0:
            badges = "".join(
                f'<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank">{c}</a>'
                for c in cve.get("cves", [])
            )
            fixes = "".join(f"<li>{_esc(f)}</li>" for f in cve.get("fixes", []))
            cve_html = (
                f'<div class="cve-panel"><h4>CVE References &amp; Remediation</h4>'
                f'<div class="cve-row">{badges}'
                f'<a class="owasp-link" href="{cve["owasp_ref"]}" target="_blank">OWASP Reference &rarr;</a></div>'
                f'<p class="vuln-desc">{_esc(cve.get("description",""))}</p>'
                f'<div class="fixes"><h5>Remediation Steps</h5><ol>{fixes}</ol></div></div>'
            )

        detail_html = ""
        if req.detail == "detailed" and cve.get("impact"):
            poc_html = ""
            if cve.get("poc_steps"):
                steps = "".join(f"<li>{_esc(s)}</li>" for s in cve["poc_steps"])
                poc_html = f'<div class="poc-block"><h5>Proof of Concept — Attack Steps</h5><ol>{steps}</ol></div>'
            code_html = ""
            if cve.get("code_before"):
                code_html = (
                    f'<div class="code-grid">'
                    f'<div class="code-pane"><div class="code-label vuln-lbl">Vulnerable Code</div>'
                    f'<pre class="code-pre">{_esc(cve["code_before"])}</pre></div>'
                    f'<div class="code-pane"><div class="code-label fix-lbl">Fixed Code</div>'
                    f'<pre class="code-pre">{_esc(cve["code_after"])}</pre></div></div>'
                )
            detail_html = (
                f'<div class="detail-section">'
                f'<div class="impact-block"><h4>Impact Assessment</h4><p>{_esc(cve["impact"])}</p></div>'
                f'{poc_html}{code_html}</div>'
            )

        cats_html += (
            f'<div class="cat">'
            f'<div class="cat-hdr"><h2>{_esc(cat.get("category",""))}</h2>'
            f'<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">{sev_badge}'
            f'<span class="badge {vuln_cls}">{vc}/{tot} Vulnerable</span></div></div>'
            f'<table><tr><th>Test</th><th>Request</th><th>Expected</th><th>Actual</th><th>Severity</th><th>Result</th></tr>'
            f'{rows}</table>{cve_html}{detail_html}</div>'
        )

    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<title>API Security Report</title>'
        f'<link rel="preconnect" href="https://fonts.googleapis.com">'
        f'<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        f'<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">'
        f'<style>{_CSS}</style></head><body>'
        f'<button class="theme-float-btn" id="theme-float-btn" onclick="toggleReportTheme()">☀️ Light</button>'
        f'<div class="header"><h1>API Security Test Report {detail_badge}</h1>'
        f'<p>Target: {_esc(req.target)} &nbsp;|&nbsp; {_esc(ts)} &nbsp;|&nbsp; OWASP API Top 10:2023</p></div>'
        f'<div class="container">'
        f'<div class="cards">'
        f'<div class="card"><div class="num red">{total_vuln}</div><div class="lbl">Vulnerabilities Found</div></div>'
        f'<div class="card"><div class="num blue">{total_tests}</div><div class="lbl">Tests Executed</div></div>'
        f'<div class="card"><div class="num green">{total_tests - total_vuln}</div><div class="lbl">Tests Passed</div></div>'
        f'<div class="card"><div class="num {score_color}">{score}%</div><div class="lbl">Security Score</div></div>'
        f'</div>{cats_html}</div>'
        f'<div class="footer">CY384 API Security Project &nbsp;|&nbsp; University of Mines and Technology, Ghana &nbsp;|&nbsp; OWASP API Security Top 10:2023</div>'
        f'<script>'
        f'function toggleReportTheme() {{'
        f'  var current = document.documentElement.getAttribute("data-theme") || "dark";'
        f'  var next = current === "dark" ? "light" : "dark";'
        f'  document.documentElement.setAttribute("data-theme", next);'
        f'  localStorage.setItem("mazapiTheme", next);'
        f'  var btn = document.getElementById("theme-float-btn");'
        f'  if (btn) btn.textContent = next === "light" ? "🌙 Dark" : "☀️ Light";'
        f'}}'
        f'(function() {{'
        f'  var theme = localStorage.getItem("mazapiTheme") || "dark";'
        f'  document.documentElement.setAttribute("data-theme", theme);'
        f'  var btn = document.getElementById("theme-float-btn");'
        f'  if (btn) btn.textContent = theme === "light" ? "🌙 Dark" : "☀️ Light";'
        f'}})();'
        f'</script>'
        f'</body></html>'
    )


@app.post("/monitor/save-report")
async def save_report(req: SaveReportRequest):
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    ts_label = req.timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ts_file  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    slug = req.target.replace("http://", "").replace("https://", "").replace(":", "-").replace("/", "_").rstrip("_")
    suffix = "_detailed" if req.detail == "detailed" else ""

    json_name = f"report_{slug}_{ts_file}{suffix}.json"
    json_data = {
        "target": req.target, "timestamp": ts_label,
        "score": req.score, "detail": req.detail,
        "total_tests": req.total_tests, "total_vulnerable": req.total_vulnerable,
        "categories": req.categories,
    }
    with open(os.path.join(_REPORTS_DIR, json_name), "w") as f:
        _json.dump(json_data, f, indent=2)

    html_name = f"report_{slug}_{ts_file}{suffix}.html"
    req.timestamp = ts_label
    html_content = _build_report_html(req)
    with open(os.path.join(_REPORTS_DIR, html_name), "w") as f:
        f.write(html_content)

    return {"json_file": json_name, "html_file": html_name}


# ── comparison endpoint ────────────────────────────────────────────────────────

class CompareRequest(BaseModel):
    vulnerable_url: str = "http://vulnerable-api:8000"
    hardened_url: str = "http://hardened-api:8001"


_CMP_DETAIL = {
    "bola": {
        "attack_payload": "GET /users/2  (authenticated as alice, user_id=1)",
        "vuln_reason": "Returns HTTP 200 with another user's full profile — no ownership check performed.",
        "hard_reason": "Returns HTTP 403 Forbidden — FastAPI dependency enforces user_id == resource owner.",
    },
    "jwt": {
        "attack_payload": "GET /users/1  (forged JWT signed with key='secret', role='admin')",
        "vuln_reason": "Returns HTTP 200 — hard-coded weak secret 'secret' accepts any forged token.",
        "hard_reason": "Returns HTTP 401 Unauthorized — JWT_SECRET loaded from env; forged token rejected.",
    },
    "mass": {
        "attack_payload": 'PUT /users/1  {"role": "admin", "balance": 999999}',
        "vuln_reason": "Returns HTTP 200 with role='admin' applied — all extra fields accepted (mass assignment).",
        "hard_reason": "HTTP 200 but role/balance stripped from Pydantic schema; privilege unchanged.",
    },
    "rate": {
        "attack_payload": "POST /auth/login  x12 rapid requests (wrong password)",
        "vuln_reason": "All 12 return HTTP 401 — no rate limiting, unlimited brute-force possible.",
        "hard_reason": "HTTP 429 Too Many Requests after 5 attempts — slowapi 5/min limit enforced.",
    },
    "func": {
        "attack_payload": "GET /admin/users  (regular user JWT, role='user')",
        "vuln_reason": "Returns HTTP 200 with full user list — only authentication checked, role ignored.",
        "hard_reason": "Returns HTTP 403 Forbidden — require_admin dependency rejects non-admin tokens.",
    },
    "debug": {
        "attack_payload": "GET /debug/config  (no authentication token)",
        "vuln_reason": "HTTP 200 exposing JWT_SECRET, DB_URL, and full environment variables.",
        "hard_reason": "HTTP 404 Not Found — endpoint gated by ENV=development; hidden in production.",
    },
    "cors": {
        "attack_payload": "GET /health  Origin: http://evil.example.com",
        "vuln_reason": "Response includes Access-Control-Allow-Origin: * — any origin can call this API.",
        "hard_reason": "No wildcard ACAO header — CORS restricted to trusted origins only.",
    },
}


async def _cmp_login(client: httpx.AsyncClient, base: str):
    try:
        r = await client.post(base + "/auth/login",
                              json={"username": "alice", "password": "alice123"}, timeout=8)
        if r.status_code == 200:
            return r.json().get("access_token", ""), 1
    except Exception:
        pass
    return "", 1


async def _cmp_bola(client: httpx.AsyncClient, base: str, token: str):
    try:
        r = await client.get(base + "/users/2",
                             headers={"Authorization": f"Bearer {token}"}, timeout=8)
        vuln = r.status_code == 200
        return {"status": r.status_code, "pass": not vuln, "vulnerable": vuln}
    except Exception:
        return {"status": 0, "pass": False, "vulnerable": False}


async def _cmp_jwt(client: httpx.AsyncClient, base: str):
    try:
        from jose import jwt as _jose
        forged = _jose.encode({"sub": "1", "username": "alice", "role": "admin"},
                              "secret", algorithm="HS256")
        r = await client.get(base + "/users/1",
                             headers={"Authorization": f"Bearer {forged}"}, timeout=8)
        vuln = r.status_code == 200
        return {"status": r.status_code, "pass": not vuln, "vulnerable": vuln}
    except ImportError:
        return {"status": -1, "pass": None, "vulnerable": None}
    except Exception:
        return {"status": 0, "pass": False, "vulnerable": False}


async def _cmp_mass(client: httpx.AsyncClient, base: str, token: str):
    try:
        r = await client.put(base + "/users/1",
                             json={"role": "admin", "balance": 999999},
                             headers={"Authorization": f"Bearer {token}"}, timeout=8)
        if r.status_code in (200, 201):
            body = r.json()
            user_data = body.get("user", body)
            vuln = user_data.get("role") == "admin" or user_data.get("balance") == 999999
        else:
            vuln = False
        return {"status": r.status_code, "pass": not vuln, "vulnerable": vuln}
    except Exception:
        return {"status": 0, "pass": False, "vulnerable": False}


async def _cmp_rate(client: httpx.AsyncClient, base: str):
    got_429 = False
    for _ in range(12):
        try:
            r = await client.post(base + "/auth/login",
                                  json={"username": "__probe__", "password": "x"}, timeout=8)
            if r.status_code == 429:
                got_429 = True
                break
        except Exception:
            break
    return {"status": 429 if got_429 else 401, "pass": got_429, "vulnerable": not got_429}


async def _cmp_func(client: httpx.AsyncClient, base: str, token: str):
    try:
        r = await client.get(base + "/admin/users",
                             headers={"Authorization": f"Bearer {token}"}, timeout=8)
        vuln = r.status_code == 200
        return {"status": r.status_code, "pass": not vuln, "vulnerable": vuln}
    except Exception:
        return {"status": 0, "pass": False, "vulnerable": False}


async def _cmp_debug(client: httpx.AsyncClient, base: str):
    try:
        r = await client.get(base + "/debug/config", timeout=8)
        vuln = r.status_code == 200
        return {"status": r.status_code, "pass": not vuln, "vulnerable": vuln}
    except Exception:
        return {"status": 0, "pass": False, "vulnerable": False}


async def _cmp_cors(client: httpx.AsyncClient, base: str):
    try:
        r = await client.get(base + "/health",
                             headers={"Origin": "http://evil.example.com"}, timeout=8)
        acao = r.headers.get("access-control-allow-origin", "")
        vuln = acao == "*"
        return {"status": r.status_code, "pass": not vuln, "vulnerable": vuln}
    except Exception:
        return {"status": 0, "pass": False, "vulnerable": False}


def _build_comparison_html(rows: list, vuln_url: str, hard_url: str,
                            vuln_score: int, hard_score: int, ts_label: str) -> str:
    from html import escape as _esc
    improvement = hard_score - vuln_score
    imp_sign  = "+" if improvement > 0 else ""
    imp_color = "var(--green)" if improvement > 0 else "var(--red)" if improvement < 0 else "var(--yellow)"
    _CSS = """
    :root {
      --bg: #090d16;
      --surf: #111827;
      --surf-alt: #1f293d;
      --border: rgba(255, 255, 255, 0.08);
      --border-glow: rgba(99, 102, 241, 0.4);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --blue: #6366f1;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
      --accent-dim: rgba(99, 102, 241, 0.08);
      --radius: 12px;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
      --font-title: 'Outfit', sans-serif;
      --font-body: 'Inter', sans-serif;
      --header-bg: linear-gradient(135deg, #1e1b4e 0%, #0f172a 100%);
      --header-text: #ffffff;
      --header-sub: #94a3b8;
    }
    [data-theme="light"] {
      --bg: #f8fafc;
      --surf: #ffffff;
      --surf-alt: #f1f5f9;
      --border: rgba(148, 163, 184, 0.2);
      --border-glow: rgba(79, 70, 229, 0.3);
      --text: #0f172a;
      --text-muted: #64748b;
      --blue: #4f46e5;
      --green: #059669;
      --red: #dc2626;
      --yellow: #d97706;
      --accent-dim: rgba(79, 70, 229, 0.06);
      --shadow: 0 4px 20px rgba(149, 157, 165, 0.1);
      --header-bg: linear-gradient(135deg, #e0e7ff 0%, #f1f5f9 100%);
      --header-text: #1e1b4e;
      --header-sub: #4f46e5;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--font-body);
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      transition: background 0.2s, color 0.2s;
    }
    .theme-float-btn {
      position: fixed; top: 16px; right: 20px; z-index: 9999;
      background: var(--surf-alt); border: 1px solid var(--border); color: var(--text);
      padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: 0.85em; font-weight: 600;
      box-shadow: var(--shadow); transition: all 0.18s; font-family: var(--font-body);
    }
    .theme-float-btn:hover { border-color: var(--blue); color: var(--blue); transform: translateY(-1px); }
    .header {
      background: var(--header-bg);
      padding: 60px 20px; text-align: center; color: var(--header-text);
      border-bottom: 1px solid var(--border);
      transition: background 0.2s, color 0.2s;
    }
    .header h1 {
      font-family: var(--font-title); font-size: 2.6em; font-weight: 800; margin-bottom: 12px;
      letter-spacing: -0.02em;
    }
    .header p { color: var(--header-sub); font-size: 1em; font-weight: 500; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: -50px; margin-bottom: 40px; }
    @media (max-width: 768px) {
      .cards { grid-template-columns: 1fr; margin-top: -30px; }
    }
    .card {
      background: var(--surf); border: 1px solid var(--border); border-radius: var(--radius);
      padding: 24px 16px; text-align: center; box-shadow: var(--shadow);
      transition: transform 0.2s, border-color 0.2s;
    }
    .card:hover { transform: translateY(-2px); border-color: var(--border-glow); }
    .card .num { font-family: var(--font-title); font-size: 2.4em; font-weight: 800; line-height: 1.1; }
    .card .lbl { color: var(--text-muted); font-size: 0.85em; margin-top: 6px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .red { color: var(--red); }
    .green { color: var(--green); }
    
    .scenario {
      background: var(--surf); border: 1px solid var(--border); border-radius: var(--radius);
      margin-bottom: 24px; box-shadow: var(--shadow); overflow: hidden;
    }
    .sc-hdr {
      padding: 18px 24px; border-bottom: 1px solid var(--border); background: var(--surf-alt);
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    }
    .sc-hdr h2 { font-family: var(--font-title); font-size: 1.2em; font-weight: 700; color: var(--text); }
    .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.78em; font-weight: 700; }
    .sev-CRITICAL { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid var(--red); }
    .sev-HIGH { background: rgba(244, 63, 94, 0.15); color: var(--red); border: 1px solid var(--red); }
    .sev-MEDIUM { background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid var(--yellow); }
    .sev-LOW { background: rgba(99, 102, 241, 0.15); color: var(--blue); border: 1px solid var(--blue); }
    
    .sc-body { display: grid; grid-template-columns: 1fr 1fr 1fr; }
    @media (max-width: 768px) {
      .sc-body { grid-template-columns: 1fr; }
    }
    .sc-col { padding: 20px; border-right: 1px solid var(--border); }
    @media (max-width: 768px) {
      .sc-col { border-right: none; border-bottom: 1px solid var(--border); }
      .sc-col:last-child { border-bottom: none; }
    }
    .sc-col:last-child { border-right: none; }
    .col-label { font-size: 0.75em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 12px; }
    .lbl-attack { color: var(--text-muted); }
    .lbl-vuln { color: var(--red); }
    .lbl-hard { color: var(--green); }
    
    .attack-code {
      display: block; background: var(--surf-alt); border: 1px solid var(--border);
      border-radius: 6px; padding: 12px; font-family: 'Fira Code', Consolas, monospace;
      font-size: 0.85em; color: var(--text); white-space: pre-wrap; word-break: break-all;
    }
    .result-status { font-family: var(--font-title); font-weight: 800; font-size: 1.1em; margin-bottom: 8px; white-space: nowrap; }
    .status-vuln { color: var(--red); }
    .status-secure { color: var(--green); }
    .http-code {
      background: var(--surf-alt); padding: 3px 8px; border-radius: 4px;
      font-family: 'Fira Code', monospace; font-size: 0.8em; margin-left: 8px; color: var(--text-muted);
      border: 1px solid var(--border);
    }
    .result-reason { font-size: 0.9em; color: var(--text-muted); line-height: 1.65; }
    
    .sc-footer {
      padding: 16px 20px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
      border-top: 1px solid var(--border); background: var(--surf-alt);
    }
    .cve-badge {
      background: var(--surf); border: 1px solid var(--border); border-radius: 6px;
      padding: 4px 10px; font-size: 0.8em; font-family: 'Fira Code', monospace; color: var(--blue);
      text-decoration: none; transition: all 0.2s;
    }
    .cve-badge:hover { border-color: var(--blue); background: var(--accent-dim); }
    .owasp-link { font-size: 0.82em; color: var(--text-muted); text-decoration: none; margin-left: auto; font-weight: 500; }
    .owasp-link:hover { color: var(--blue); }
    
    .footer {
      text-align: center; padding: 40px 20px; color: var(--text-muted); font-size: 0.85em;
      border-top: 1px solid var(--border); margin-top: 40px; font-weight: 500;
    }

    """

    scenarios_html = ""
    for row in rows:
        cve       = _CVE_DB_M.get(row.get("cve_key", ""), {})
        sev       = cve.get("severity", row.get("severity", ""))
        sev_badge = f'<span class="badge sev-{sev}">{sev}</span>' if sev else ""
        v_vuln    = row.get("v_vulnerable", True)
        h_vuln    = row.get("h_vulnerable", False)
        v_text    = "VULNERABLE" if v_vuln else "SECURE"
        h_text    = "SECURE" if not h_vuln else "VULNERABLE"
        v_cls     = "status-vuln" if v_vuln else "status-secure"
        h_cls     = "status-secure" if not h_vuln else "status-vuln"
        v_st      = row.get("v_status", "—")
        h_st      = row.get("h_status", "—")
        cve_badges = "".join(
            f'<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank">{_esc(c)}</a>'
            for c in cve.get("cves", []))
        owasp_link = (f'<a class="owasp-link" href="{cve["owasp_ref"]}" target="_blank">OWASP Reference &rarr;</a>'
                      if cve.get("owasp_ref") else "")
        sc_footer = (f'<div class="sc-footer">{cve_badges}{owasp_link}</div>'
                     if cve_badges or owasp_link else "")
        scenarios_html += (
            f'<div class="scenario">'
            f'<div class="sc-hdr"><h2>{_esc(row.get("name",""))}</h2>'
            f'<div style="display:flex;gap:8px">{sev_badge}</div></div>'
            f'<div class="sc-body">'
            f'<div class="sc-col"><div class="col-label lbl-attack">Attack Payload</div>'
            f'<code class="attack-code">{_esc(row.get("attack_payload",""))}</code></div>'
            f'<div class="sc-col"><div class="col-label lbl-vuln">Vulnerable API'
            f'<span class="http-code">HTTP {v_st}</span></div>'
            f'<div class="result-status {v_cls}">{v_text}</div>'
            f'<div class="result-reason">{_esc(row.get("vuln_reason",""))}</div></div>'
            f'<div class="sc-col"><div class="col-label lbl-hard">Hardened API'
            f'<span class="http-code">HTTP {h_st}</span></div>'
            f'<div class="result-status {h_cls}">{h_text}</div>'
            f'<div class="result-reason">{_esc(row.get("hard_reason",""))}</div></div>'
            f'</div>{sc_footer}</div>'
        )

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<title>Comparison Report</title>'
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">'
        f'<style>{_CSS}</style></head><body>'
        '<button class="theme-float-btn" id="theme-float-btn" onclick="toggleReportTheme()">☀️ Light</button>'
        '<div class="header"><h1>Vulnerability Comparison Report</h1>'
        f'<p>Vulnerable: {_esc(vuln_url)} &nbsp;|&nbsp; Hardened: {_esc(hard_url)}'
        f' &nbsp;|&nbsp; {_esc(ts_label)}</p></div>'
        '<div class="container">'
        '<div class="cards">'
        f'<div class="card"><div class="num red">{vuln_score}%</div><div class="lbl">Vulnerable API Score</div></div>'
        f'<div class="card"><div class="num" style="color:{imp_color}">{imp_sign}{improvement}pp</div>'
        '<div class="lbl">Security Improvement</div></div>'
        f'<div class="card"><div class="num green">{hard_score}%</div><div class="lbl">Hardened API Score</div></div>'
        f'</div>{scenarios_html}</div>'
        '<div class="footer">CY384 API Security Project &nbsp;|&nbsp; University of Mines and Technology, Ghana'
        ' &nbsp;|&nbsp; OWASP API Security Top 10:2023</div>'
        '<script>'
        'function toggleReportTheme() {'
        '  var current = document.documentElement.getAttribute("data-theme") || "dark";'
        '  var next = current === "dark" ? "light" : "dark";'
        '  document.documentElement.setAttribute("data-theme", next);'
        '  localStorage.setItem("mazapiTheme", next);'
        '  var btn = document.getElementById("theme-float-btn");'
        '  if (btn) btn.textContent = next === "light" ? "🌙 Dark" : "☀️ Light";'
        '}'
        '(function() {'
        '  var theme = localStorage.getItem("mazapiTheme") || "dark";'
        '  document.documentElement.setAttribute("data-theme", theme);'
        '  var btn = document.getElementById("theme-float-btn");'
        '  if (btn) btn.textContent = theme === "light" ? "🌙 Dark" : "☀️ Light";'
        '})();'
        '</script>'
        '</body></html>'
    )


@app.post("/monitor/run-comparison")
async def run_comparison(req: CompareRequest):
    V = req.vulnerable_url.rstrip("/")
    H = req.hardened_url.rstrip("/")
    ts_label = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ts_file  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    _STEPS = [
        ("bola",  "API1:2023 — BOLA",                  "API1:2023 - Broken Object Level Authorization"),
        ("jwt",   "API2:2023 — Broken Authentication",  "API2:2023 - Broken Authentication"),
        ("mass",  "API3:2023 — Mass Assignment",        "API3:2023 - Broken Object Property Level Authorization"),
        ("rate",  "API4:2023 — Rate Limiting",          "API4:2023 - Unrestricted Resource Consumption"),
        ("func",  "API5:2023 — Function Level Auth",    "API5:2023 - Broken Function Level Authorization"),
        ("debug", "API8:2023 — Debug Endpoint",         "API8:2023 - Security Misconfiguration"),
        ("cors",  "API8:2023 — CORS",                   "API8:2023 - Security Misconfiguration"),
    ]
    _FN_MAP = {
        "bola": _cmp_bola, "jwt":  _cmp_jwt,  "mass": _cmp_mass,
        "rate": _cmp_rate, "func": _cmp_func, "debug": _cmp_debug, "cors": _cmp_cors,
    }
    _NEEDS_TOKEN = {"bola", "mass", "func"}

    rows = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        v_token, _ = await _cmp_login(client, V)
        h_token, _ = await _cmp_login(client, H)
        await asyncio.sleep(0.4)

        for sid, name, cve_key in _STEPS:
            detail = _CMP_DETAIL.get(sid, {})
            cve    = _CVE_DB_M.get(cve_key, {})
            fn     = _FN_MAP[sid]
            if sid in _NEEDS_TOKEN:
                vr = await fn(client, V, v_token)
                await asyncio.sleep(0.35)
                hr = await fn(client, H, h_token)
            else:
                vr = await fn(client, V)
                await asyncio.sleep(0.35)
                hr = await fn(client, H)
            await asyncio.sleep(0.25)

            rows.append({
                "id":             sid,
                "name":           name,
                "cve_key":        cve_key,
                "severity":       cve.get("severity", ""),
                "attack_payload": detail.get("attack_payload", ""),
                "vuln_reason":    detail.get("vuln_reason", ""),
                "hard_reason":    detail.get("hard_reason", ""),
                "v_status":       vr.get("status", "—"),
                "v_pass":         vr.get("pass", False),
                "v_vulnerable":   vr.get("vulnerable", True),
                "h_status":       hr.get("status", "—"),
                "h_pass":         hr.get("pass", True),
                "h_vulnerable":   hr.get("vulnerable", False),
            })

    total      = len(rows)
    v_pass_cnt = sum(1 for r in rows if not r.get("v_vulnerable", True))
    h_pass_cnt = sum(1 for r in rows if not r.get("h_vulnerable", False))
    vuln_score = round(v_pass_cnt / total * 100) if total else 0
    hard_score = round(h_pass_cnt / total * 100) if total else 0
    improvement = hard_score - vuln_score

    os.makedirs(_REPORTS_DIR, exist_ok=True)
    json_name = f"comparison_{ts_file}.json"
    html_name = f"comparison_{ts_file}.html"

    with open(os.path.join(_REPORTS_DIR, json_name), "w") as f:
        _json.dump({
            "vulnerable_url": V,   "hardened_url":    H,
            "timestamp":      ts_label,
            "vuln_score":     vuln_score, "hard_score": hard_score,
            "improvement":    improvement, "total_scenarios": total,
            "scenarios":      rows,
        }, f, indent=2)

    with open(os.path.join(_REPORTS_DIR, html_name), "w") as f:
        f.write(_build_comparison_html(rows, V, H, vuln_score, hard_score, ts_label))

    return {
        "json_file":       json_name,
        "html_file":       html_name,
        "vuln_score":      vuln_score,
        "hard_score":      hard_score,
        "improvement":     improvement,
        "total_scenarios": total,
        "timestamp":       ts_label,
    }


_SCAN_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MazAPI Scanner</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}
nav{background:#161b22;border-bottom:1px solid #30363d;padding:0 24px;display:flex;align-items:center;gap:16px;height:54px}
nav .logo{color:#58a6ff;font-weight:700;font-size:1.1em}
nav a{color:#8b949e;font-size:.85em;text-decoration:none}
nav a:hover{color:#58a6ff}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px}
h1{color:#58a6ff;font-size:1.5em;margin-bottom:6px}
.sub{color:#8b949e;font-size:.87em;margin-bottom:28px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;margin-bottom:20px}
.card h2{font-size:1em;color:#e6edf3;margin-bottom:16px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.field{margin-bottom:14px}
.field label{display:block;font-size:.8em;color:#8b949e;margin-bottom:5px}
.field input,.field textarea{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:8px 10px;font-size:.87em}
.field input:focus,.field textarea:focus{outline:none;border-color:#58a6ff}
.hint{font-size:.77em;color:#8b949e;margin-top:4px}
.btn{padding:10px 24px;border:none;border-radius:6px;cursor:pointer;font-size:.9em;font-weight:600}
.btn-primary{background:#238636;color:#fff}.btn-primary:hover{background:#2ea043}
.btn-primary:disabled{opacity:.5;cursor:not-allowed}
.presets{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
.preset{background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:.82em}
.preset:hover{border-color:#58a6ff;color:#58a6ff}
#status-bar{display:none;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px;margin-bottom:20px;font-size:.87em}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
#results{display:none}
.score-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.scard{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;text-align:center}
.scard .num{font-size:2em;font-weight:700}.scard .lbl{color:#8b949e;font-size:.82em;margin-top:4px}
.red{color:#f85149}.green{color:#3fb950}.blue{color:#58a6ff}.yellow{color:#e3b341}
.cat-block{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:14px;overflow:hidden}
.cat-hdr{padding:14px 18px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.cat-hdr h3{font-size:.95em;color:#e6edf3}
.badge{padding:3px 10px;border-radius:12px;font-size:.78em;font-weight:700}
.bv{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.bs{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid #3fb950}
.sev-CRITICAL{background:rgba(188,30,30,.2);color:#ff6b6b;border:1px solid #ff6b6b}
.sev-HIGH{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.sev-MEDIUM{background:rgba(227,179,65,.15);color:#e3b341;border:1px solid #e3b341}
table{width:100%;border-collapse:collapse}
th{background:#0d1117;padding:10px 14px;text-align:left;font-size:.77em;color:#8b949e;text-transform:uppercase}
td{padding:10px 14px;border-top:1px solid #21262d;font-size:.84em;word-break:break-word}
code{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:.85em}
.vY{color:#f85149;font-weight:700;white-space:nowrap}.vN{color:#3fb950;white-space:nowrap}
.cve-panel{padding:16px 18px;border-top:1px solid #21262d;background:#0d1117}
.cve-panel h4{color:#8b949e;font-size:.77em;text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px}
.cve-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center}
.cve-badge{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:3px 9px;font-size:.78em;font-family:monospace;color:#58a6ff;text-decoration:none}
.cve-badge:hover{border-color:#58a6ff}
.owasp-link{font-size:.8em;color:#8b949e;text-decoration:none;margin-left:auto}
.owasp-link:hover{color:#58a6ff}
.vuln-desc{font-size:.84em;color:#8b949e;margin-bottom:10px;line-height:1.5}
.fixes ol{padding-left:16px}
.fixes li{font-size:.83em;color:#c9d1d9;line-height:1.6;padding:2px 0}
.export-bar{display:flex;align-items:center;gap:10px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;margin-top:14px;flex-wrap:wrap}
.btn-save{padding:7px 14px;border:1px solid;border-radius:6px;font-size:.82em;font-weight:600;cursor:pointer;transition:background .15s}
.btn-save-brief{background:rgba(63,185,80,.12);color:#3fb950;border-color:rgba(63,185,80,.4)}
.btn-save-brief:hover{background:rgba(63,185,80,.25)}
.btn-save-detail{background:rgba(88,166,255,.12);color:#58a6ff;border-color:rgba(88,166,255,.4)}
.btn-save-detail:hover{background:rgba(88,166,255,.25)}
</style>
</head>
<body>
<nav>
  <span class="logo">MazAPI Scanner</span>
  <a href="/dashboard">Monitor</a>
  <a href="http://localhost:8000/ui" target="_blank">ShopApp Demo</a>
  <a href="http://localhost:8000/docs" target="_blank">API Docs</a>
</nav>
<div class="wrap">
  <h1>MazAPI Scanner</h1>
  <p class="sub">Multi-standard API vulnerability scanner — OWASP API Top 10, MITRE ATT&amp;CK, CWE. No source code needed.</p>

  <!-- Presets -->
  <div class="presets">
    <span style="font-size:.82em;color:#8b949e;align-self:center">Quick presets:</span>
    <button class="preset" onclick="loadPreset('vulnerable')">Vulnerable API (lab)</button>
    <button class="preset" onclick="loadPreset('hardened')">Hardened API (lab)</button>
    <button class="preset" onclick="loadPreset('monitoring')">Monitoring proxy (lab)</button>
  </div>
  <p style="font-size:.79em;color:#8b949e;margin-bottom:18px">
    The scan runs server-side from inside the monitoring container. To scan lab services use the Docker container names above (e.g. <code>http://vulnerable-api:8000</code>). External APIs (e.g. <code>https://api.example.com</code>) are reachable directly.
  </p>

  <div class="card">
    <h2>Scan Configuration</h2>
    <div class="field">
      <label>Target Base URL *</label>
      <input id="f-target" type="url" placeholder="https://api.example.com or http://localhost:8000">
    </div>
    <div class="row">
      <div class="field">
        <label>Auth Endpoint</label>
        <input id="f-auth-ep" type="text" value="/auth/login">
        <span class="hint">POST endpoint that returns a token</span>
      </div>
      <div class="field">
        <label>Token Field</label>
        <input id="f-token-field" type="text" value="access_token">
        <span class="hint">JSON key in the login response</span>
      </div>
    </div>
    <div class="field">
      <label>Auth Body (JSON)</label>
      <textarea id="f-auth-body" rows="2" placeholder='{"username": "alice", "password": "alice123"}'></textarea>
      <span class="hint">Leave blank to skip authenticated probes (BOLA, mass assignment, rate-limit)</span>
    </div>
    <div class="row">
      <div class="field">
        <label>BOLA Path Template</label>
        <input id="f-bola" type="text" value="/users/{id}">
        <span class="hint">Use {id} as the object ID placeholder</span>
      </div>
      <div class="field">
        <label>Update Path (for mass-assignment)</label>
        <input id="f-update" type="text" value="/users/1">
        <span class="hint">PUT endpoint that updates a user object</span>
      </div>
    </div>
    <div class="field">
      <label>Protected Admin Path (for JWT forge test)</label>
      <input id="f-protected" type="text" value="/admin/users">
    </div>
    <button class="btn btn-primary" id="scan-btn" onclick="runScan()">Run Scan</button>
  </div>

  <div id="status-bar">
    <span class="spinner"></span>
    <span id="status-msg">Scanning — this may take 15–30 seconds...</span>
  </div>

  <div id="results"></div>
</div>

<script>
const CVE_DB = {
  "API1:2023 - Broken Object Level Authorization": {
    cves: ["CVE-2019-14234","CVE-2020-7927","CVE-2021-21302"],
    owasp_ref: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    severity: "HIGH",
    description: "The API retrieves data based on a client-supplied identifier without verifying that the requesting user is authorised to access that specific object.",
    fixes: [
      "Verify ownership on every request: check current_user.id == resource.owner_id before returning data.",
      "Use unpredictable UUIDs instead of sequential integer IDs to reduce guessability.",
      "Apply an authorization middleware/dependency that enforces ownership rather than repeating checks per endpoint.",
      "Write integration tests that log in as User A and attempt to access User B's resources — expect 403."
    ]
  },
  "API2:2023 - Broken Authentication": {
    cves: ["CVE-2018-1000531","CVE-2022-21449","CVE-2021-27958"],
    owasp_ref: "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    severity: "CRITICAL",
    description: "Authentication mechanisms are implemented incorrectly, allowing attackers to forge tokens, brute-force credentials, or bypass authentication entirely.",
    fixes: [
      "Load JWT secrets from environment variables — never hard-code them in source code.",
      "Always set an expiry claim (exp) in JWTs; 15–30 minutes is typical for access tokens.",
      "Rate-limit login endpoints to 5 attempts per minute per IP and implement account lockout.",
      "Use a well-audited library and verify the alg header to prevent algorithm confusion attacks."
    ]
  },
  "API3:2023 - Broken Object Property Level Authorization": {
    cves: ["CVE-2012-2676","CVE-2022-32532","CVE-2021-41079"],
    owasp_ref: "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    severity: "HIGH",
    description: "The API accepts more fields than intended, allowing clients to modify properties they should never control — such as role or balance.",
    fixes: [
      "Define strict input schemas that explicitly list allowed fields.",
      "Never pass user input directly to ORM .update() calls — always use an allowlist.",
      "Treat privilege fields (role, is_admin, balance) as server-controlled.",
      "Return a separate response schema that omits sensitive fields like password hash."
    ]
  },
  "API4:2023 - Unrestricted Resource Consumption": {
    cves: ["CVE-2019-11324","CVE-2020-26258","CVE-2021-25742"],
    owasp_ref: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    severity: "MEDIUM",
    description: "The API does not limit the rate or volume of requests, enabling brute-force attacks, credential stuffing, and denial-of-service.",
    fixes: [
      "Apply per-IP rate limiting on authentication endpoints.",
      "Apply per-user rate limiting on resource endpoints to prevent data scraping.",
      "Set maximum request body sizes and reject oversized payloads early.",
      "Implement exponential backoff or temporary IP bans after repeated failures."
    ]
  },
  "API5:2023 - Broken Function Level Authorization": {
    cves: ["CVE-2021-41773","CVE-2022-22947","CVE-2020-14882"],
    owasp_ref: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    severity: "HIGH",
    description: "Administrative or privileged endpoints are accessible to regular users because the API checks authentication but not the user's role or permissions.",
    fixes: [
      "Default to deny — every endpoint must explicitly declare the required role/permission.",
      "Use a shared authorization dependency/guard that verifies role on every admin route.",
      "Keep admin functionality on a separate service or subdomain with network-level controls.",
      "Audit all routes regularly to ensure no admin path is reachable without explicit role validation."
    ]
  },
  "API8:2023 - Security Misconfiguration": {
    cves: ["CVE-2021-44228","CVE-2020-1938","CVE-2019-0232"],
    owasp_ref: "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    severity: "MEDIUM",
    description: "The API exposes sensitive information through debug endpoints, verbose error messages, permissive CORS, or publicly accessible API documentation.",
    fixes: [
      "Remove all debug/development endpoints before deploying to production.",
      "Configure CORS to allow only known, trusted origins; never use wildcard (*) with credentialed requests.",
      "Return generic error messages — never reveal whether a username exists or a password is wrong.",
      "Disable interactive API documentation (Swagger UI, ReDoc) in production environments."
    ]
  }
};

let _lastScan = null;

// Scan runs server-side inside the monitoring Docker container.
// Internal services must use Docker container names, not localhost.
const PRESETS = {
  vulnerable: { target: 'http://vulnerable-api:8000', auth: '{"username":"alice","password":"alice123"}' },
  hardened:   { target: 'http://hardened-api:8001',   auth: '{"username":"alice","password":"alice123"}' },
  monitoring: { target: 'http://monitoring:9000',      auth: '{"username":"alice","password":"alice123"}' },
};

function loadPreset(name) {
  const p = PRESETS[name];
  document.getElementById('f-target').value = p.target;
  document.getElementById('f-auth-body').value = p.auth;
}

async function runScan() {
  const target = document.getElementById('f-target').value.trim();
  if (!target) return alert('Enter a target URL');

  let authBody = null;
  const raw = document.getElementById('f-auth-body').value.trim();
  if (raw) {
    try { authBody = JSON.parse(raw); } catch(e) { return alert('Auth body must be valid JSON'); }
  }

  document.getElementById('scan-btn').disabled = true;
  document.getElementById('status-bar').style.display = 'block';
  document.getElementById('results').style.display = 'none';

  const payload = {
    target,
    auth_endpoint: document.getElementById('f-auth-ep').value,
    auth_body: authBody,
    token_field: document.getElementById('f-token-field').value,
    bola_path: document.getElementById('f-bola').value,
    update_path: document.getElementById('f-update').value,
    protected_path: document.getElementById('f-protected').value,
  };

  try {
    const r = await fetch('/monitor/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    if (!r.ok) throw new Error(await r.text());
    const data = await r.json();
    _lastScan = data;
    renderResults(data);
  } catch(e) {
    document.getElementById('status-bar').innerHTML = '<span style="color:#f85149">Error: ' + e.message + '</span>';
  } finally {
    document.getElementById('scan-btn').disabled = false;
  }
}

function renderResults(data) {
  document.getElementById('status-bar').style.display = 'none';
  const el = document.getElementById('results');
  el.style.display = 'block';
  const scoreColor = data.score >= 80 ? 'green' : data.score >= 50 ? 'yellow' : 'red';

  let html = `
    <div class="score-row">
      <div class="scard"><div class="num ${scoreColor}">${data.score}%</div><div class="lbl">Security Score</div></div>
      <div class="scard"><div class="num blue">${data.total_tests}</div><div class="lbl">Tests Run</div></div>
      <div class="scard"><div class="num red">${data.total_vulnerable}</div><div class="lbl">Vulnerable</div></div>
      <div class="scard"><div class="num green">${data.total_tests - data.total_vulnerable}</div><div class="lbl">Passed</div></div>
    </div>
    <p style="color:#8b949e;font-size:.83em;margin-bottom:16px">Target: <code>${data.target}</code> &nbsp;|&nbsp; ${data.timestamp}</p>
  `;

  for (const cat of data.categories) {
    const cve = CVE_DB[cat.category] || null;
    const vuln = cat.vulnerable_count > 0;
    html += `
    <div class="cat-block">
      <div class="cat-hdr">
        <h3>${cat.category}</h3>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${cve ? `<span class="badge sev-${cve.severity}">${cve.severity}</span>` : ''}
          <span class="badge ${vuln ? 'bv' : 'bs'}">${cat.vulnerable_count}/${cat.total} Vulnerable</span>
        </div>
      </div>
      <table>
        <tr><th>Test</th><th>Request</th><th>Expected</th><th>Actual</th><th>Result</th></tr>
        ${cat.tests.map(t => `
        <tr>
          <td>${t.test}</td>
          <td><code>${t.request}</code></td>
          <td>${t.expected}</td>
          <td>${t.actual}</td>
          <td class="${t.vulnerable ? 'vY' : 'vN'}">${t.vulnerable ? 'VULNERABLE' : 'SECURE'}</td>
        </tr>`).join('')}
      </table>
      ${cve ? `
      <div class="cve-panel">
        <h4>CVE References &amp; Remediation</h4>
        <div class="cve-row">
          ${cve.cves.map(id => `<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank">${id}</a>`).join('')}
          <a class="owasp-link" href="${cve.owasp_ref}" target="_blank">OWASP Reference &rarr;</a>
        </div>
        <p class="vuln-desc">${cve.description}</p>
        <div class="fixes"><ol>${cve.fixes.map(f => `<li>${f}</li>`).join('')}</ol></div>
      </div>` : ''}
    </div>`;
  }

  el.innerHTML = html + `
  <div class="export-bar">
    <span style="font-size:.82em;color:#8b949e;white-space:nowrap">Save as report:</span>
    <button class="btn-save btn-save-brief" onclick="saveReport('brief')">Brief Report</button>
    <button class="btn-save btn-save-detail" onclick="saveReport('detailed')">Detailed Report</button>
    <span id="save-msg" style="font-size:.82em;margin-left:4px"></span>
  </div>`;
}

async function saveReport(detail) {
  if (!_lastScan) return;
  const msg = document.getElementById('save-msg');
  msg.style.color = '#8b949e';
  msg.textContent = 'Saving…';
  try {
    const r = await fetch('/monitor/save-report', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        target: _lastScan.target,
        timestamp: _lastScan.timestamp,
        score: _lastScan.score,
        total_tests: _lastScan.total_tests,
        total_vulnerable: _lastScan.total_vulnerable,
        categories: _lastScan.categories,
        detail,
      })
    });
    if (!r.ok) throw new Error(await r.text());
    const res = await r.json();
    msg.innerHTML = `Saved! <a href="/monitor/reports/${res.html_file}" target="_blank" style="color:#58a6ff;font-weight:600">View Report &rarr;</a>`;
  } catch(e) {
    msg.style.color = '#f85149';
    msg.textContent = 'Error: ' + e.message;
  }
}
</script>
</body>
</html>"""


@app.post("/monitor/reset-logs")
async def reset_logs():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM traffic")
        await db.commit()
    return {"reset": True}


@app.get("/monitor/health")
async def health():
    result: dict = {"monitoring": {"status": "up", "url": "localhost:9000"}}
    checks = [("vulnerable-api", "http://vulnerable-api:8000"),
              ("hardened-api",   "http://hardened-api:8001")]
    async with httpx.AsyncClient(timeout=4) as client:
        for name, base in checks:
            try:
                r = await client.get(base + "/health")
                result[name] = {
                    "status":      "up" if r.status_code < 500 else "degraded",
                    "status_code": r.status_code,
                    "url":         base,
                }
            except Exception as exc:
                result[name] = {"status": "down", "url": base, "error": str(exc)[:80]}
    return result


# ── Global configuration state ──────────────────────────────────────────
_INLINE_BLOCKING_ENABLED = False

@app.post("/api/toggle-blocking")
async def toggle_blocking(req: Request):
    global _INLINE_BLOCKING_ENABLED
    data = await req.json()
    _INLINE_BLOCKING_ENABLED = bool(data.get("enabled", not _INLINE_BLOCKING_ENABLED))
    return {"inline_blocking_enabled": _INLINE_BLOCKING_ENABLED}

@app.get("/api/export-openapi")
async def export_openapi():
    """Synthesize an OpenAPI 3.0 specification from captured traffic logs."""
    paths = {}
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT method, path, status_code FROM traffic LIMIT 2000") as cursor:
            rows = await cursor.fetchall()
            for method, p, status in rows:
                p_str = p or "/"
                m_str = (method or "GET").lower()
                if p_str not in paths:
                    paths[p_str] = {}
                if m_str not in paths[p_str]:
                    paths[p_str][m_str] = {
                        "summary": f"Discovered endpoint {method} {p_str}",
                        "responses": {
                            str(status): {"description": f"Observed status code {status}"}
                        }
                    }
                else:
                    paths[p_str][m_str]["responses"][str(status)] = {"description": f"Observed status code {status}"}

    openapi_spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "MazAPI Synthesized OpenAPI Specification",
            "version": "1.0.0",
            "description": "Automatically generated API contract from captured live traffic logs."
        },
        "paths": paths
    }
    return JSONResponse(openapi_spec)

@app.get("/api/export-bom")
async def export_bom():
    """Export unified AI-BOM, API-BOM, and S-BOM compliance report."""
    endpoints = []
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT DISTINCT method, path, has_auth FROM traffic") as cursor:
            rows = await cursor.fetchall()
            for m, p, auth in rows:
                endpoints.append({"method": m, "path": p, "authenticated": bool(auth)})

    bom = {
        "bom_version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "framework": "MazAPI Unified Security Ecosystem",
        "api_bom": {
            "total_mapped_endpoints": len(endpoints),
            "endpoints": endpoints
        },
        "ai_bom": {
            "llm_providers": ["OpenAI", "Anthropic", "Google Gemini", "Groq", "Mistral"],
            "agent_frameworks": ["LangChain", "LangGraph", "CrewAI"],
            "mcp_support": "Model Context Protocol (MCP) Auditor Active",
            "status": "Audited via MazAPI VS Code & Testing Engine"
        },
        "s_bom": {
            "compliance_standards": ["OWASP API Top 10:2023", "PCI-DSS 4.0", "GDPR Art. 32", "ISO/IEC 27001"],
            "active_protection": "Transparent Proxy + Dual ML Ensemble (IsolationForest + RandomForest)"
        }
    }
    return JSONResponse(bom)

@app.get("/api/topology")
async def topology_graph():
    """Return node and edge topology map of mapped endpoints and security state."""
    nodes = [
        {"id": "client", "label": "Browser / Mobile Client", "type": "client", "color": "#58a6ff"},
        {"id": "proxy", "label": "MazAPI ML Proxy (:9000)", "type": "proxy", "color": "#3fb950"},
        {"id": "target_vuln", "label": "Vulnerable API Target (:8000)", "type": "target", "color": "#f85149"},
        {"id": "target_hardened", "label": "Hardened API Target (:8001)", "type": "target", "color": "#238636"},
        {"id": "ai_surface", "label": "AI LLM / MCP Gateway", "type": "ai", "color": "#a371f7"},
    ]
    edges = [
        {"from": "client", "to": "proxy", "label": "HTTP/REST Payload"},
        {"from": "proxy", "to": "target_vuln", "label": "Sidecar Route"},
        {"from": "proxy", "to": "target_hardened", "label": "Hardened Route"},
        {"from": "proxy", "to": "ai_surface", "label": "AI-BOM Audit Context"}
    ]
    return JSONResponse({"nodes": nodes, "edges": edges, "inline_blocking": _INLINE_BLOCKING_ENABLED})


# ── transparent proxy (catch-all — AFTER all specific routes) ─────────────────
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(request: Request, path: str):
    x_target   = request.headers.get("x-target", "").lower()
    upstream   = "http://hardened-api:8001" if x_target == "hardened" else UPSTREAM
    url        = f"{upstream}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    # Strip internal routing headers before forwarding
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "x-target")}
    body        = await request.body()
    has_auth    = "authorization" in {k.lower() for k in request.headers}

    # Detect BOLA: compare JWT sub claim with the numeric user ID in the URL path
    bola_suspected = False
    _uid_match = _re.match(r'^/users/(\d+)', f"/{path}")
    if _uid_match and has_auth:
        try:
            _auth_h = request.headers.get("authorization", "")
            if _auth_h.startswith("Bearer "):
                _payload_b64 = _auth_h.split(".")[1]
                _payload_b64 += "=" * (4 - len(_payload_b64) % 4)
                _payload = _json.loads(_b64.b64decode(_payload_b64))
                if str(_payload.get("sub", "")) != _uid_match.group(1):
                    bola_suspected = True
        except Exception:
            pass

    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            up = await client.request(request.method, url, headers=fwd_headers, content=body)
            status, content = up.status_code, up.content
            resp_headers    = dict(up.headers)
        except Exception:
            status, content = 502, b'{"detail":"Upstream unavailable"}'
            resp_headers    = {"content-type": "application/json"}

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    rec = {
        "timestamp":        datetime.utcnow().strftime("%H:%M:%S"),
        "method":           request.method,
        "path":             f"/{path}",
        "status_code":      status,
        "response_time_ms": elapsed_ms,
        "has_auth":         has_auth,
        "bola_suspected":   bola_suspected,
    }
    det = detector.predict(rec)

    # Active Inline Mitigation Mode: auto-block high confidence threats if enabled
    if _INLINE_BLOCKING_ENABLED and det["anomaly"] and det.get("confidence", 0) >= 0.85:
        block_rec = dict(rec)
        block_rec.update({"status_code": 403, "anomaly": 1, "score": det["score"], "reason": f"INLINE_BLOCKED ({det['reason']})"})
        asyncio.create_task(_log(block_rec))
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Blocked by MazAPI Active Inline Threat Mitigation",
                "reason": det["reason"],
                "confidence": det.get("confidence"),
                "model": det.get("model")
            }
        )

    rec.update({"anomaly": det["anomaly"], "score": det["score"], "reason": det["reason"]})
    asyncio.create_task(_log(rec))

    resp_headers.pop("content-encoding", None)
    resp_headers.pop("transfer-encoding", None)
    return Response(content=content, status_code=status, headers=resp_headers)
