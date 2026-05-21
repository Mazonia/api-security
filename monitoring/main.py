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
    if not os.path.exists("/data/model.joblib"):
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
            "SUM(anomaly) as anomalies "
            "FROM traffic GROUP BY minute ORDER BY minute DESC LIMIT ?", (minutes,))
        rows = list(reversed([dict(r) for r in await cur.fetchall()]))
    return rows


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
    # auth: direct token / API key
    direct_token: Optional[str] = None
    api_key_header: Optional[str] = None
    api_key_value: Optional[str] = None
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


async def _async_get(client: httpx.AsyncClient, url: str, headers: dict = None):
    try:
        return await client.get(url, headers=headers or {}, timeout=8)
    except Exception:
        return None


async def _async_post(client: httpx.AsyncClient, url: str, body: dict, headers: dict = None):
    try:
        return await client.post(url, json=body, headers=headers or {}, timeout=8)
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
    _run    = set(req.tests) if req.tests else {"api1","api2","api3","api4","api5","api8"}

    # Build effective auth headers from whichever method was provided
    eff_hdrs: dict = {}
    if req.api_key_header and req.api_key_value:
        eff_hdrs[req.api_key_header] = req.api_key_value
    if token:
        eff_hdrs["Authorization"] = f"Bearer {token}"
        try:
            _pld = _json.loads(_b64.b64decode(token.split(".")[1] + "=="))
            user_id = int(_pld.get("sub", 1))
        except Exception:
            pass

    async with httpx.AsyncClient(follow_redirects=True) as client:

        # ── API8 / API5: sensitive path enumeration ─────────────────────────────
        if "api8" in _run or "api5" in _run:
            for path in _SENSITIVE_PATHS:
                r = await _async_get(client, base + path)
                if r is None:
                    continue
                exposed = r.status_code == 200
                cat = ("API5:2023 - Broken Function Level Authorization"
                       if path in _ADMIN_PATHS else "API8:2023 - Security Misconfiguration")
                results.append({
                    "test": f"Sensitive path accessible: {path}",
                    "request": f"GET {path} (no auth)",
                    "expected": "401, 403, or 404",
                    "actual": str(r.status_code),
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
            _SEC_HDRS = [
                ("x-content-type-options",  "nosniff", "MEDIUM"),
                ("x-frame-options",          None,      "MEDIUM"),
                ("content-security-policy",  None,      "MEDIUM"),
                ("referrer-policy",          None,      "LOW"),
            ]
            if base.startswith("https://"):
                _SEC_HDRS.append(("strict-transport-security", None, "HIGH"))
            for probe_path in ["/health", "/", "/api"]:
                r = await _async_get(client, base + probe_path)
                if r is not None:
                    for hdr_name, expected_val, sev in _SEC_HDRS:
                        actual = r.headers.get(hdr_name, "")
                        present = (actual.lower() == expected_val.lower()
                                   if expected_val else bool(actual))
                        results.append({
                            "test": f"Security header: {hdr_name}",
                            "request": f"GET {probe_path}",
                            "expected": f"{hdr_name}: {expected_val or '(any value)'}",
                            "actual": actual or "(missing)",
                            "severity": sev,
                            "vulnerable": not present,
                            "category": "API8:2023 - Security Misconfiguration",
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

        # ── Login flow: acquire token if not already provided ────────────────────
        if not token and req.auth_body and req.auth_endpoint:
            r = await _async_post(client, base + req.auth_endpoint, req.auth_body)
            if r and r.status_code == 200:
                try:
                    token = r.json().get(req.token_field or "access_token", "")
                except Exception:
                    pass
            if token:
                eff_hdrs["Authorization"] = f"Bearer {token}"
                try:
                    _pld = _json.loads(_b64.b64decode(token.split(".")[1] + "=="))
                    user_id = int(_pld.get("sub", 1))
                except Exception:
                    pass

        # ── API2: JWT weak secret ────────────────────────────────────────────────
        if "api2" in _run:
            try:
                from jose import jwt as jose_jwt
                forged = jose_jwt.encode(
                    {"sub": "1", "username": "alice", "role": "admin"},
                    "secret", algorithm="HS256",
                )
                r = await _async_get(client, base + req.bola_path.replace("{id}", "1"),
                                     headers={"Authorization": f"Bearer {forged}"})
                if r is not None:
                    results.append({
                        "test": "JWT weak secret — forge token with key 'secret'",
                        "request": f"GET {req.bola_path.replace('{id}', '1')} (forged JWT, key='secret')",
                        "expected": "401 or 403 (forged token rejected)",
                        "actual": str(r.status_code),
                        "severity": "CRITICAL",
                        "vulnerable": r.status_code == 200,
                        "category": "API2:2023 - Broken Authentication",
                    })
            except ImportError:
                pass

            # ── API2: JWT algorithm confusion — alg:none bypass ──────────────────
            try:
                _hdr_b64 = _b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
                _pld_b64 = _b64.urlsafe_b64encode(
                    b'{"sub":"1","username":"alice","role":"admin"}'
                ).rstrip(b'=').decode()
                alg_none_tok = f"{_hdr_b64}.{_pld_b64}."
                r_alg = await _async_get(
                    client, base + req.bola_path.replace("{id}", "1"),
                    headers={"Authorization": f"Bearer {alg_none_tok}"},
                )
                if r_alg is not None:
                    results.append({
                        "test": "JWT algorithm confusion — alg:none (unsigned token)",
                        "request": f"GET {req.bola_path.replace('{id}', '1')} (JWT alg=none, no signature)",
                        "expected": "401 — unsigned tokens must be rejected",
                        "actual": str(r_alg.status_code),
                        "severity": "CRITICAL",
                        "vulnerable": r_alg.status_code == 200,
                        "category": "API2:2023 - Broken Authentication",
                    })
            except Exception:
                pass

        # ── API1: BOLA — single probe + ID range ────────────────────────────────
        if "api1" in _run and eff_hdrs.get("Authorization"):
            other_id = 1 if user_id != 1 else 2
            r = await _async_get(client, base + req.bola_path.replace("{id}", str(other_id)),
                                 headers=eff_hdrs)
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
            # Enumerate IDs 1-5 to check how wide the exposure is
            bola_hits = []
            for probe_id in range(1, 6):
                if probe_id == user_id:
                    continue
                r2 = await _async_get(client, base + req.bola_path.replace("{id}", str(probe_id)),
                                      headers=eff_hdrs)
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
        if "api5" in _run and eff_hdrs.get("Authorization"):
            r = await _async_get(client, base + req.protected_path, headers=eff_hdrs)
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
        if "api3" in _run and eff_hdrs.get("Authorization"):
            try:
                r = await client.put(
                    base + req.update_path,
                    json={"role": "admin", "balance": 999999},
                    headers={**eff_hdrs, "Content-Type": "application/json"},
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

    grouped = list(buckets.values())
    total_v = sum(g["vulnerable_count"] for g in grouped)
    total_t = sum(g["total"] for g in grouped)
    score   = round((1 - total_v / total_t) * 100) if total_t else 100

    return JSONResponse({
        "target":          req.target,
        "timestamp":       datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "score":           score,
        "total_tests":     total_t,
        "total_vulnerable": total_v,
        "categories":      grouped,
    })


@app.get("/monitor/scan/discover")
async def discover_schema(target: str):
    """Try common OpenAPI/Swagger paths on a target and return found endpoints."""
    base = target.rstrip("/")
    _SCHEMA_PATHS = [
        "/openapi.json", "/swagger.json", "/api-docs",
        "/v1/openapi.json", "/api/openapi.json", "/swagger/v1/swagger.json",
    ]
    async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
        for path in _SCHEMA_PATHS:
            try:
                r = await client.get(base + path)
                if r.status_code == 200:
                    try:
                        schema = r.json()
                        paths  = list(schema.get("paths", {}).keys())
                        info   = schema.get("info", {})
                        return {
                            "found":        True,
                            "schema_path":  path,
                            "api_title":    info.get("title", ""),
                            "api_version":  info.get("version", ""),
                            "paths":        paths[:60],
                            "total_paths":  len(paths),
                        }
                    except Exception:
                        return {"found": True, "schema_path": path, "paths": [], "total_paths": 0}
            except Exception:
                continue
    return {"found": False}


_SCAN_UI_HTML_V2 = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Scanner - CY384</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}
nav{background:#161b22;border-bottom:1px solid #30363d;padding:0 24px;display:flex;align-items:center;gap:16px;height:54px}
nav .logo{color:#58a6ff;font-weight:700;font-size:1.1em}
nav a{color:#8b949e;font-size:.85em;text-decoration:none}
nav a:hover{color:#58a6ff}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{color:#58a6ff;font-size:1.5em;margin-bottom:6px}
.sub{color:#8b949e;font-size:.87em;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:22px;margin-bottom:18px}
.card h2{font-size:.82em;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#8b949e;margin-bottom:16px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.field{margin-bottom:14px}
.field label{display:block;font-size:.8em;color:#8b949e;margin-bottom:5px}
.field input,.field textarea{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:8px 10px;font-size:.87em;font-family:inherit}
.field input:focus,.field textarea:focus{outline:none;border-color:#58a6ff}
.hint{font-size:.77em;color:#8b949e;margin-top:4px}
.auth-tabs{display:flex;gap:2px;border-bottom:1px solid #30363d;margin-bottom:14px}
.auth-tab{background:none;border:none;border-bottom:2px solid transparent;color:#8b949e;cursor:pointer;padding:7px 14px;font-size:.84em;margin-bottom:-1px;font-family:inherit;transition:color .15s,border-color .15s}
.auth-tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.auth-tab:hover{color:#c9d1d9}
.disc-row{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.btn-disc{background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.4);color:#58a6ff;border-radius:6px;padding:6px 14px;font-size:.82em;cursor:pointer;font-family:inherit}
.btn-disc:hover{background:rgba(88,166,255,.2)}
.test-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.test-lbl{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;background:#0d1117;border:1px solid #21262d;border-radius:6px;cursor:pointer;user-select:none}
.test-lbl:hover{border-color:#30363d}
.test-lbl input[type=checkbox]{margin-top:3px;flex-shrink:0;accent-color:#58a6ff}
.cat-name{display:block;font-size:.87em;font-weight:600;color:#e6edf3}
.cat-desc{display:block;font-size:.77em;color:#8b949e;margin-top:2px;line-height:1.4}
.link-btn{background:none;border:none;color:#58a6ff;cursor:pointer;font-size:.81em;text-decoration:underline;padding:0;font-family:inherit}
.btn{padding:10px 26px;border:none;border-radius:6px;cursor:pointer;font-size:.92em;font-weight:700;font-family:inherit}
.btn-primary{background:#238636;color:#fff}.btn-primary:hover{background:#2ea043}
.btn-primary:disabled{opacity:.5;cursor:not-allowed}
#status-bar{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:13px 18px;margin:16px 0;font-size:.87em}
.spinner{display:inline-block;width:13px;height:13px;border:2px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.score-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.scard{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;text-align:center}
.scard .num{font-size:2em;font-weight:700}.scard .lbl{color:#8b949e;font-size:.81em;margin-top:4px}
.red{color:#f85149}.green{color:#3fb950}.blue{color:#58a6ff}.yellow{color:#e3b341}
.cat-block{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:12px;overflow:hidden}
.cat-hdr{padding:13px 18px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.cat-hdr h3{font-size:.95em;color:#e6edf3}
.badge{padding:3px 10px;border-radius:12px;font-size:.78em;font-weight:700}
.bv{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.bs{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid #3fb950}
.sev-CRITICAL{background:rgba(188,30,30,.2);color:#ff6b6b;border:1px solid #ff6b6b}
.sev-HIGH{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.sev-MEDIUM{background:rgba(227,179,65,.15);color:#e3b341;border:1px solid #e3b341}
.sev-LOW{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid #58a6ff}
table{width:100%;border-collapse:collapse}
th{background:#0d1117;padding:9px 14px;text-align:left;font-size:.75em;color:#8b949e;text-transform:uppercase}
td{padding:9px 14px;border-top:1px solid #21262d;font-size:.84em;word-break:break-word}
code{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:.84em}
.vY{color:#f85149;font-weight:700}.vN{color:#3fb950}
.cve-panel{padding:14px 18px;border-top:1px solid #21262d;background:#0d1117}
.cve-panel h4{color:#8b949e;font-size:.76em;text-transform:uppercase;letter-spacing:.07em;margin-bottom:9px}
.cve-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:9px;align-items:center}
.cve-badge{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:3px 9px;font-size:.77em;font-family:monospace;color:#58a6ff;text-decoration:none}
.cve-badge:hover{border-color:#58a6ff}
.owasp-link{font-size:.79em;color:#8b949e;text-decoration:none;margin-left:auto}
.owasp-link:hover{color:#58a6ff}
.vuln-desc{font-size:.83em;color:#8b949e;margin-bottom:9px;line-height:1.5}
.fixes ol{padding-left:16px}
.fixes li{font-size:.82em;color:#c9d1d9;line-height:1.6;padding:2px 0}
.export-bar{display:flex;align-items:center;gap:10px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:11px 15px;margin-top:12px;flex-wrap:wrap}
.btn-save{padding:6px 13px;border:1px solid;border-radius:6px;font-size:.81em;font-weight:600;cursor:pointer;font-family:inherit}
.btn-save-brief{background:rgba(63,185,80,.1);color:#3fb950;border-color:rgba(63,185,80,.4)}
.btn-save-brief:hover{background:rgba(63,185,80,.22)}
.btn-save-detail{background:rgba(88,166,255,.1);color:#58a6ff;border-color:rgba(88,166,255,.4)}
.btn-save-detail:hover{background:rgba(88,166,255,.22)}
.presets{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.preset{background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:.82em;font-family:inherit}
.preset:hover{border-color:#58a6ff;color:#58a6ff}
</style>
</head>
<body>
<nav>
  <span class="logo">CY384 - External API Scanner</span>
  <a href="/dashboard">Monitor Dashboard</a>
  <a href="http://localhost:8000/ui" target="_blank">Shop App</a>
  <a href="http://localhost:8000/docs" target="_blank">API Docs</a>
</nav>
<div class="wrap">
  <h1>Generic OWASP API Security Scanner</h1>
  <p class="sub">Scan any REST API for OWASP API Top 10:2023 vulnerabilities. No source code required.</p>

  <div class="presets">
    <span style="font-size:.82em;color:#8b949e">Quick presets:</span>
    <button class="preset" onclick="loadPreset('vulnerable')">Vulnerable API (lab)</button>
    <button class="preset" onclick="loadPreset('hardened')">Hardened API (lab)</button>
    <button class="preset" onclick="loadPreset('external')">External API</button>
  </div>
  <p class="hint" style="margin-bottom:20px">Scans run server-side inside the monitoring container. Lab services: use Docker names like <code>http://vulnerable-api:8000</code>. External APIs: enter the full URL directly.</p>

  <div class="card">
    <h2>Target</h2>
    <div class="field">
      <label>Base URL *</label>
      <input id="f-target" type="text" placeholder="https://api.example.com  or  http://vulnerable-api:8000">
    </div>
    <h2 style="margin-top:18px;margin-bottom:12px">Authentication</h2>
    <div class="auth-tabs">
      <button class="auth-tab active" onclick="setAuth(this,'login')">Login Flow</button>
      <button class="auth-tab" onclick="setAuth(this,'bearer')">Bearer Token</button>
      <button class="auth-tab" onclick="setAuth(this,'apikey')">API Key</button>
      <button class="auth-tab" onclick="setAuth(this,'none')">None</button>
    </div>
    <div id="auth-login">
      <div class="row">
        <div class="field"><label>Auth Endpoint</label><input id="f-auth-ep" value="/auth/login"><span class="hint">POST endpoint that returns a token</span></div>
        <div class="field"><label>Token Field</label><input id="f-token-field" value="access_token"><span class="hint">Key in the JSON response</span></div>
      </div>
      <div class="field"><label>Credentials (JSON)</label><textarea id="f-auth-body" rows="2" placeholder='{"username": "alice", "password": "alice123"}'></textarea><span class="hint">Leave blank to skip tests requiring a session</span></div>
    </div>
    <div id="auth-bearer" style="display:none">
      <div class="field"><label>Bearer Token</label><input id="f-direct-token" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."><span class="hint">Paste an existing JWT. Used for BOLA, mass assignment, and function-auth tests.</span></div>
    </div>
    <div id="auth-apikey" style="display:none">
      <div class="row">
        <div class="field"><label>Header Name</label><input id="f-api-key-header" placeholder="X-API-Key"><span class="hint">The header that carries the key</span></div>
        <div class="field"><label>Key Value</label><input id="f-api-key-value" placeholder="sk-..."></div>
      </div>
    </div>
    <div id="auth-none" style="display:none">
      <p class="hint" style="padding:8px 0">Only unauthenticated tests run: sensitive paths, CORS, security headers, schema exposure, rate-limit probing, and JWT forgery attempts.</p>
    </div>
  </div>

  <div class="card">
    <h2>Endpoint Configuration</h2>
    <div class="disc-row">
      <button class="btn-disc" onclick="discoverSchema()">Discover Schema</button>
      <span id="discover-msg" class="hint"></span>
    </div>
    <div class="row">
      <div class="field"><label>BOLA Path Template</label><input id="f-bola" value="/users/{id}"><span class="hint">Use {id} as the numeric ID placeholder</span></div>
      <div class="field"><label>Update Path (mass assignment)</label><input id="f-update" value="/users/1"><span class="hint">PUT endpoint that accepts a user body</span></div>
    </div>
    <div class="row">
      <div class="field"><label>Protected / Admin Path</label><input id="f-protected" value="/admin/users"><span class="hint">Endpoint only admins should access</span></div>
      <div class="field"><label>Rate-limit Probe Endpoint</label><input id="f-rate-ep" value="/auth/login"><span class="hint">Also used for verbose-error detection</span></div>
    </div>
  </div>

  <div class="card">
    <h2>Tests to Run</h2>
    <div class="test-grid">
      <label class="test-lbl"><input type="checkbox" id="t-api1" checked><div><span class="cat-name">API1 - BOLA</span><span class="cat-desc">Object-level access control + ID enumeration (IDs 1-5)</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api2" checked><div><span class="cat-name">API2 - Authentication</span><span class="cat-desc">JWT weak secret + algorithm confusion (alg:none bypass)</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api3" checked><div><span class="cat-name">API3 - Mass Assignment</span><span class="cat-desc">Privilege escalation via extra JSON fields (role, balance)</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api4" checked><div><span class="cat-name">API4 - Rate Limiting</span><span class="cat-desc">12 rapid login attempts - expect HTTP 429</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api5" checked><div><span class="cat-name">API5 - Function Auth</span><span class="cat-desc">Regular user token calling admin-only endpoints</span></div></label>
      <label class="test-lbl"><input type="checkbox" id="t-api8" checked><div><span class="cat-name">API8 - Misconfiguration</span><span class="cat-desc">CORS, security headers, schema exposure, verbose errors, sensitive paths</span></div></label>
    </div>
    <div style="margin-top:10px;display:flex;gap:12px">
      <button class="link-btn" onclick="toggleAll(true)">Select All</button>
      <button class="link-btn" onclick="toggleAll(false)">Clear All</button>
    </div>
  </div>

  <button class="btn btn-primary" id="scan-btn" onclick="runScan()">Run Scan</button>
  <div id="status-bar" style="display:none"></div>
  <div id="results" style="margin-top:16px"></div>
</div>

<script>
const CVE_DB = {
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

const PRESETS = {
  vulnerable:{target:'http://vulnerable-api:8000',auth:'{"username":"alice","password":"alice123"}'},
  hardened:  {target:'http://hardened-api:8001',  auth:'{"username":"alice","password":"alice123"}'},
  external:  {target:'',auth:''},
};
function loadPreset(name) {
  const p = PRESETS[name];
  if (name==='external') {
    document.getElementById('f-target').value = '';
    document.getElementById('f-auth-body').value = '';
    document.getElementById('discover-msg').textContent = 'Enter the target URL then click Discover Schema.';
    return;
  }
  document.getElementById('f-target').value = p.target;
  document.getElementById('f-auth-body').value = p.auth;
}

let _authMode = 'login';
function setAuth(tab, mode) {
  document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');
  ['login','bearer','apikey','none'].forEach(m =>
    document.getElementById('auth-'+m).style.display = m===mode ? 'block' : 'none'
  );
  _authMode = mode;
}

async function discoverSchema() {
  const target = document.getElementById('f-target').value.trim();
  if (!target) return alert('Enter a target URL first');
  const msg = document.getElementById('discover-msg');
  msg.textContent = 'Discovering...'; msg.style.color = '#8b949e';
  try {
    const r = await fetch('/monitor/scan/discover?target='+encodeURIComponent(target));
    const data = await r.json();
    if (data.found) {
      const paths = data.paths||[];
      const up = paths.find(p=>/\{[^}]+\}/.test(p)&&/user/i.test(p))||paths.find(p=>/\{[^}]+\}/.test(p));
      if (up) document.getElementById('f-bola').value = up.replace(/\{[^}]+\}/g,'{id}');
      const ap = paths.find(p=>/admin/i.test(p));
      if (ap) document.getElementById('f-protected').value = ap.replace(/\{[^}]+\}/g,'1');
      if (up) document.getElementById('f-update').value = up.replace(/\{[^}]+\}/g,'1');
      msg.textContent = 'Found '+data.schema_path+' ('+data.total_paths+' paths'+(data.api_title?' - '+data.api_title:'')+')';
      msg.style.color = '#3fb950';
    } else {
      msg.textContent = 'No OpenAPI schema found at common paths.'; msg.style.color = '#e3b341';
    }
  } catch(e) { msg.textContent = 'Error: '+e.message; msg.style.color='#f85149'; }
}

function toggleAll(checked) {
  ['api1','api2','api3','api4','api5','api8'].forEach(id => document.getElementById('t-'+id).checked = checked);
}

let _lastScan = null;

async function runScan() {
  const target = document.getElementById('f-target').value.trim();
  if (!target) return alert('Enter a target URL');
  const tests = ['api1','api2','api3','api4','api5','api8'].filter(id=>document.getElementById('t-'+id).checked);
  if (!tests.length) return alert('Select at least one test category');

  let authBody=null, directToken=null, apiKeyHeader=null, apiKeyValue=null;
  let authEndpoint=document.getElementById('f-rate-ep').value||'/auth/login', tokenField='access_token';
  if (_authMode==='login') {
    authEndpoint = document.getElementById('f-auth-ep').value||'/auth/login';
    tokenField   = document.getElementById('f-token-field').value||'access_token';
    const raw = (document.getElementById('f-auth-body').value||'').trim();
    if (raw) { try { authBody=JSON.parse(raw); } catch(e) { return alert('Credentials must be valid JSON'); } }
  } else if (_authMode==='bearer') {
    directToken = (document.getElementById('f-direct-token').value||'').trim()||null;
  } else if (_authMode==='apikey') {
    apiKeyHeader = (document.getElementById('f-api-key-header').value||'').trim()||null;
    apiKeyValue  = (document.getElementById('f-api-key-value').value||'').trim()||null;
  }

  const payload = {
    target, auth_endpoint:authEndpoint, auth_body:authBody, token_field:tokenField,
    direct_token:directToken, api_key_header:apiKeyHeader, api_key_value:apiKeyValue,
    bola_path:document.getElementById('f-bola').value,
    update_path:document.getElementById('f-update').value,
    protected_path:document.getElementById('f-protected').value,
    tests,
  };

  document.getElementById('scan-btn').disabled = true;
  const bar = document.getElementById('status-bar');
  bar.style.display = 'block';
  bar.innerHTML = '<span class="spinner"></span>Scanning <strong>'+target+'</strong> - may take 20-40s...';
  document.getElementById('results').innerHTML = '';

  try {
    const r = await fetch('/monitor/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if (!r.ok) throw new Error(await r.text());
    const data = await r.json();
    _lastScan = data;
    renderResults(data);
    bar.style.display = 'none';
  } catch(e) {
    bar.innerHTML = '<span style="color:#f85149">Error: '+e.message+'</span>';
  } finally {
    document.getElementById('scan-btn').disabled = false;
  }
}

function renderResults(data) {
  const el = document.getElementById('results');
  const sc = data.score>=80?'green':data.score>=50?'yellow':'red';
  let html = '<div class="score-row">'
    +'<div class="scard"><div class="num '+sc+'">'+data.score+'%</div><div class="lbl">Security Score</div></div>'
    +'<div class="scard"><div class="num blue">'+data.total_tests+'</div><div class="lbl">Tests Run</div></div>'
    +'<div class="scard"><div class="num red">'+data.total_vulnerable+'</div><div class="lbl">Vulnerable</div></div>'
    +'<div class="scard"><div class="num green">'+(data.total_tests-data.total_vulnerable)+'</div><div class="lbl">Passed</div></div>'
    +'</div>'
    +'<p style="color:#8b949e;font-size:.83em;margin-bottom:16px">Target: <code>'+data.target+'</code> &nbsp;|&nbsp; '+data.timestamp+'</p>';
  for (const cat of data.categories) {
    const cve = CVE_DB[cat.category]||null;
    const vuln = cat.vulnerable_count>0;
    html += '<div class="cat-block"><div class="cat-hdr"><h3>'+cat.category+'</h3>'
      +'<div style="display:flex;gap:8px;flex-wrap:wrap">'
      +(cve?'<span class="badge sev-'+cve.severity+'">'+cve.severity+'</span>':'')
      +'<span class="badge '+(vuln?'bv':'bs')+'">'+cat.vulnerable_count+'/'+cat.total+' Vulnerable</span>'
      +'</div></div>'
      +'<table><tr><th>Test</th><th>Request</th><th>Expected</th><th>Actual</th><th>Result</th></tr>';
    for (const t of cat.tests) {
      html += '<tr><td>'+t.test+'</td><td><code>'+t.request+'</code></td><td>'+t.expected+'</td><td>'+t.actual+'</td>'
        +'<td class="'+(t.vulnerable?'vY':'vN')+'">'+(t.vulnerable?'VULNERABLE':'SECURE')+'</td></tr>';
    }
    html += '</table>';
    if (cve) {
      html += '<div class="cve-panel"><h4>CVE References &amp; Remediation</h4>'
        +'<div class="cve-row">'
        +cve.cves.map(id=>'<a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/'+id+'" target="_blank">'+id+'</a>').join('')
        +'<a class="owasp-link" href="'+cve.owasp_ref+'" target="_blank">OWASP Reference &#x2192;</a>'
        +'</div><p class="vuln-desc">'+cve.description+'</p>'
        +'<div class="fixes"><ol>'+cve.fixes.map(f=>'<li>'+f+'</li>').join('')+'</ol></div></div>';
    }
    html += '</div>';
  }
  html += '<div class="export-bar">'
    +'<span style="font-size:.82em;color:#8b949e">Save as report:</span>'
    +'<button class="btn-save btn-save-brief" onclick="saveReport(\'brief\')">Brief Report</button>'
    +'<button class="btn-save btn-save-detail" onclick="saveReport(\'detailed\')">Detailed Report</button>'
    +'<span id="save-msg" style="font-size:.82em;margin-left:4px"></span></div>';
  el.innerHTML = html;
}

async function saveReport(detail) {
  if (!_lastScan) return;
  const msg = document.getElementById('save-msg');
  msg.style.color='#8b949e'; msg.textContent='Saving...';
  try {
    const r = await fetch('/monitor/save-report',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target:_lastScan.target,timestamp:_lastScan.timestamp,score:_lastScan.score,
        total_tests:_lastScan.total_tests,total_vulnerable:_lastScan.total_vulnerable,
        categories:_lastScan.categories,detail})});
    if (!r.ok) throw new Error(await r.text());
    const res = await r.json();
    msg.innerHTML = 'Saved! <a href="/monitor/reports/'+res.html_file+'" target="_blank" style="color:#58a6ff;font-weight:600">View Report &#x2192;</a>';
  } catch(e) { msg.style.color='#f85149'; msg.textContent='Error: '+e.message; }
}
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
    _CSS = """*{box-sizing:border-box;margin:0;padding:0}body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9}.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:40px;text-align:center}.header h1{color:#58a6ff;font-size:2.2em;margin-bottom:8px}.header p{color:#8b949e}.detail-badge{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.4);padding:3px 10px;border-radius:5px;font-size:.45em;font-weight:700;vertical-align:middle;margin-left:10px;text-transform:uppercase}.container{max-width:1200px;margin:0 auto;padding:28px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center}.card .num{font-size:2.2em;font-weight:700}.card .lbl{color:#8b949e;font-size:.83em;margin-top:5px}.red{color:#f85149}.green{color:#3fb950}.blue{color:#58a6ff}.yellow{color:#e3b341}.cat{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:16px}.cat-hdr{padding:16px 20px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}.cat-hdr h2{font-size:1.05em;color:#e6edf3}.badge{padding:3px 10px;border-radius:16px;font-size:.8em;font-weight:700}.bv{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}.bs{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid #3fb950}.sev-CRITICAL{background:rgba(188,30,30,.2);color:#ff6b6b;border:1px solid #ff6b6b}.sev-HIGH{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}.sev-MEDIUM{background:rgba(227,179,65,.15);color:#e3b341;border:1px solid #e3b341}.sev-LOW{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid #58a6ff}table{width:100%;border-collapse:collapse}th{background:#0d1117;padding:10px 14px;text-align:left;font-size:.78em;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}td{padding:10px 14px;border-top:1px solid #21262d;font-size:.85em;word-break:break-word}code{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:.86em}.vY{color:#f85149;font-weight:700}.vN{color:#3fb950}.sC{color:#f85149}.sH{color:#e3b341}.sM{color:#58a6ff}.sL{color:#8b949e}.cve-panel{padding:16px 20px;border-top:1px solid #21262d;background:#0d1117}.cve-panel h4{color:#8b949e;font-size:.78em;text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px}.cve-row{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:12px;align-items:center}.cve-badge{background:#161b22;border:1px solid #30363d;border-radius:5px;padding:3px 9px;font-size:.78em;font-family:monospace;color:#58a6ff;text-decoration:none}.cve-badge:hover{border-color:#58a6ff}.owasp-link{font-size:.8em;color:#8b949e;text-decoration:none;margin-left:auto}.owasp-link:hover{color:#58a6ff}.vuln-desc{font-size:.85em;color:#8b949e;margin-bottom:12px;line-height:1.55}.fixes h5{font-size:.78em;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin-bottom:7px}.fixes ol{padding-left:18px}.fixes li{font-size:.84em;color:#c9d1d9;line-height:1.6;padding:2px 0}.detail-section{padding:16px 20px;border-top:2px solid #1c2128;background:#0a0d10}.impact-block{margin-bottom:16px}.impact-block h4{color:#e3b341;font-size:.78em;text-transform:uppercase;letter-spacing:.07em;margin-bottom:7px}.impact-block p{font-size:.85em;color:#c9d1d9;line-height:1.6}.poc-block{margin-bottom:16px}.poc-block h5{font-size:.76em;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin-bottom:7px}.poc-block ol{padding-left:18px}.poc-block li{font-size:.83em;color:#c9d1d9;line-height:1.65;padding:2px 0}.code-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.code-label{font-size:.7em;font-weight:700;text-transform:uppercase;letter-spacing:.07em;padding:3px 9px;display:inline-block;border-radius:4px 4px 0 0}.vuln-lbl{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3);border-bottom:none}.fix-lbl{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.3);border-bottom:none}pre.code-pre{background:#0d1117;border:1px solid #21262d;border-radius:0 5px 5px 5px;padding:12px;font-size:.8em;font-family:Consolas,monospace;color:#c9d1d9;overflow-x:auto;white-space:pre;margin:0;line-height:1.55}.footer{text-align:center;padding:24px;color:#8b949e;font-size:.8em;border-top:1px solid #21262d;margin-top:28px}"""

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
        if cve:
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
        f'<title>API Security Report</title><style>{_CSS}</style></head><body>'
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
    imp_color = "#3fb950" if improvement > 0 else "#f85149" if improvement < 0 else "#e3b341"
    _CSS = ("*{box-sizing:border-box;margin:0;padding:0}body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9}"
            ".header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:40px;text-align:center}"
            ".header h1{color:#bc8cff;font-size:2.2em;margin-bottom:8px}.header p{color:#8b949e;font-size:.9em}"
            ".container{max-width:1200px;margin:0 auto;padding:28px}"
            ".cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:28px}"
            ".card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:22px;text-align:center}"
            ".card .num{font-size:2.4em;font-weight:700}.card .lbl{color:#8b949e;font-size:.85em;margin-top:6px}"
            ".red{color:#f85149}.green{color:#3fb950}"
            ".scenario{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:18px}"
            ".sc-hdr{padding:16px 20px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}"
            ".sc-hdr h2{font-size:1.05em;color:#e6edf3}"
            ".badge{padding:4px 12px;border-radius:20px;font-size:.82em;font-weight:700}"
            ".sev-CRITICAL{background:rgba(188,30,30,.2);color:#ff6b6b;border:1px solid #ff6b6b}"
            ".sev-HIGH{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}"
            ".sev-MEDIUM{background:rgba(227,179,65,.15);color:#e3b341;border:1px solid #e3b341}"
            ".sev-LOW{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid #58a6ff}"
            ".sc-body{display:grid;grid-template-columns:1fr 1fr 1fr}"
            ".sc-col{padding:16px 18px;border-right:1px solid #21262d}.sc-col:last-child{border-right:none}"
            ".col-label{font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px}"
            ".lbl-attack{color:#8b949e}.lbl-vuln{color:#f85149}.lbl-hard{color:#3fb950}"
            ".attack-code{display:block;background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px 12px;"
            "font-family:Consolas,monospace;font-size:.82em;color:#c9d1d9;white-space:pre-wrap;word-break:break-all}"
            ".result-status{font-weight:700;font-size:1.1em;margin-bottom:8px}"
            ".status-vuln{color:#f85149}.status-secure{color:#3fb950}"
            ".http-code{background:#0d1117;padding:2px 7px;border-radius:4px;font-family:monospace;font-size:.85em;margin-left:6px;color:#c9d1d9}"
            ".result-reason{font-size:.84em;color:#8b949e;line-height:1.55}"
            ".sc-footer{padding:14px 18px;display:flex;flex-wrap:wrap;gap:7px;align-items:center;border-top:1px solid #21262d}"
            ".cve-badge{background:#161b22;border:1px solid #30363d;border-radius:5px;padding:3px 9px;"
            "font-size:.78em;font-family:monospace;color:#58a6ff;text-decoration:none}"
            ".cve-badge:hover{border-color:#58a6ff}.owasp-link{font-size:.8em;color:#8b949e;text-decoration:none;margin-left:auto}"
            ".owasp-link:hover{color:#58a6ff}"
            ".footer{text-align:center;padding:28px;color:#8b949e;font-size:.82em;border-top:1px solid #21262d;margin-top:24px}")

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
        f'<style>{_CSS}</style></head><body>'
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
        ' &nbsp;|&nbsp; OWASP API Security Top 10:2023</div></body></html>'
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
<title>External API Scanner — CY384</title>
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
.vY{color:#f85149;font-weight:700}.vN{color:#3fb950}
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
  <span class="logo">CY384 — External API Scanner</span>
  <a href="/dashboard">Monitor</a>
  <a href="http://localhost:8000/ui" target="_blank">ShopApp Demo</a>
  <a href="http://localhost:8000/docs" target="_blank">API Docs</a>
</nav>
<div class="wrap">
  <h1>Generic OWASP API Security Scanner</h1>
  <p class="sub">Scan any API for OWASP API Top 10:2023 vulnerabilities — no source code required.</p>

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
    rec.update({"anomaly": det["anomaly"], "score": det["score"], "reason": det["reason"]})
    asyncio.create_task(_log(rec))

    resp_headers.pop("content-encoding", None)
    resp_headers.pop("transfer-encoding", None)
    return Response(content=content, status_code=status, headers=resp_headers)
