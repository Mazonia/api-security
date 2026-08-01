"""
VulnBank API — an intentionally vulnerable fintech REST API for practising with MazAPI.

Every endpoint below maps to exactly one OWASP API Security Top 10 (2023) category so the
target is predictable: you know what each route is *supposed* to teach. The `/lab` endpoint
returns a machine-readable challenge card for each vulnerability (name, description, hint,
how to test it with MazAPI), which the MazAPI extension can surface as a practice mode.

⚠️  DO NOT DEPLOY. This service is deliberately insecure and exists only for security
    education inside an isolated Docker network.

Stack: Flask (chosen per spec; the project's other deliberately-vulnerable target,
`vulnerable-api`, is FastAPI — VulnBank is a separate, OWASP-mapped practice target).
"""
import os
import time
import base64
import json
import hmac
import hashlib

from flask import Flask, request, jsonify, Response, render_template_string

app = Flask(__name__)

# ── API8: Security Misconfiguration ──────────────────────────────────────────────
# Debug mode on, wildcard CORS, and stack traces returned to the client (see error handler).
DEBUG_MODE = True

# Hardcoded JWT secret (also feeds the weak-auth lesson). Real apps load this from a vault.
JWT_SECRET = "vulnbank-super-secret-key"

# A third-party "identity verification" URL baked into an env var with no validation (API10).
IDENTITY_PROVIDER_URL = os.environ.get("IDENTITY_PROVIDER_URL", "http://identity-partner.internal/verify")


@app.after_request
def add_permissive_cors(resp: Response) -> Response:
    # API8: wildcard CORS with credentials — a textbook misconfiguration.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    return resp


# ── In-memory data ───────────────────────────────────────────────────────────────
ACCOUNTS = {
    "1001": {"id": "1001", "owner": "alice", "balance": 4200.50, "iban": "GH88 0000 1001",
             "ssn": "501-22-9087", "phone": "+233201112233"},
    "1002": {"id": "1002", "owner": "bob",   "balance": 980.00,  "iban": "GH88 0000 1002",
             "ssn": "502-33-1144", "phone": "+233244556677"},
    "1003": {"id": "1003", "owner": "carol", "balance": 75250.0, "iban": "GH88 0000 1003",
             "ssn": "503-44-2255", "phone": "+233209998877"},
}

USERS = {
    "alice": {"username": "alice", "password": "alice123", "role": "user",  "account": "1001",
              "password_hash": hashlib.sha256(b"alice123").hexdigest(), "is_admin": False, "internal_id": "u-001"},
    "bob":   {"username": "bob",   "password": "bob123",   "role": "user",  "account": "1002",
              "password_hash": hashlib.sha256(b"bob123").hexdigest(),   "is_admin": False, "internal_id": "u-002"},
    "carol": {"username": "carol", "password": "carol123", "role": "admin", "account": "1003",
              "password_hash": hashlib.sha256(b"carol123").hexdigest(), "is_admin": True,  "internal_id": "u-003"},
}

TRANSACTIONS = [
    {"id": i, "account": acct, "amount": round((i * 13.5) % 900, 2), "type": "debit" if i % 2 else "credit"}
    for i, acct in enumerate(["1001", "1002", "1003"] * 60, start=1)
]


# ── Minimal JWT (intentionally weak) ─────────────────────────────────────────────
def _b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).decode().rstrip("=")


def make_token(username: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": username, "role": USERS.get(username, {}).get("role", "user")}).encode())
    sig = _b64(hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def read_token():
    """Decode the bearer token WITHOUT verifying the signature — accepts forged/alg:none tokens."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        payload = auth.split(" ", 1)[1].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


# ── API1: Broken Object Level Authorization (BOLA) ───────────────────────────────
@app.route("/accounts/<account_id>", methods=["GET"])
def get_account(account_id):
    # No check that the caller actually owns this account — any ID is returned.
    acct = ACCOUNTS.get(account_id)
    if not acct:
        return jsonify({"error": "not found"}), 404
    return jsonify(acct)


# ── API2: Broken Authentication ──────────────────────────────────────────────────
@app.route("/auth/login", methods=["POST"])
def login():
    # No rate limiting + a hardcoded backdoor password that works for ANY account.
    body = request.get_json(silent=True) or {}
    username, password = body.get("username"), body.get("password")
    user = USERS.get(username)
    if user and (password == user["password"] or password == "admin123"):  # backdoor
        return jsonify({"token": make_token(username), "role": user["role"]})
    return jsonify({"error": "invalid credentials"}), 401


# ── API3: Broken Object Property Level Authorization ─────────────────────────────
@app.route("/users/profile", methods=["GET"])
def profile():
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
    user = USERS.get(tok.get("sub"))
    if not user:
        return jsonify({"error": "unknown user"}), 401
    # Returns the WHOLE user object, including password_hash, is_admin and internal_id.
    return jsonify(user)


# ── API4: Unrestricted Resource Consumption ──────────────────────────────────────
@app.route("/transactions/export", methods=["GET"])
def export_transactions():
    # No pagination, no limit — dumps every transaction in one response.
    return jsonify({"count": len(TRANSACTIONS), "transactions": TRANSACTIONS})


# ── API5: Broken Function Level Authorization ────────────────────────────────────
@app.route("/admin/users/<user_id>", methods=["DELETE"])
def admin_delete_user(user_id):
    # "Authorization" is a query param the client controls, not a real check.
    if request.args.get("admin") == "true":
        return jsonify({"deleted": user_id, "status": "ok"})
    return jsonify({"error": "forbidden"}), 403


# ── API6: Unrestricted Access to Sensitive Business Flows ─────────────────────────
@app.route("/transfer", methods=["POST"])
def transfer():
    # No idempotency key — the same transfer can be replayed indefinitely.
    body = request.get_json(silent=True) or {}
    src, dst, amount = body.get("from"), body.get("to"), float(body.get("amount", 0))
    if src in ACCOUNTS and dst in ACCOUNTS:
        ACCOUNTS[src]["balance"] -= amount
        ACCOUNTS[dst]["balance"] += amount
        return jsonify({"status": "transferred", "amount": amount, "from": src, "to": dst,
                        "replayable": True})
    return jsonify({"error": "invalid account"}), 400


# ── API7: Server-Side Request Forgery (SSRF) ─────────────────────────────────────
@app.route("/webhook/test", methods=["POST"])
def webhook_test():
    # Fetches any URL the client supplies — including internal / metadata endpoints.
    body = request.get_json(silent=True) or {}
    url = body.get("url", "")
    try:
        import urllib.request
        # nosec: this is the intentional SSRF sink for the lab
        with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310
            return jsonify({"url": url, "status": r.status, "body": r.read(200).decode("utf-8", "replace")})
    except Exception as e:
        return jsonify({"url": url, "error": str(e)})


# ── API9: Improper Inventory Management ──────────────────────────────────────────
# Both /api/v1 and /api/v2 are live; v1 has NO auth on routes that v2 protects.
@app.route("/api/v1/accounts/<account_id>", methods=["GET"])
def v1_account(account_id):
    # Legacy, unauthenticated — the shadow API.
    return jsonify({"version": "v1", "warning": "deprecated-but-live", **ACCOUNTS.get(account_id, {})})


@app.route("/api/v2/accounts/<account_id>", methods=["GET"])
def v2_account(account_id):
    if not read_token():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"version": "v2", **ACCOUNTS.get(account_id, {})})


# ── API10: Unsafe Consumption of APIs ────────────────────────────────────────────
@app.route("/verify/identity", methods=["POST"])
def verify_identity():
    # Forwards user PII to a third-party URL from an env var with no validation of the
    # destination or the response — blindly trusts whatever comes back.
    body = request.get_json(silent=True) or {}
    try:
        import urllib.request
        req = urllib.request.Request(
            IDENTITY_PROVIDER_URL, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3) as r:  # noqa: S310
            return jsonify({"forwarded_to": IDENTITY_PROVIDER_URL, "provider_response": r.read(200).decode("utf-8", "replace")})
    except Exception as e:
        # Still echoes the destination so the misconfiguration is observable in the lab.
        return jsonify({"forwarded_to": IDENTITY_PROVIDER_URL, "sent": body, "error": str(e)})


# ── /lab: machine-readable challenge cards (practice mode) ────────────────────────
LAB_CHALLENGES = [
    {"id": "API1", "name": "Broken Object Level Authorization (BOLA)",
     "endpoint": "GET /accounts/{id}", "severity": "CRITICAL",
     "description": "Any account ID returns that account's data, regardless of who is authenticated.",
     "hint": "Request /accounts/1001 then /accounts/1003 with the same (or no) token.",
     "mazapi": "MazAPI's IDOR-probing behavioral detector fires when you walk sequential IDs."},
    {"id": "API2", "name": "Broken Authentication",
     "endpoint": "POST /auth/login", "severity": "CRITICAL",
     "description": "No rate limiting, and the hardcoded password 'admin123' logs into any account.",
     "hint": "POST {\"username\":\"alice\",\"password\":\"admin123\"} — it succeeds.",
     "mazapi": "Run the Scan tab with the auth endpoint set; the rate-limit test will not see a 429."},
    {"id": "API3", "name": "Broken Object Property Level Authorization",
     "endpoint": "GET /users/profile", "severity": "HIGH",
     "description": "Returns internal fields: password_hash, is_admin, internal_id.",
     "hint": "Log in, then GET /users/profile and inspect the extra fields.",
     "mazapi": "MazAPI flags PII / over-exposed object properties in the response."},
    {"id": "API4", "name": "Unrestricted Resource Consumption",
     "endpoint": "GET /transactions/export", "severity": "HIGH",
     "description": "No pagination — returns all transactions in one unbounded response.",
     "hint": "GET /transactions/export and note the count is unbounded.",
     "mazapi": "Excessive-data and enumeration heuristics flag the large array."},
    {"id": "API5", "name": "Broken Function Level Authorization",
     "endpoint": "DELETE /admin/users/{id}", "severity": "CRITICAL",
     "description": "Admin gate is the client-controlled ?admin=true query param.",
     "hint": "DELETE /admin/users/2?admin=true succeeds without any real role check.",
     "mazapi": "Function-level auth test + auth-bypass behavioral detector."},
    {"id": "API6", "name": "Unrestricted Access to Sensitive Business Flows",
     "endpoint": "POST /transfer", "severity": "HIGH",
     "description": "No idempotency key — transfers can be replayed any number of times.",
     "hint": "POST the same /transfer body twice; the balance moves twice.",
     "mazapi": "Replay the request and observe the duplicate effect."},
    {"id": "API7", "name": "Server-Side Request Forgery (SSRF)",
     "endpoint": "POST /webhook/test", "severity": "CRITICAL",
     "description": "Fetches any URL the client provides, including cloud metadata.",
     "hint": "POST {\"url\":\"http://169.254.169.254/latest/meta-data/\"}.",
     "mazapi": "MazAPI's SSRF test targets the metadata service automatically."},
    {"id": "API8", "name": "Security Misconfiguration",
     "endpoint": "(all routes)", "severity": "HIGH",
     "description": "Debug mode on, wildcard CORS with credentials, stack traces in errors.",
     "hint": "Trigger an error (e.g. malformed JSON) and read the traceback.",
     "mazapi": "CORS-wildcard, security-headers and stack-trace tests cover this."},
    {"id": "API9", "name": "Improper Inventory Management",
     "endpoint": "GET /api/v1/accounts/{id}", "severity": "HIGH",
     "description": "Legacy /api/v1 is live and unauthenticated while /api/v2 requires a token.",
     "hint": "Compare /api/v1/accounts/1003 (open) vs /api/v2/accounts/1003 (401).",
     "mazapi": "MazAPI's multi-version detection flags coexisting v1/v2."},
    {"id": "API10", "name": "Unsafe Consumption of APIs",
     "endpoint": "POST /verify/identity", "severity": "MEDIUM",
     "description": "Forwards user PII to a hardcoded third-party URL with no validation.",
     "hint": "POST identity data and see it forwarded to IDENTITY_PROVIDER_URL.",
     "mazapi": "Review the forwarded_to field — destination is attacker-influenceable via env."},
]


@app.route("/lab", methods=["GET"])
def lab():
    return jsonify({
        "service": "VulnBank API",
        "warning": "Intentionally vulnerable — for security education only.",
        "challenges": LAB_CHALLENGES,
        "credentials": {"alice": "alice123", "bob": "bob123", "carol": "carol123 (admin)"},
        "backdoor_password": "admin123",
    })


LAB_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#090d16;--surf:#111827;--surf2:#1f293d;--border:rgba(255,255,255,0.09);
    --text:#f3f4f6;--muted:#9ca3af;--emerald:#10b981;--indigo:#6366f1;
    --rose:#f43f5e;--amber:#f59e0b;--purple:#8b5cf6;--radius:12px;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;padding:32px 24px;line-height:1.5;max-width:1400px;margin:0 auto}
  h1{color:var(--emerald);font-size:2rem;font-weight:800;margin-bottom:4px;letter-spacing:-0.02em}
  .subtitle{color:var(--muted);font-size:0.92rem;margin-bottom:28px}
  .creds{background:var(--surf);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:32px;font-size:0.88rem;box-shadow:0 4px 20px rgba(0,0,0,0.2)}
  .creds b{color:var(--emerald)}
  .creds code{background:var(--bg);border:1px solid var(--border);padding:2px 7px;border-radius:4px;color:#60a5fa;font-family:'Fira Code',monospace}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:20px}
  .card{background:var(--surf);border:1px solid var(--border);border-radius:var(--radius);padding:22px;display:flex;flex-direction:column;gap:12px;box-shadow:0 4px 20px rgba(0,0,0,0.25);transition:border-color 0.2s,transform 0.2s}
  .card:hover{border-color:rgba(99,102,241,0.3);transform:translateY(-2px)}
  .card-head{display:flex;align-items:center;gap:10px}
  .badge{font-size:0.72rem;font-weight:800;padding:3px 10px;border-radius:20px;text-transform:uppercase;white-space:nowrap;letter-spacing:0.04em}
  .CRITICAL{background:rgba(244,63,94,0.15);color:var(--rose);border:1px solid rgba(244,63,94,0.4)}
  .HIGH{background:rgba(245,158,11,0.15);color:var(--amber);border:1px solid rgba(245,158,11,0.4)}
  .MEDIUM{background:rgba(99,102,241,0.15);color:var(--indigo);border:1px solid rgba(99,102,241,0.4)}
  .card-id{font-size:0.75rem;color:var(--muted);font-weight:600;font-family:'Fira Code',monospace}
  .card-name{font-size:1.02rem;font-weight:700;color:#fff}
  .card-desc{font-size:0.86rem;color:var(--muted);line-height:1.55}
  .card-hint{font-size:0.82rem;color:var(--emerald);background:rgba(16,185,129,0.08);border-left:3px solid var(--emerald);padding:8px 12px;border-radius:0 6px 6px 0}
  .card-mazapi{font-size:0.8rem;color:var(--purple);background:rgba(139,92,246,0.08);border-left:3px solid var(--purple);padding:8px 12px;border-radius:0 6px 6px 0}
  .endpoint{font-family:'Fira Code',monospace;font-size:0.82rem;background:var(--bg);border:1px solid var(--border);padding:6px 12px;border-radius:6px;color:#60a5fa;display:flex;align-items:center;justify-content:space-between;gap:8px}
  .try-btn{background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff;border:none;border-radius:20px;padding:7px 16px;font-size:0.82rem;font-weight:700;cursor:pointer;white-space:nowrap;flex-shrink:0;transition:opacity 0.15s}
  .try-btn:hover{opacity:0.9}
  .response-box{display:none;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'Fira Code',monospace;font-size:0.78rem;color:var(--text);white-space:pre-wrap;max-height:240px;overflow-y:auto}
  .response-box.visible{display:block}
  .status-ok{color:var(--emerald);font-weight:600}
  .status-err{color:var(--rose);font-weight:600}
  label{font-size:0.8rem;color:var(--muted);font-weight:500}
  input[type=text]{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);font-size:0.84em;margin-top:4px;font-family:inherit;transition:border-color 0.15s}
  input[type=text]:focus{outline:none;border-color:var(--indigo)}
  .token-row{display:flex;gap:8px;align-items:flex-end;margin-top:4px}
  .token-row input{flex:1}
  .login-hint{font-size:0.75rem;color:var(--muted);margin-top:3px}
</style>
</head>
<body>
<h1>VulnBank Lab</h1>
<p class="subtitle">Intentionally vulnerable API — OWASP API Security Top 10 (2023) practice target for MazAPI</p>

<div class="creds">
  <b>Credentials:</b>&nbsp;
  alice / <code>alice123</code> &nbsp;|&nbsp;
  bob / <code>bob123</code> &nbsp;|&nbsp;
  carol / <code>carol123</code> (admin) &nbsp;|&nbsp;
  backdoor: <code>admin123</code> works on any account
</div>

<div style="margin-bottom:18px">
  <label>Bearer token (paste after logging in via API2, used by any challenge that needs auth)
    <div class="token-row">
      <input type="text" id="global-token" placeholder="eyJ...">
    </div>
  </label>
  <div class="login-hint">Quick-login: use the "Try it" button on API2 to get a token, then paste it here.</div>
</div>

<div class="grid" id="grid"></div>

<script>
const BASE = "http://localhost:8002";
const CHALLENGES = {{ challenges|tojson }};

const PREFILLS = {
  "API1": [{label:"Account ID", key:"account_id", default:"1001"}],
  "API2": [{label:"Username", key:"username", default:"alice"},{label:"Password", key:"password", default:"admin123"}],
  "API3": [],
  "API4": [],
  "API5": [{label:"User ID to delete", key:"user_id", default:"2"}],
  "API6": [{label:"From account", key:"from", default:"1001"},{label:"To account", key:"to", default:"1002"},{label:"Amount", key:"amount", default:"50"}],
  "API7": [{label:"URL to fetch", key:"url", default:"http://169.254.169.254/latest/meta-data/"}],
  "API8": [],
  "API9": [{label:"Account ID", key:"account_id", default:"1003"}],
  "API10": [{label:"Name", key:"name", default:"Alice Test"},{label:"ID number", key:"id_number", default:"GH-1234567"}],
};

function token() { return document.getElementById("global-token").value.trim(); }

async function fire(id) {
  const box = document.getElementById("resp-"+id);
  box.className = "response-box visible";
  box.textContent = "Loading\\u2026";

  const hdrs = {"Content-Type":"application/json"};
  if (token()) hdrs["Authorization"] = "Bearer " + token();

  const inputs = PREFILLS[id] || [];
  const vals = {};
  inputs.forEach(f => { vals[f.key] = document.getElementById(id+"-"+f.key).value; });

  let url = BASE, method = "GET", body = null;

  try {
    if (id === "API1") { url = BASE+"/accounts/"+vals.account_id; }
    else if (id === "API2") {
      url = BASE+"/auth/login"; method = "POST";
      body = JSON.stringify({username:vals.username, password:vals.password});
    }
    else if (id === "API3") { url = BASE+"/users/profile"; }
    else if (id === "API4") { url = BASE+"/transactions/export"; }
    else if (id === "API5") { url = BASE+"/admin/users/"+vals.user_id+"?admin=true"; method = "DELETE"; }
    else if (id === "API6") {
      url = BASE+"/transfer"; method = "POST";
      body = JSON.stringify({from:vals.from, to:vals.to, amount:parseFloat(vals.amount)});
    }
    else if (id === "API7") {
      url = BASE+"/webhook/test"; method = "POST";
      body = JSON.stringify({url:vals.url});
    }
    else if (id === "API8") { url = BASE+"/health"; }
    else if (id === "API9") { url = BASE+"/api/v1/accounts/"+vals.account_id; }
    else if (id === "API10") {
      url = BASE+"/verify/identity"; method = "POST";
      body = JSON.stringify({name:vals.name, id_number:vals.id_number});
    }

    const opts = {method, headers:hdrs};
    if (body) opts.body = body;
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => r.text());
    const label = r.ok ? "\\u2705 "+r.status : "\\u274c "+r.status;
    box.innerHTML = '<span class="'+(r.ok?"status-ok":"status-err")+'">'+label+'</span>\\n'+JSON.stringify(data,null,2);

    // Auto-paste token if this was a login
    if (id === "API2" && data.token) {
      document.getElementById("global-token").value = data.token;
      box.innerHTML += "\\n\\n// Token saved to the field above ^";
    }
  } catch(e) {
    box.innerHTML = '<span class="status-err">Error: '+e.message+'</span>';
  }
}

CHALLENGES.forEach(c => {
  const inputs = PREFILLS[c.id] || [];
  const inputsHtml = inputs.map(f => `
    <label>${f.label}
      <input type="text" id="${c.id}-${f.key}" value="${f.default}">
    </label>`).join("");

  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `
    <div class="card-head">
      <span class="badge ${c.severity}">${c.severity}</span>
      <span class="card-id">${c.id}</span>
    </div>
    <div class="card-name">${c.name}</div>
    <div class="card-desc">${c.description}</div>
    <div class="endpoint">
      <span>${c.endpoint}</span>
      <button class="try-btn" data-id="${c.id}">Try it</button>
    </div>
    ${inputsHtml}
    <div class="card-hint">Hint: ${c.hint}</div>
    <div class="card-mazapi">MazAPI: ${c.mazapi}</div>
    <pre class="response-box" id="resp-${c.id}"></pre>
  `;
  document.getElementById("grid").appendChild(card);
  // Attach the handler in JS (not inline onclick) so quotes in the data never break it.
  card.querySelector(".try-btn").addEventListener("click", () => fire(c.id));
});
</script>
</body>
</html>"""


@app.route("/lab/ui", methods=["GET"])
def lab_ui():
    return render_template_string(LAB_UI, challenges=LAB_CHALLENGES)


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "VulnBank API", "lab": "/lab", "lab_ui": "/lab/ui", "challenges": len(LAB_CHALLENGES)})


@app.route("/health", methods=["GET"])
def health():
    # API8 bonus: unauthenticated health endpoint that leaks version/build info.
    return jsonify({"status": "ok", "version": "1.0.0-vuln", "debug": DEBUG_MODE, "build": "vulnbank-lab"})


# API8: verbose error handler returns the stack trace to the client.
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    return jsonify({"error": str(e), "traceback": traceback.format_exc() if DEBUG_MODE else "hidden"}), 500


if __name__ == "__main__":
    # API8: debug=True in "production" — never do this for real.
    app.run(host="0.0.0.0", port=8002, debug=DEBUG_MODE)
