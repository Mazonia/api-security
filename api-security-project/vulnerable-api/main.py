import time
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Vulnerable API", docs_url="/docs", redoc_url="/redoc")

# API8: Wildcard CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API2: Hardcoded weak secret, no expiry
SECRET_KEY = "secret"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users_db: dict = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com",
        "password": pwd_context.hash("alice123"), "role": "user", "balance": 1000.0},
    2: {"id": 2, "username": "bob", "email": "bob@example.com",
        "password": pwd_context.hash("bob123"), "role": "user", "balance": 500.0},
    3: {"id": 3, "username": "admin", "email": "admin@example.com",
        "password": pwd_context.hash("admin123"), "role": "admin", "balance": 9999.0},
}

orders_db: dict = {
    1: {"id": 1, "user_id": 1, "item": "Laptop", "price": 999.99, "status": "shipped"},
    2: {"id": 2, "user_id": 2, "item": "Phone", "price": 499.99, "status": "pending"},
    3: {"id": 3, "user_id": 3, "item": "Server", "price": 4999.99, "status": "delivered"},
}


class LoginRequest(BaseModel):
    username: str
    password: str


class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None      # API3: mass assignment — role should never be user-updatable
    balance: Optional[float] = None  # API3: balance should never be user-updatable


def create_token(user_id: int, username: str, role: str) -> str:
    # API2: no expiry claim
    return jwt.encode({"sub": str(user_id), "username": username, "role": role},
                      SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = users_db.get(int(payload["sub"]))
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/auth/login")
def login(req: LoginRequest):
    for user in users_db.values():
        if user["username"] == req.username:
            if pwd_context.verify(req.password, user["password"]):
                return {"access_token": create_token(user["id"], user["username"], user["role"]),
                        "token_type": "bearer"}
            # API8: verbose error reveals that username exists but password is wrong
            raise HTTPException(status_code=401,
                                detail=f"Wrong password for user '{req.username}'")
    # API8: verbose error reveals username does not exist
    raise HTTPException(status_code=401, detail=f"User not found: '{req.username}'")


@app.get("/users/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    # API1: BOLA — no ownership check
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {k: v for k, v in user.items() if k != "password"}


@app.put("/users/{user_id}")
def update_user(user_id: int, update: UserUpdate,
                current_user: dict = Depends(get_current_user)):
    # API1: BOLA — no ownership check
    # API3: accepts role and balance from request body
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    data = update.model_dump(exclude_none=True)
    if "password" in data:
        data["password"] = pwd_context.hash(data["password"])
    user.update(data)
    return {"message": "Updated", "user": {k: v for k, v in user.items() if k != "password"}}


@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user: dict = Depends(get_current_user)):
    # API1: BOLA — any authenticated user reads any order
    order = orders_db.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@app.get("/users/{user_id}/orders")
def get_user_orders(user_id: int, current_user: dict = Depends(get_current_user)):
    # API1: BOLA — no ownership check
    return [o for o in orders_db.values() if o["user_id"] == user_id]


# API5: admin endpoints with no role check
@app.get("/admin/users")
def admin_list_users(current_user: dict = Depends(get_current_user)):
    return list(users_db.values())


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    del users_db[user_id]
    return {"message": "User deleted"}


@app.get("/admin/orders")
def admin_list_orders(current_user: dict = Depends(get_current_user)):
    return list(orders_db.values())


# API8: debug endpoint exposes secret key and internal config
@app.get("/debug/config")
def debug_config():
    return {
        "secret_key": SECRET_KEY,
        "algorithm": ALGORITHM,
        "environment": "vulnerable",
        "users_count": len(users_db),
        "server_time": time.time(),
        "debug_mode": True,
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "vulnerable-api"}


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def shopapp_ui():
    return _SHOPAPP_HTML


_SHOPAPP_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShopApp — Vulnerable API Demo</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#090d16;--surf:#111827;--surf2:#1f293d;--border:rgba(255,255,255,0.09);
  --text:#f3f4f6;--muted:#9ca3af;--emerald:#10b981;--indigo:#6366f1;
  --rose:#f43f5e;--amber:#f59e0b;--radius:10px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
nav{background:var(--surf);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:16px;height:60px;box-shadow:0 4px 16px rgba(0,0,0,0.3)}
nav .logo{color:var(--emerald);font-weight:800;font-size:1.2em;letter-spacing:-0.01em}
nav .badge{background:rgba(244,63,94,0.15);color:var(--rose);border:1px solid rgba(244,63,94,0.4);border-radius:20px;padding:3px 12px;font-size:0.75em;font-weight:700}
nav button{background:var(--surf2);border:1px solid var(--border);color:var(--text);border-radius:20px;padding:6px 16px;cursor:pointer;font-size:0.85em;font-weight:600;transition:all 0.18s}
nav button:hover{border-color:var(--emerald);color:var(--emerald)}
.nav-tool-link{color:var(--muted);font-size:0.82em;text-decoration:none;padding:5px 12px;border:1px solid var(--border);border-radius:20px;transition:all 0.18s}
.nav-tool-link:hover{color:var(--indigo);border-color:var(--indigo)}
.main{max-width:1140px;margin:0 auto;padding:32px 20px;display:grid;grid-template-columns:310px 1fr;gap:24px}
.sidebar{display:flex;flex-direction:column;gap:18px}
.panel{background:var(--surf);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.2)}
.panel-hdr{padding:16px 20px;border-bottom:1px solid var(--border);background:var(--surf2);display:flex;justify-content:space-between;align-items:center}
.panel-hdr h3{font-size:0.95em;font-weight:700;color:#fff}
.vuln-tag{background:rgba(244,63,94,0.15);color:var(--rose);border:1px solid rgba(244,63,94,0.4);border-radius:20px;padding:2px 9px;font-size:0.72em;font-weight:700}
.panel-body{padding:18px 20px}
.field{margin-bottom:14px}
.field label{display:block;font-size:0.8em;color:var(--muted);margin-bottom:6px;font-weight:500}
.field input,.field select{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:9px 12px;font-size:0.88em;font-family:inherit;transition:border-color 0.15s}
.field input:focus,.field select:focus{outline:none;border-color:var(--indigo);box-shadow:0 0 0 3px rgba(99,102,241,0.2)}
.field input[readonly]{opacity:0.6;cursor:not-allowed}
.btn{width:100%;padding:10px;border:none;border-radius:20px;cursor:pointer;font-size:0.88em;font-weight:700;font-family:inherit;transition:all 0.18s}
.btn-primary{background:linear-gradient(135deg,#10b981,#059669);color:#fff;box-shadow:0 2px 10px rgba(16,185,129,0.3)}.btn-primary:hover{opacity:0.9;transform:translateY(-1px)}
.btn-danger{background:linear-gradient(135deg,#f43f5e,#e11d48);color:#fff;box-shadow:0 2px 10px rgba(244,63,94,0.3)}.btn-danger:hover{opacity:0.9;transform:translateY(-1px)}
.btn-secondary{background:var(--surf2);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{border-color:var(--indigo);color:var(--indigo)}
.btn-warn{background:rgba(245,158,11,0.15);color:var(--amber);border:1px solid rgba(245,158,11,0.4)}.btn-warn:hover{background:rgba(245,158,11,0.25)}
.msg{margin-top:12px;padding:9px 14px;border-radius:6px;font-size:0.83em;display:none;font-weight:500}
.msg.ok{background:rgba(16,185,129,0.12);color:var(--emerald);border:1px solid rgba(16,185,129,0.3)}
.msg.err{background:rgba(244,63,94,0.12);color:var(--rose);border:1px solid rgba(244,63,94,0.3)}
.msg.warn{background:rgba(245,158,11,0.12);color:var(--amber);border:1px solid rgba(245,158,11,0.3)}
.kv{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:0.85em}
.kv:last-child{border:none}
.kv .k{color:var(--muted)}
.kv .v{color:#fff;font-weight:600;word-break:break-all;text-align:right;max-width:60%}
.kv .v.red{color:var(--rose)}.kv .v.green{color:var(--emerald)}.kv .v.yellow{color:var(--amber)}.kv .v.blue{color:var(--indigo)}
.order-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:12px}
.order-card:last-child{margin-bottom:0}
.order-card .item{font-weight:700;font-size:0.9em;margin-bottom:6px;color:#fff}
.order-card .meta{font-size:0.8em;color:var(--muted)}
.status-shipped{color:var(--emerald);font-weight:600}.status-pending{color:var(--amber);font-weight:600}.status-delivered{color:var(--indigo);font-weight:600}
.login-wrap{max-width:420px;margin:80px auto;padding:0 20px}
.login-wrap h2{color:var(--emerald);font-size:1.6em;font-weight:800;margin-bottom:6px}
.login-wrap p{color:var(--muted);font-size:0.88em;margin-bottom:24px}
.accounts{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:18px}
.accounts p{font-size:.8em;color:#8b949e;margin-bottom:8px}
.acc{display:flex;gap:8px;margin-bottom:6px;align-items:center;font-size:.83em}
.acc button{background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;padding:2px 10px;cursor:pointer;font-size:.8em}
.acc button:hover{border-color:#58a6ff;color:#58a6ff}
.warn-banner{background:rgba(227,179,65,.1);border:1px solid rgba(227,179,65,.4);border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:.82em;color:#e3b341}
pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-size:.8em;color:#79c0ff;overflow:auto;max-height:260px;white-space:pre-wrap;word-break:break-all}
.tab-row{display:flex;gap:0;border-bottom:1px solid #30363d}
.tab{padding:10px 16px;cursor:pointer;font-size:.85em;color:#8b949e;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.tab-content{padding:16px 18px}
.tab-pane{display:none}.tab-pane.active{display:block}
/* tutorials */
details.guide{margin-bottom:12px;background:#0d1117;border:1px solid #30363d;border-radius:6px}
details.guide summary{padding:8px 12px;cursor:pointer;font-size:.79em;color:#e3b341;font-weight:600;list-style:none;user-select:none}
details.guide summary::-webkit-details-marker{display:none}
details.guide summary::before{content:"▶ ";font-size:.7em;transition:transform .15s;display:inline-block}
details[open].guide summary::before{transform:rotate(90deg)}
details.guide .gb{padding:10px 14px 12px;border-top:1px solid #21262d}
details.guide ol{padding-left:16px;margin-bottom:8px}
details.guide li{font-size:.82em;color:#c9d1d9;line-height:1.7}
details.guide li strong{color:#79c0ff}
details.guide .gnote{font-size:.78em;color:#8b949e;line-height:1.5;border-top:1px solid #21262d;margin-top:8px;padding-top:8px}
.proxy-notice{background:rgba(88,166,255,.07);border-left:3px solid #58a6ff;padding:8px 16px;margin:0 20px 0;font-size:.79em;color:#58a6ff;display:flex;align-items:center;gap:8px}
.proxy-notice a{color:#58a6ff}
</style>
</head>
<body>
<!-- ─── NAV ─── -->
<nav>
  <span class="logo">ShopApp</span>
  <span id="nav-badge" class="badge">INTENTIONALLY VULNERABLE</span>
  <div style="display:flex;gap:4px;margin:0 8px">
    <a class="nav-tool-link" href="http://localhost:9000/dashboard">Monitor</a>
    <a class="nav-tool-link" href="http://localhost:9000/scan-ui">Scanner</a>
  </div>
  <!-- API mode toggle -->
  <div style="display:flex;align-items:center;gap:4px;background:#21262d;border:1px solid #30363d;border-radius:7px;padding:3px;margin-left:12px">
    <button id="mode-vuln-btn" onclick="setMode('vulnerable')"
      style="padding:4px 12px;border:none;border-radius:5px;font-size:.78em;font-weight:700;cursor:pointer;background:#f85149;color:#fff;transition:all .15s">
      Vulnerable
    </button>
    <button id="mode-hard-btn" onclick="setMode('hardened')"
      style="padding:4px 12px;border:none;border-radius:5px;font-size:.78em;font-weight:700;cursor:pointer;background:transparent;color:#8b949e;transition:all .15s">
      Hardened
    </button>
  </div>
  <span id="nav-user" style="font-size:.85em;color:#8b949e;margin-left:auto"></span>
  <button id="logout-btn" onclick="logout()" style="display:none;padding:5px 14px;background:transparent;border:1px solid #30363d;border-radius:6px;color:#8b949e;cursor:pointer;font-size:.82em">Logout</button>
</nav>

<!-- ─── LOGIN ─── -->
<div id="login-view">
  <div class="login-wrap">
    <h2>Sign in to ShopApp</h2>
    <p>Demonstration app for the CY384 API Security Project — this API is intentionally vulnerable to OWASP API Top 10 flaws.</p>
    <div class="warn-banner">All data is synthetic. This app exists to demonstrate real API security vulnerabilities in a controlled lab environment.</div>
    <div class="accounts">
      <p>Demo accounts (click to fill):</p>
      <div class="acc"><span>alice / alice123 (user)</span><button onclick="fill('alice','alice123')">Use</button></div>
      <div class="acc"><span>bob / bob123 (user)</span><button onclick="fill('bob','bob123')">Use</button></div>
      <div class="acc"><span>admin / admin123 (admin)</span><button onclick="fill('admin','admin123')">Use</button></div>
    </div>
    <div class="panel">
      <div class="panel-body">
        <div class="field"><label>Username</label><input id="l-user" type="text" placeholder="username"></div>
        <div class="field"><label>Password</label><input id="l-pass" type="password" placeholder="password"></div>
        <button class="btn btn-primary" onclick="doLogin()">Sign In</button>
        <div class="msg" id="l-msg"></div>
      </div>
    </div>
  </div>
</div>

<!-- ─── MAIN APP ─── -->
<div id="app-view" style="display:none">
  <div class="proxy-notice">⇄ All requests route through the <strong>monitoring proxy</strong> (port&nbsp;9000) — every action you take here appears in real time on the <a href="http://localhost:9000/dashboard" target="_blank">dashboard</a>.</div>
  <div class="main">
    <!-- LEFT SIDEBAR -->
    <div class="sidebar">
      <!-- Profile Card -->
      <div class="panel">
        <div class="panel-hdr"><h3>My Profile</h3></div>
        <div class="panel-body" id="profile-display"></div>
      </div>
      <!-- Update Profile -->
      <div class="panel">
        <div class="panel-hdr">
          <h3>Update Profile</h3>
          <span class="vuln-tag">API3 Mass Assignment</span>
        </div>
        <div class="panel-body">
          <details class="guide">
            <summary>📋 Demo: OWASP API3 — Mass Assignment</summary>
            <div class="gb">
              <ol>
                <li>Set <strong>Role</strong> dropdown to <strong>"admin"</strong></li>
                <li>Set <strong>Balance</strong> to any large number, e.g. <strong>99999</strong></li>
                <li>Click <strong>Save Changes</strong></li>
                <li>Watch your profile card update — role and balance both changed</li>
              </ol>
              <p class="gnote">Why it works: PUT /users/{id} passes the full request body directly to the DB update with no field filtering. Privileged fields (role, balance) should be stripped before any update is applied.</p>
            </div>
          </details>
          <div class="field"><label>Email</label><input id="u-email" type="text"></div>
          <div class="field"><label>New Password</label><input id="u-pass" type="password" placeholder="leave blank to keep"></div>
          <div class="field">
            <label>Role <span style="color:#f85149">(should be server-only!)</span></label>
            <select id="u-role">
              <option value="">-- keep current --</option>
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </div>
          <div class="field">
            <label>Balance <span style="color:#f85149">(should be server-only!)</span></label>
            <input id="u-balance" type="number" placeholder="e.g. 9999">
          </div>
          <button class="btn btn-warn" onclick="doUpdate()">Save Changes</button>
          <div class="msg" id="u-msg"></div>
        </div>
      </div>
    </div>

    <!-- RIGHT CONTENT -->
    <div style="display:flex;flex-direction:column;gap:20px">
      <!-- My Orders -->
      <div class="panel">
        <div class="panel-hdr"><h3>My Orders</h3></div>
        <div class="panel-body" id="orders-display"><span style="color:#8b949e;font-size:.87em">Loading...</span></div>
      </div>

      <!-- BOLA Explorer -->
      <div class="panel">
        <div class="panel-hdr">
          <h3>View Any User Profile</h3>
          <span class="vuln-tag">API1 BOLA</span>
        </div>
        <div class="panel-body">
          <details class="guide">
            <summary>📋 Demo: OWASP API1 — Broken Object Level Auth</summary>
            <div class="gb">
              <ol>
                <li>Log in as <strong>alice</strong> (her user ID is 1)</li>
                <li>Change the ID field to <strong>2</strong> (Bob's ID)</li>
                <li>Click <strong>Fetch User</strong> — you see Bob's email, balance, role</li>
                <li>Try ID <strong>3</strong> — you see the admin account details</li>
              </ol>
              <p class="gnote">Why it works: GET /users/{id} has no ownership check. Any valid token can retrieve any user object — the server only verifies you are logged in, not that you own the resource.</p>
            </div>
          </details>
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <input id="bola-id" type="number" min="1" max="9" value="2" style="width:80px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:7px 10px;font-size:.88em">
            <button class="btn btn-danger" style="width:auto;padding:7px 18px" onclick="doBolaFetch()">Fetch User</button>
          </div>
          <pre id="bola-result">Click "Fetch User" to demonstrate BOLA</pre>
        </div>
      </div>

      <!-- Tabs: Admin | Debug -->
      <div class="panel">
        <div class="tab-row">
          <div class="tab active" onclick="switchTab('admin')">Admin Endpoints <span class="vuln-tag">API5</span></div>
          <div class="tab" onclick="switchTab('debug')">Debug Config <span class="vuln-tag">API8</span></div>
          <div class="tab" onclick="switchTab('orders-tab')">Order BOLA <span class="vuln-tag">API1</span></div>
        </div>
        <!-- Admin Tab -->
        <div id="tab-admin" class="tab-pane active tab-content">
          <details class="guide">
            <summary>📋 Demo: OWASP API5 — Broken Function Level Auth</summary>
            <div class="gb">
              <ol>
                <li>Stay logged in as <strong>alice</strong> (regular user, not admin)</li>
                <li>Click <strong>GET /admin/users</strong> below</li>
                <li>The server returns every account including the admin's password hash</li>
                <li>Open the <a href="http://localhost:9000/dashboard" target="_blank" style="color:#58a6ff">monitor dashboard</a> — you'll see this request flagged as an anomaly</li>
              </ol>
              <p class="gnote">Why it works: the endpoint uses <code>Depends(get_current_user)</code> which only verifies the JWT is valid — it never checks <code>current_user["role"] == "admin"</code>.</p>
            </div>
          </details>
          <button class="btn btn-danger" style="margin-bottom:12px" onclick="doAdminList()">GET /admin/users</button>
          <pre id="admin-result">Click to call the admin endpoint</pre>
        </div>
        <!-- Debug Tab -->
        <div id="tab-debug" class="tab-pane tab-content">
          <details class="guide">
            <summary>📋 Demo: OWASP API8 — Security Misconfiguration (Debug Endpoint)</summary>
            <div class="gb">
              <ol>
                <li><strong>No login required</strong> — click the button below right now</li>
                <li>The server returns the JWT signing secret: <strong>"secret"</strong></li>
                <li>Use that key to forge any JWT — paste it into the Scanner to test JWT forgery</li>
                <li>It also reveals algorithm, user count, and debug mode status</li>
              </ol>
              <p class="gnote">Why it works: /debug/config has no authentication decorator and is accessible to the public internet. Debug routes must be removed or gated by environment variable before deployment.</p>
            </div>
          </details>
          <button class="btn btn-danger" style="margin-bottom:12px" onclick="doDebug()">GET /debug/config</button>
          <pre id="debug-result">Click to reveal server secrets</pre>
        </div>
        <!-- Orders BOLA Tab -->
        <div id="tab-orders-tab" class="tab-pane tab-content">
          <details class="guide">
            <summary>📋 Demo: OWASP API1 — BOLA on Order objects</summary>
            <div class="gb">
              <ol>
                <li>Logged in as <strong>alice</strong> — she owns Order #1 (Laptop)</li>
                <li>Change the ID to <strong>2</strong> — that is Bob's Phone order</li>
                <li>Try <strong>3</strong> — that is the admin's $4,999 Server order</li>
                <li>No ownership check is performed at any point</li>
              </ol>
              <p class="gnote">Why it works: GET /orders/{id} returns the order for whatever ID you supply. The server never compares <code>order.user_id</code> against <code>current_user.id</code>.</p>
            </div>
          </details>
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <input id="order-id" type="number" min="1" max="9" value="2" style="width:80px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:7px 10px;font-size:.88em">
            <button class="btn btn-danger" style="width:auto;padding:7px 18px" onclick="doOrderFetch()">Fetch Order</button>
          </div>
          <pre id="order-result">Click "Fetch Order" to demonstrate order BOLA</pre>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const API = 'http://localhost:9000';  // all requests go through monitoring proxy
let token = null;
let currentUser = null;
let _mode = 'vulnerable'; // 'vulnerable' | 'hardened'

function _xhdr() {
  // Adds X-Target header when in hardened mode so the proxy routes to hardened-api:8001
  return _mode === 'hardened' ? {'X-Target': 'hardened'} : {};
}

function setMode(m) {
  _mode = m;
  const vBtn = document.getElementById('mode-vuln-btn');
  const hBtn = document.getElementById('mode-hard-btn');
  const badge = document.getElementById('nav-badge');
  if (m === 'vulnerable') {
    vBtn.style.background = '#f85149'; vBtn.style.color = '#fff';
    hBtn.style.background = 'transparent'; hBtn.style.color = '#8b949e';
    badge.textContent = 'INTENTIONALLY VULNERABLE';
    badge.style.background = 'rgba(248,81,73,.18)'; badge.style.color = '#f85149';
  } else {
    hBtn.style.background = '#3fb950'; hBtn.style.color = '#fff';
    vBtn.style.background = 'transparent'; vBtn.style.color = '#8b949e';
    badge.textContent = 'HARDENED MODE';
    badge.style.background = 'rgba(63,185,80,.18)'; badge.style.color = '#3fb950';
  }
  if (currentUser) { loadProfile(); loadOrders(); }
}

function show(msg, type, elId) {
  const el = document.getElementById(elId);
  el.className = 'msg ' + type;
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', 5000);
}

function fill(u, p) {
  document.getElementById('l-user').value = u;
  document.getElementById('l-pass').value = p;
}

async function doLogin() {
  const username = document.getElementById('l-user').value.trim();
  const password = document.getElementById('l-pass').value;
  if (!username) return show('Enter a username', 'err', 'l-msg');
  try {
    const r = await fetch(API + '/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ..._xhdr()},
      body: JSON.stringify({username, password})
    });
    const data = await r.json();
    if (!r.ok) {
      show(data.detail || 'Login failed', 'err', 'l-msg');
      return;
    }
    token = data.access_token;
    // API8: the verbose error from the server already leaked if you entered wrong — decoded JWT shows user info
    const payload = JSON.parse(atob(token.split('.')[1]));
    currentUser = { id: parseInt(payload.sub), username: payload.username, role: payload.role };
    document.getElementById('login-view').style.display = 'none';
    document.getElementById('app-view').style.display = 'block';
    document.getElementById('nav-user').textContent = username + ' (' + payload.role + ')';
    document.getElementById('logout-btn').style.display = '';
    loadProfile();
    loadOrders();
  } catch(e) { show('Network error', 'err', 'l-msg'); }
}

function logout() {
  token = null; currentUser = null;
  document.getElementById('app-view').style.display = 'none';
  document.getElementById('login-view').style.display = 'block';
  document.getElementById('nav-user').textContent = '';
  document.getElementById('logout-btn').style.display = 'none';
  document.getElementById('l-pass').value = '';
}

function authHdr() {
  return {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', ..._xhdr()};
}

async function loadProfile() {
  const r = await fetch(API + '/users/' + currentUser.id, {headers: authHdr()});
  const u = await r.json();
  const role_color = u.role === 'admin' ? 'red' : 'green';
  document.getElementById('profile-display').innerHTML = `
    <div class="kv"><span class="k">ID</span><span class="v blue">#${u.id}</span></div>
    <div class="kv"><span class="k">Username</span><span class="v">${u.username}</span></div>
    <div class="kv"><span class="k">Email</span><span class="v">${u.email}</span></div>
    <div class="kv"><span class="k">Role</span><span class="v ${role_color}">${u.role}</span></div>
    <div class="kv"><span class="k">Balance</span><span class="v yellow">$${u.balance?.toFixed(2)}</span></div>
  `;
  document.getElementById('u-email').value = u.email || '';
}

async function doUpdate() {
  const body = {};
  const email = document.getElementById('u-email').value.trim();
  const pass  = document.getElementById('u-pass').value;
  const role  = document.getElementById('u-role').value;
  const bal   = document.getElementById('u-balance').value;
  if (email) body.email = email;
  if (pass)  body.password = pass;
  if (role)  body.role = role;
  if (bal !== '') body.balance = parseFloat(bal);
  if (!Object.keys(body).length) return show('Nothing to update', 'warn', 'u-msg');
  const r = await fetch(API + '/users/' + currentUser.id, {
    method:'PUT', headers: authHdr(), body: JSON.stringify(body)
  });
  const data = await r.json();
  if (r.ok) {
    show('Profile updated! Role/balance changes accepted by server (API3 flaw).', 'warn', 'u-msg');
    loadProfile();
  } else {
    show(data.detail || 'Update failed', 'err', 'u-msg');
  }
}

async function loadOrders() {
  const r = await fetch(API + '/users/' + currentUser.id + '/orders', {headers: authHdr()});
  const orders = await r.json();
  const el = document.getElementById('orders-display');
  if (!orders.length) { el.innerHTML = '<span style="color:#8b949e;font-size:.87em">No orders found.</span>'; return; }
  el.innerHTML = orders.map(o => `
    <div class="order-card">
      <div class="item">${o.item} — <span class="status-${o.status}">${o.status}</span></div>
      <div class="meta">Order #${o.id} &nbsp;·&nbsp; $${o.price?.toFixed(2)}</div>
    </div>
  `).join('');
}

async function doBolaFetch() {
  const id = document.getElementById('bola-id').value;
  const r = await fetch(API + '/users/' + id, {headers: authHdr()});
  const data = await r.json();
  document.getElementById('bola-result').textContent = JSON.stringify(data, null, 2);
}

async function doAdminList() {
  const r = await fetch(API + '/admin/users', {headers: authHdr()});
  const data = await r.json();
  document.getElementById('admin-result').textContent = JSON.stringify(data, null, 2);
}

async function doDebug() {
  const r = await fetch(API + '/debug/config', {headers: _xhdr()});
  const data = await r.json();
  document.getElementById('debug-result').textContent = JSON.stringify(data, null, 2);
}

async function doOrderFetch() {
  const id = document.getElementById('order-id').value;
  const r = await fetch(API + '/orders/' + id, {headers: authHdr()});
  const data = await r.json();
  document.getElementById('order-result').textContent = JSON.stringify(data, null, 2);
}

function switchTab(name) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.currentTarget.classList.add('active');
}
</script>
</body>
</html>"""
