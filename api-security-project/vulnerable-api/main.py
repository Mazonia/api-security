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


class OrderCreate(BaseModel):
    item: str
    price: float


@app.post("/orders")
def create_order(req: OrderCreate, current_user: dict = Depends(get_current_user)):
    new_id = max(orders_db.keys()) + 1 if orders_db else 1
    orders_db[new_id] = {
        "id": new_id,
        "user_id": current_user["id"],
        "item": req.item,
        "price": req.price,
        "status": "pending"
    }
    return orders_db[new_id]


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
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🔒 MazAPI Security Storefront</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#070b13;
  --surf:#0e1424;
  --surf2:#171e35;
  --border:rgba(255,255,255,0.08);
  --border-glow:rgba(99,102,241,0.35);
  --text:#f3f4f6;
  --muted:#9ca3af;
  --emerald:#10b981;
  --indigo:#6366f1;
  --rose:#f43f5e;
  --amber:#f59e0b;
  --radius:16px;
  --shadow-glass:0 8px 32px 0 rgba(0,0,0,0.37);
  --glass-blur:blur(16px) saturate(180%);
  --input-bg:#070b13;
  --input-border:rgba(255,255,255,0.15);
  --card-hover:rgba(99,102,241,0.06);
}
[data-theme="light"]{
  --bg:#f3f4f6;
  --surf:#ffffff;
  --surf2:#f9fafb;
  --border:rgba(0,0,0,0.08);
  --border-glow:rgba(99,102,241,0.4);
  --text:#1f2937;
  --muted:#6b7280;
  --input-bg:#ffffff;
  --input-border:rgba(0,0,0,0.12);
  --shadow-glass:0 8px 24px 0 rgba(149,157,165,0.12);
  --card-hover:rgba(99,102,241,0.04);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5;overflow-x:hidden;transition:background 0.2s,color 0.2s}

/* Navigation bar */
nav{background:var(--surf);backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:16px;height:75px;box-shadow:var(--shadow-glass);position:sticky;top:0;z-index:100;transition:background 0.2s}
nav .logo{font-family:'Outfit',sans-serif;color:var(--emerald);font-weight:800;font-size:1.45em;letter-spacing:-0.02em;display:flex;align-items:center;gap:8px}
nav .badge{background:rgba(244,63,94,0.12);color:var(--rose);border:1px solid rgba(244,63,94,0.3);border-radius:20px;padding:4px 14px;font-size:0.75em;font-weight:800;letter-spacing:0.02em}
.nav-links{display:flex;gap:8px;margin:0 12px}
.nav-tool-link{color:var(--muted);font-size:0.85em;text-decoration:none;padding:7px 16px;border:1px solid var(--border);border-radius:20px;transition:all 0.18s;font-weight:700}
.nav-tool-link:hover{color:var(--indigo);border-color:var(--indigo);background:var(--card-hover)}
.nav-right{display:flex;align-items:center;gap:12px;margin-left:auto}

/* Styled buttons */
.btn{padding:10px 18px;border:none;border-radius:20px;cursor:pointer;font-size:0.86em;font-weight:700;font-family:inherit;transition:all 0.18s;text-align:center;display:inline-block;box-shadow:0 2px 6px rgba(0,0,0,0.1)}
.btn-primary{background:linear-gradient(135deg,#10b981,#059669);color:#fff;box-shadow:0 2px 10px rgba(16,185,129,0.25)}.btn-primary:hover{opacity:0.95;transform:translateY(-1px);box-shadow:0 4px 14px rgba(16,185,129,0.35)}
.btn-danger{background:linear-gradient(135deg,#f43f5e,#e11d48);color:#fff;box-shadow:0 2px 10px rgba(244,63,94,0.25)}.btn-danger:hover{opacity:0.95;transform:translateY(-1px);box-shadow:0 4px 14px rgba(244,63,94,0.35)}
.btn-secondary{background:var(--surf2);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{border-color:var(--indigo);color:var(--indigo);background:var(--card-hover)}
.btn-warn{background:rgba(245,158,11,0.1);color:var(--amber);border:1px solid rgba(245,158,11,0.3)}.btn-warn:hover{background:rgba(245,158,11,0.2)}

/* Theme selector toggle */
#theme-toggle-btn{background:var(--surf2);border:1px solid var(--border);color:var(--text);cursor:pointer;font-size:0.85em;padding:6px 14px;border-radius:20px;font-weight:700;transition:all 0.15s}
#theme-toggle-btn:hover{border-color:var(--indigo);color:var(--indigo)}

/* Layout grid */
.main{max-width:1300px;margin:0 auto;padding:32px 24px;display:flex;flex-direction:column;gap:32px}
.storefront-grid{display:grid;grid-template-columns:1.8fr 1fr;gap:32px}
.lab-section{width:100%}

/* Panel styling */
.panel{background:var(--surf);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow-glass);transition:all 0.2s ease}
.panel:hover{border-color:var(--border-glow)}
.panel-hdr{padding:18px 24px;border-bottom:1px solid var(--border);background:var(--surf2);display:flex;justify-content:space-between;align-items:center}
.panel-hdr h3{font-family:'Outfit',sans-serif;font-size:1.05em;font-weight:700;color:var(--text)}
.vuln-tag{background:rgba(244,63,94,0.12);color:var(--rose);border:1px solid rgba(244,63,94,0.35);border-radius:20px;padding:3px 10px;font-size:0.72em;font-weight:700}
.panel-body{padding:20px 24px}

/* Advanced designed form controls */
.field{margin-bottom:18px}
.field label{display:block;font-size:0.75em;color:var(--muted);margin-bottom:6px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em}
.field input, .field select, .field textarea,
.search-container input, .bola-form input, .order-form input {
  width: 100%;
  background: var(--input-bg);
  border: 1.5px solid var(--input-border);
  border-radius: 8px;
  color: var(--text);
  padding: 11px 14px;
  font-size: 0.9em;
  font-family: inherit;
  transition: all 0.2s ease;
  outline: none;
  box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
}
.field input:focus, .field select:focus, .field textarea:focus,
.search-container input:focus, .bola-form input:focus, .order-form input:focus {
  border-color: var(--indigo);
  box-shadow: 0 0 0 4px rgba(99,102,241,0.15), inset 0 2px 4px rgba(0,0,0,0.05);
  background: var(--surf);
}
.field input[readonly]{opacity:0.6;cursor:not-allowed}

/* Message styling */
.msg{margin-top:14px;padding:11px 16px;border-radius:8px;font-size:0.85em;display:none;font-weight:600}
.msg.ok{background:rgba(16,185,129,0.1);color:var(--emerald);border:1px solid rgba(16,185,129,0.25)}
.msg.err{background:rgba(244,63,94,0.1);color:var(--rose);border:1px solid rgba(244,63,94,0.25)}

/* Key-Value tables */
.kv{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);font-size:0.88em}
.kv:last-child{border:none}
.kv .k{color:var(--muted);font-weight:600}
.kv .v{color:var(--text);font-weight:700;word-break:break-all;text-align:right;max-width:60%}
.kv .v.red{color:var(--rose)}.kv .v.green{color:var(--emerald)}.kv .v.yellow{color:var(--amber)}.kv .v.blue{color:var(--indigo)}

/* Order Receipt Cards */
.order-card{background:rgba(0,0,0,0.15);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.order-card:last-child{margin-bottom:0}
.order-card .item{font-weight:700;font-size:0.95em;color:var(--text)}
.order-card .meta{font-size:0.8em;color:var(--muted);margin-top:2px}
.status-shipped{background:rgba(16,185,129,0.12);color:var(--emerald);border:1px solid rgba(16,185,129,0.3);padding:3px 10px;border-radius:12px;font-size:0.75em;font-weight:800}
.status-pending{background:rgba(245,158,11,0.12);color:var(--amber);border:1px solid rgba(245,158,11,0.3);padding:3px 10px;border-radius:12px;font-size:0.75em;font-weight:800}
.status-delivered{background:rgba(99,102,241,0.12);color:var(--indigo);border:1px solid rgba(99,102,241,0.3);padding:3px 10px;border-radius:12px;font-size:0.75em;font-weight:800}

/* Login screen redesigned */
.login-view-container{display:flex;min-height:90vh;align-items:center;justify-content:center;padding:40px 20px}
.login-wrap{width:100%;max-width:480px;background:var(--surf);border:1px solid var(--border);border-radius:24px;padding:36px;box-shadow:var(--shadow-glass)}
.login-wrap h2{font-family:'Outfit',sans-serif;color:var(--emerald);font-size:1.9em;font-weight:800;margin-bottom:8px;letter-spacing:-0.03em;text-align:center}
.login-wrap p{color:var(--muted);font-size:0.92em;margin-bottom:24px;text-align:center}
.accounts{background:rgba(0,0,0,0.15);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:20px}
.accounts p{font-size:.82em;color:var(--muted);margin-bottom:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;text-align:left}
.acc{display:flex;gap:10px;margin-bottom:10px;align-items:center;font-size:.85em;justify-content:space-between;border-bottom:1px solid var(--border);padding-bottom:8px}
.acc:last-child{border:none;padding-bottom:0}
.acc span{color:var(--text);font-weight:600}
.acc button{background:var(--surf2);border:1px solid var(--border);color:var(--text);border-radius:12px;padding:4px 12px;cursor:pointer;font-size:.8em;font-weight:700;transition:all 0.18s}
.acc button:hover{border-color:var(--indigo);color:var(--indigo);background:var(--card-hover)}
.warn-banner{background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:.84em;color:var(--amber);line-height:1.4}

/* Store catalog grid */
.catalog-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.search-container{position:relative;width:260px}
.products-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:20px}
.product-card{background:var(--surf);border:1px solid var(--border);border-radius:var(--radius);padding:20px;display:flex;flex-direction:column;gap:12px;position:relative;transition:all 0.25s ease;box-shadow:var(--shadow-glass)}
.product-card:hover{transform:translateY(-3px);border-color:var(--border-glow);box-shadow:0 8px 24px rgba(99,102,241,0.12)}
.product-card .card-badge{position:absolute;top:12px;right:12px;background:rgba(16,185,129,0.12);color:var(--emerald);border:1px solid rgba(16,185,129,0.25);border-radius:20px;padding:2px 8px;font-size:0.68em;font-weight:800}
.product-card .title{font-family:'Outfit',sans-serif;font-weight:800;font-size:1.15em;color:var(--text);margin-top:6px}
.product-card .rating{font-size:0.8em;color:var(--amber);display:flex;gap:2px}
.product-card .desc{font-size:0.85em;color:var(--muted);line-height:1.45;flex:1}
.product-card .price-row{display:flex;justify-content:space-between;align-items:center;margin-top:4px}
.product-card .price{font-family:'Outfit',sans-serif;font-weight:800;font-size:1.3em;color:var(--amber)}

/* Cart panel */
.cart-summary{background:rgba(16,185,129,0.03);border:1.5px dashed rgba(16,185,129,0.3);border-radius:var(--radius);padding:20px;display:flex;flex-direction:column;gap:14px}
.cart-header{font-weight:800;font-size:0.95em;text-transform:uppercase;color:var(--emerald);letter-spacing:0.04em}
.cart-row{display:flex;justify-content:space-between;font-size:0.9em;font-weight:700}
.cart-list{max-height:180px;overflow-y:auto;margin:6px 0}

/* Labs and Consoles */
.tab-row{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:18px}
.tab{padding:12px 18px;cursor:pointer;font-size:.85em;color:var(--muted);border-bottom:2px solid transparent;font-weight:700;transition:all 0.18s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--indigo);border-bottom-color:var(--indigo)}
.tab-content{padding:0}
.tab-pane{display:none}.tab-pane.active{display:block}
details.guide{margin-bottom:16px;background:rgba(0,0,0,0.15);border:1px solid var(--border);border-radius:10px}
details.guide summary{padding:10px 14px;cursor:pointer;font-size:.82em;color:var(--amber);font-weight:700;user-select:none;display:flex;align-items:center;gap:6px}
details.guide summary::before{content:"▶";font-size:.75em;transition:transform .15s;display:inline-block}
details[open].guide summary::before{transform:rotate(90deg)}
details.guide .gb{padding:12px 16px 14px;border-top:1px solid var(--border)}
details.guide ol{padding-left:16px;margin-bottom:10px}
details.guide li{font-size:.84em;color:var(--text);line-height:1.7}
details.guide li strong{color:var(--indigo)}
details.guide .gnote{font-size:.8em;color:var(--muted);line-height:1.5;border-top:1px solid var(--border);margin-top:10px;padding-top:10px}

pre{background:#040713;border:1px solid var(--border);border-radius:8px;padding:14px;font-size:.82em;color:#79c0ff;overflow:auto;max-height:260px;font-family:'Fira Code',monospace;white-space:pre-wrap;word-break:break-all}
</style>
</head>
<body>

<nav>
  <span class="logo">🔒 ShopApp</span>
  <span id="nav-badge" class="badge">INTENTIONALLY VULNERABLE</span>
  <div class="nav-links">
    <a class="nav-tool-link" href="http://localhost:9000/dashboard" target="_blank">Monitor Dashboard</a>
    <a class="nav-tool-link" href="http://localhost:9000/scan-ui" target="_blank">Security Scanner</a>
  </div>
  <!-- API mode toggle -->
  <div style="display:flex;align-items:center;gap:4px;background:var(--surf2);border:1px solid var(--border);border-radius:20px;padding:4px;margin-left:12px">
    <button id="mode-vuln-btn" onclick="setMode('vulnerable')"
      style="padding:5px 16px;border:none;border-radius:20px;font-size:.78em;font-weight:800;cursor:pointer;background:#f43f5e;color:#fff;transition:all 0.15s">
      Vulnerable
    </button>
    <button id="mode-hard-btn" onclick="setMode('hardened')"
      style="padding:5px 16px;border:none;border-radius:20px;font-size:.78em;font-weight:800;cursor:pointer;background:transparent;color:var(--muted);transition:all 0.15s">
      Hardened
    </button>
  </div>
  <div class="nav-right">
    <span id="nav-user" style="font-size:.88em;color:var(--text);font-weight:700"></span>
    <button id="theme-toggle-btn" onclick="toggleShopTheme()">☀️ Light</button>
    <button id="logout-btn" onclick="logout()" style="display:none;padding:7px 16px;background:transparent;border:1px solid var(--border);border-radius:20px;color:var(--muted);cursor:pointer;font-size:.82em;font-weight:700">Logout</button>
  </div>
</nav>

<!-- ─── LOGIN ─── -->
<div id="login-view">
  <div class="login-view-container">
    <div class="login-wrap">
      <h2>Sign in to ShopApp</h2>
      <p>Demonstration storefront app for the CY384 API Security Lab.</p>
      <div class="warn-banner">⚠️ All data is generated synthetically. This app exists strictly to demonstrate real API vulnerabilities in an isolated sandbox.</div>
      <div class="accounts">
        <p>Select a Practice Account:</p>
        <div class="acc"><span>Alice (Regular User)</span><button onclick="fill('alice','alice123')">Select</button></div>
        <div class="acc"><span>Bob (Regular User)</span><button onclick="fill('bob','bob123')">Select</button></div>
        <div class="acc"><span>Admin Account</span><button onclick="fill('admin','admin123')">Select</button></div>
      </div>
      <div class="panel">
        <div class="panel-body" style="padding: 16px 0 0 0">
          <div class="field"><label>Username</label><input id="l-user" type="text" placeholder="e.g. alice"></div>
          <div class="field"><label>Password</label><input id="l-pass" type="password" placeholder="••••••••"></div>
          <button class="btn btn-primary" onclick="doLogin()">Sign In</button>
          <div class="msg" id="l-msg"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ─── MAIN APP ─── -->
<div id="app-view" style="display:none">
  <div class="main">
    
    <!-- TOP ROW: Routing and Status -->
    <div class="panel" style="border-left:4px solid var(--indigo)">
      <div class="panel-body" style="padding:16px;font-size:0.88em;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div style="font-weight:600">⇄ Active Gateway Routing: <span style="color:var(--indigo);font-weight:800">Monitoring ML Proxy (Port 9000)</span></div>
        <div id="blocking-status-badge" style="background:rgba(248,81,73,0.12);color:var(--rose);border:1px solid rgba(248,81,73,0.3);padding:6px 16px;border-radius:20px;font-size:0.85em;font-weight:bold;transition:all 0.3s">
          Auto-Blocking: INACTIVE (Monitoring Only)
        </div>
      </div>
    </div>

    <!-- MIDDLE SECTION: E-Commerce Storefront Layout -->
    <div class="storefront-grid">
      <!-- LEFT COLUMN: Product Catalog -->
      <div class="panel">
        <div class="panel-hdr">
          <h3>E-Commerce Hardware Catalog</h3>
          <div class="search-container">
            <input type="text" id="store-search" placeholder="Search catalog..." oninput="filterStoreProducts()" style="padding:7px 14px;font-size:0.85em">
          </div>
        </div>
        <div class="panel-body">
          <p style="color:var(--muted);font-size:0.85em;margin-bottom:20px">Purchase premium security equipment. Your transaction will post to your order feed via the secure proxy.</p>
          <div class="products-grid" id="catalog-products-list">
            <div class="product-card" data-title="fido2 cyberkey">
              <span class="card-badge">HOT</span>
              <div class="title">Fido2 CyberKey</div>
              <div class="rating">⭐⭐⭐⭐⭐ <span>(42)</span></div>
              <div class="desc">Cryptographic hardware token supporting passwordless WebAuthn and security login.</div>
              <div class="price-row">
                <span class="price">$49.99</span>
                <button class="btn btn-secondary" style="border-radius:12px;padding:6px 12px;font-size:0.8em" onclick="selectProduct('Fido2 CyberKey', 49.99)">Add to Cart</button>
              </div>
            </div>
            <div class="product-card" data-title="pineapple wifi router">
              <span class="card-badge">PENTEST</span>
              <div class="title">Pineapple WiFi Router</div>
              <div class="rating">⭐⭐⭐⭐⭐ <span>(18)</span></div>
              <div class="desc">Hotspot auditing platform for wireless penetration testing and monitoring.</div>
              <div class="price-row">
                <span class="price">$199.99</span>
                <button class="btn btn-secondary" style="border-radius:12px;padding:6px 12px;font-size:0.8em" onclick="selectProduct('Pineapple WiFi Router', 199.99)">Add to Cart</button>
              </div>
            </div>
            <div class="product-card" data-title="proxytap hardware sniffer">
              <span class="card-badge">POPULAR</span>
              <div class="title">ProxyTap Hardware Sniffer</div>
              <div class="rating">⭐⭐⭐⭐☆ <span>(31)</span></div>
              <div class="desc">In-line ethernet packet tap for transparent packet analysis.</div>
              <div class="price-row">
                <span class="price">$99.99</span>
                <button class="btn btn-secondary" style="border-radius:12px;padding:6px 12px;font-size:0.8em" onclick="selectProduct('ProxyTap Sniffer', 99.99)">Add to Cart</button>
              </div>
            </div>
            <div class="product-card" data-title="cyberlab secure gateway">
              <span class="card-badge">ENTERPRISE</span>
              <div class="title">CyberLab Secure Gateway</div>
              <div class="rating">⭐⭐⭐⭐⭐ <span>(9)</span></div>
              <div class="desc">Rackmount hardware firewall with integrated intrusion prevention.</div>
              <div class="price-row">
                <span class="price">$999.99</span>
                <button class="btn btn-secondary" style="border-radius:12px;padding:6px 12px;font-size:0.8em" onclick="selectProduct('Secure Gateway', 999.99)">Add to Cart</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- RIGHT COLUMN: Cart & Profile Information -->
      <div style="display:flex;flex-direction:column;gap:24px">
        <!-- Multi-Item Shopping Cart -->
        <div class="cart-summary panel">
          <div class="cart-header">🛒 Shopping Cart (<span id="cart-count">0</span>)</div>
          <div class="cart-list" id="cart-items-list">
            <div style="color:var(--muted);font-size:0.82em;text-align:center;padding:12px 0;">Your cart is empty</div>
          </div>
          <div style="border-top:1px dashed var(--border);padding-top:12px">
            <div class="cart-row">
              <span>Checkout Price:</span>
              <span id="cart-total" style="color:var(--amber);font-size:1.1em">$0.00</span>
            </div>
          </div>
          <button class="btn btn-primary" id="checkout-btn" style="margin-top:6px;width:100%" onclick="checkoutCart()" disabled>Confirm Purchase</button>
        </div>

        <!-- Profile Card -->
        <div class="panel">
          <div class="panel-hdr"><h3>My Profile</h3></div>
          <div class="panel-body" id="profile-display"></div>
        </div>

        <!-- My Orders -->
        <div class="panel">
          <div class="panel-hdr"><h3>My Order Receipts</h3></div>
          <div class="panel-body" id="orders-display" style="max-height:240px;overflow-y:auto"><span style="color:var(--muted);font-size:.87em">Loading orders...</span></div>
        </div>
      </div>
    </div>

    <!-- BOTTOM ROW: Labs & Dev Panel -->
    <div class="lab-section">
      <div class="panel">
        <div class="panel-hdr">
          <h3 style="color:var(--amber)">🛠️ API Practice Lab &amp; Vulnerability Consoles</h3>
        </div>
        
        <div class="tab-row" style="background:var(--surf2);padding:0 12px">
          <div class="tab active" onclick="switchTab('admin', this)">Admin Panel <span class="vuln-tag">API5 BFLA</span></div>
          <div class="tab" onclick="switchTab('debug', this)">Server Configuration <span class="vuln-tag">API8 Misconfig</span></div>
          <div class="tab" onclick="switchTab('bola-profiles', this)">Profile BOLA <span class="vuln-tag">API1</span></div>
          <div class="tab" onclick="switchTab('bola-orders', this)">Order BOLA <span class="vuln-tag">API1</span></div>
          <div class="tab" onclick="switchTab('mass-assignment', this)">Update Settings <span class="vuln-tag">API3 Mass Assignment</span></div>
        </div>

        <div class="panel-body">
          <!-- Admin Tab -->
          <div id="tab-admin" class="tab-pane active">
            <details class="guide">
              <summary>📋 Broken Function Level Authorization Walkthrough</summary>
              <div class="gb">
                <ol>
                  <li>Login as user <strong>alice</strong> (non-privileged)</li>
                  <li>Click <strong>Request Admin Accounts</strong></li>
                  <li>The server will leak every registered user profile, including password hashes.</li>
                </ol>
                <p class="gnote">Explanation: The endpoint <code>/admin/users</code> accepts any valid token, without validating the user's role claim. Route handlers must restrict access based on active roles.</p>
              </div>
            </details>
            <button class="btn btn-danger" style="margin-bottom:12px;width:auto" onclick="doAdminList()">Request Admin Accounts</button>
            <pre id="admin-result">Click button to execute GET /admin/users</pre>
          </div>

          <!-- Debug Tab -->
          <div id="tab-debug" class="tab-pane">
            <details class="guide">
              <summary>📋 Security Misconfiguration Walkthrough</summary>
              <div class="gb">
                <ol>
                  <li>No authentication headers are required for this check.</li>
                  <li>Click <strong>Request Debug Configuration</strong>.</li>
                  <li>The server reveals its JWT signing secret key: <code>"secret"</code>.</li>
                </ol>
                <p class="gnote">Explanation: The debug configuration route is exposed without access controls. Debug tools and variables must be stripped or gated behind environment limits before going live.</p>
              </div>
            </details>
            <button class="btn btn-danger" style="margin-bottom:12px;width:auto" onclick="doDebug()">Request Debug Configuration</button>
            <pre id="debug-result">Click button to execute GET /debug/config</pre>
          </div>

          <!-- Profile BOLA Tab -->
          <div id="tab-bola-profiles" class="tab-pane">
            <details class="guide">
              <summary>📋 Profile BOLA Walkthrough</summary>
              <div class="gb">
                <ol>
                  <li>Login as <strong>alice</strong> (user ID #1)</li>
                  <li>Modify the Target User ID field to <strong>2</strong> (Bob) or <strong>3</strong> (Admin)</li>
                  <li>Click <strong>Fetch Profile</strong> to load Bob's private balance and SSN details.</li>
                </ol>
                <p class="gnote">Explanation: <code>GET /users/{id}</code> validates that the caller is logged in, but fails to check if the caller is authorized to view this specific user's database entry.</p>
              </div>
            </details>
            <div class="bola-form" style="display:flex;gap:8px;margin-bottom:12px;max-width:240px">
              <input id="bola-id" type="number" min="1" max="9" value="2" placeholder="User ID">
              <button class="btn btn-danger" style="width:auto" onclick="doBolaFetch()">Fetch Profile</button>
            </div>
            <pre id="bola-result">Select User ID and click Fetch Profile</pre>
          </div>

          <!-- Order BOLA Tab -->
          <div id="tab-bola-orders" class="tab-pane">
            <details class="guide">
              <summary>📋 Order BOLA Walkthrough</summary>
              <div class="gb">
                <ol>
                  <li>Alice owns Order Receipt #1.</li>
                  <li>Set the Order ID field to <strong>2</strong> (Bob's order) or <strong>3</strong> (Admin's order).</li>
                  <li>Click <strong>Fetch Order Detail</strong>. The server returns full order information without ownership checks.</li>
                </ol>
                <p class="gnote">Explanation: <code>GET /orders/{id}</code> displays orders without comparing the order's owner ID against the requester's user ID.</p>
              </div>
            </details>
            <div class="order-form" style="display:flex;gap:8px;margin-bottom:12px;max-width:240px">
              <input id="order-id" type="number" min="1" max="9" value="2" placeholder="Order ID">
              <button class="btn btn-danger" style="width:auto" onclick="doOrderFetch()">Fetch Order Detail</button>
            </div>
            <pre id="order-result">Select Order ID and click Fetch Order Detail</pre>
          </div>

          <!-- Mass Assignment Tab -->
          <div id="tab-mass-assignment" class="tab-pane">
            <details class="guide">
              <summary>📋 Mass Assignment Walkthrough</summary>
              <div class="gb">
                <ol>
                  <li>Set <strong>Role</strong> to <strong>"admin"</strong></li>
                  <li>Set <strong>Balance</strong> to <strong>99999</strong></li>
                  <li>Click <strong>Save Changes</strong></li>
                  <li>Verify your role and balance updated on the profile card.</li>
                </ol>
                <p class="gnote">Explanation: <code>PUT /users/{id}</code> updates database fields directly from client input without filtering. Privileged parameters (role, balance) should be blocked at the controller level.</p>
              </div>
            </details>
            <div style="max-width:480px">
              <div class="field"><label>Email Address</label><input id="u-email" type="text" placeholder="new email"></div>
              <div class="field"><label>New Password</label><input id="u-pass" type="password" placeholder="Leave blank to keep"></div>
              <div class="field">
                <label>Role <span style="color:var(--rose)">(Server-only!)</span></label>
                <select id="u-role">
                  <option value="">-- keep current --</option>
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <div class="field">
                <label>Balance <span style="color:var(--rose)">(Server-only!)</span></label>
                <input id="u-balance" type="number" placeholder="e.g. 1000">
              </div>
              <button class="btn btn-warn" onclick="doUpdate()">Save Changes</button>
              <div class="msg" id="u-msg"></div>
            </div>
          </div>

        </div>
      </div>
    </div>

  </div>
</div>

<script>
const API = 'http://localhost:9000';
let token = null;
let currentUser = null;
let _mode = 'vulnerable';
let cart = [];

function _xhdr() {
  return _mode === 'hardened' ? {'X-Target': 'hardened'} : {};
}

function setMode(m) {
  _mode = m;
  const vBtn = document.getElementById('mode-vuln-btn');
  const hBtn = document.getElementById('mode-hard-btn');
  const badge = document.getElementById('nav-badge');
  if (m === 'vulnerable') {
    vBtn.style.background = '#f43f5e'; vBtn.style.color = '#fff';
    hBtn.style.background = 'transparent'; hBtn.style.color = 'var(--muted)';
    badge.textContent = 'INTENTIONALLY VULNERABLE';
    badge.style.background = 'rgba(244,63,94,0.12)'; badge.style.color = 'var(--rose)';
    badge.style.borderColor = 'rgba(244,63,94,0.3)';
  } else {
    hBtn.style.background = '#10b981'; hBtn.style.color = '#fff';
    vBtn.style.background = 'transparent'; vBtn.style.color = 'var(--muted)';
    badge.textContent = 'HARDENED MODE';
    badge.style.background = 'rgba(16,185,129,0.12)'; badge.style.color = 'var(--emerald)';
    badge.style.borderColor = 'rgba(16,185,129,0.3)';
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
    const payload = JSON.parse(atob(token.split('.')[1]));
    currentUser = { id: parseInt(payload.sub), username: payload.username, role: payload.role };
    document.getElementById('login-view').style.display = 'none';
    document.getElementById('app-view').style.display = 'block';
    document.getElementById('nav-user').textContent = username + ' (' + payload.role + ')';
    document.getElementById('logout-btn').style.display = '';
    loadProfile();
    loadOrders();
    checkBlockingStatus();
  } catch(e) { show('Network error', 'err', 'l-msg'); }
}

function logout() {
  token = null; currentUser = null; cart = [];
  document.getElementById('app-view').style.display = 'none';
  document.getElementById('login-view').style.display = 'block';
  document.getElementById('nav-user').textContent = '';
  document.getElementById('logout-btn').style.display = 'none';
  document.getElementById('l-pass').value = '';
  renderCart();
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

async function loadOrders() {
  const r = await fetch(API + '/users/' + currentUser.id + '/orders', {headers: authHdr()});
  const orders = await r.json();
  const el = document.getElementById('orders-display');
  if (!orders.length) { el.innerHTML = '<span style="color:var(--muted);font-size:.87em">No orders found.</span>'; return; }
  el.innerHTML = orders.map(o => `
    <div class="order-card">
      <div>
        <div class="item">${o.item}</div>
        <div class="meta">Receipt #${o.id} &nbsp;|&nbsp; Price: $${o.price.toFixed(2)}</div>
      </div>
      <span class="status-${o.status || 'pending'}">${(o.status || 'pending').toUpperCase()}</span>
    </div>
  `).join('');
}

function selectProduct(name, price) {
  cart.push({ item: name, price: price });
  renderCart();
}

function removeFromCart(index) {
  cart.splice(index, 1);
  renderCart();
}

function renderCart() {
  const listEl = document.getElementById('cart-items-list');
  const countEl = document.getElementById('cart-count');
  const totalEl = document.getElementById('cart-total');
  const btn = document.getElementById('checkout-btn');
  
  if (cart.length === 0) {
    listEl.innerHTML = '<div style="color:var(--muted);font-size:0.82em;text-align:center;padding:12px 0;">Your cart is empty</div>';
    countEl.textContent = '0';
    totalEl.textContent = '$0.00';
    btn.disabled = true;
    return;
  }
  
  let total = 0;
  listEl.innerHTML = cart.map((item, idx) => {
    total += item.price;
    return `
      <div style="display:flex;justify-content:space-between;align-items:center;background:rgba(0,0,0,0.15);padding:8px 12px;border-radius:8px;margin-bottom:8px;font-size:0.84em;border:1px solid var(--border)">
        <div>
          <div style="font-weight:700;color:var(--text)">${item.item}</div>
          <div style="color:var(--amber);font-weight:700;margin-top:2px">$${item.price.toFixed(2)}</div>
        </div>
        <button onclick="removeFromCart(${idx})" style="background:transparent;border:none;color:var(--rose);cursor:pointer;font-size:1.15em;font-weight:bold;padding:4px 8px">✕</button>
      </div>
    `;
  }).join('');
  
  countEl.textContent = cart.length;
  totalEl.textContent = '$' + total.toFixed(2);
  btn.disabled = false;
}

async function checkoutCart() {
  if (cart.length === 0) return;
  const btn = document.getElementById('checkout-btn');
  btn.disabled = true;
  
  try {
    let successCount = 0;
    for (const cartItem of cart) {
      const r = await fetch(API + '/orders', {
        method: 'POST',
        headers: authHdr(),
        body: JSON.stringify({ item: cartItem.item, price: cartItem.price })
      });
      const data = await r.json();
      if (!r.ok) {
        alert("Order Blocked for " + cartItem.item + ": " + (data.detail || "Request blocked by ML Proxy"));
        break; 
      }
      successCount++;
    }
    
    if (successCount > 0) {
      alert(`Successfully placed ${successCount} order(s)!`);
      cart = [];
      renderCart();
      loadProfile();
      loadOrders();
    }
  } catch (e) {
    alert("Network error: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

function filterStoreProducts() {
  const query = document.getElementById('store-search').value.toLowerCase().trim();
  const cards = document.querySelectorAll('#catalog-products-list .product-card');
  cards.forEach(card => {
    const title = card.getAttribute('data-title') || '';
    if (title.includes(query)) {
      card.style.display = 'flex';
    } else {
      card.style.display = 'none';
    }
  });
}

async function doUpdate() {
  const email = document.getElementById('u-email').value.trim();
  const password = document.getElementById('u-pass').value;
  const role = document.getElementById('u-role').value;
  const balance = document.getElementById('u-balance').value ? parseFloat(document.getElementById('u-balance').value) : null;

  const payload = {};
  if (email) payload.email = email;
  if (password) payload.password = password;
  if (role) payload.role = role;
  if (balance !== null) payload.balance = balance;

  const el = document.getElementById('u-msg');
  try {
    const r = await fetch(API + '/users/' + currentUser.id, {
      method: 'PUT',
      headers: authHdr(),
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (!r.ok) {
      show(data.detail || 'Update failed', 'err', 'u-msg');
      return;
    }
    show('Profile updated successfully!', 'ok', 'u-msg');
    loadProfile();
  } catch(e) { show('Network error', 'err', 'u-msg'); }
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

function switchTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}

async function checkBlockingStatus() {
  try {
    const r = await fetch(API + '/api/topology');
    if (r.ok) {
      const data = await r.json();
      const badge = document.getElementById('blocking-status-badge');
      if (badge) {
        if (data.inline_blocking) {
          badge.textContent = 'Auto-Blocking: ACTIVE (ML Protection)';
          badge.style.background = 'rgba(63,185,80,0.18)';
          badge.style.color = '#3fb950';
          badge.style.borderColor = 'rgba(63,185,80,0.4)';
        } else {
          badge.textContent = 'Auto-Blocking: INACTIVE (Monitoring Only)';
          badge.style.background = 'rgba(248,81,73,0.15)';
          badge.style.color = '#f85149';
          badge.style.borderColor = 'rgba(248,81,73,0.3)';
        }
      }
    }
  } catch (e) {
    console.error("Failed to fetch proxy topology status", e);
  }
}

function toggleShopTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  applyShopTheme(next);
  localStorage.setItem('shopTheme', next);
}

function applyShopTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) {
    btn.innerHTML = theme === 'light' ? '🌙 Dark' : '☀️ Light';
  }
}

// Initialize theme on DOM load
(function initShopTheme() {
  const saved = localStorage.getItem('shopTheme') || 'dark';
  applyShopTheme(saved);
})();

// Start checking status periodically
setInterval(checkBlockingStatus, 5000);
checkBlockingStatus();
</script>
</body>
</html>"""
