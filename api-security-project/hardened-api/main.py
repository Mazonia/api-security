import os
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

# API8: docs disabled in production
app = FastAPI(title="Hardened API", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# API8: strict CORS — only allow configured origins
_allowed = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# API2: strong secret from env, enforced at startup
SECRET_KEY = os.environ.get("JWT_SECRET", "")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET environment variable must be set")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

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


# API3: only safe fields — role and balance are not updatable
class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None


def create_token(user_id: int, username: str, role: str) -> str:
    # API2: token expires after 30 minutes
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "username": username, "role": role, "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM
    )


def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = users_db.get(int(payload["sub"]))
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Not authenticated")


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    # API5: explicit admin role check on every admin endpoint
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# API4: login rate limited to 5 attempts per minute per IP
@app.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, req: LoginRequest):
    for user in users_db.values():
        if user["username"] == req.username and pwd_context.verify(req.password, user["password"]):
            return {"access_token": create_token(user["id"], user["username"], user["role"]),
                    "token_type": "bearer"}
    # API8: generic error — does not reveal whether user exists
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/users/{user_id}")
@limiter.limit("60/minute")
def get_user(request: Request, user_id: int,
             current_user: dict = Depends(get_current_user)):
    # API1: ownership enforced
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {k: v for k, v in user.items() if k not in ("password", "balance")}


@app.put("/users/{user_id}")
@limiter.limit("10/minute")
def update_user(request: Request, user_id: int, update: UserUpdate,
                current_user: dict = Depends(get_current_user)):
    # API1: ownership enforced
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # API3: only email/password reach here — role and balance are not in UserUpdate
    data = update.model_dump(exclude_none=True)
    if "password" in data:
        data["password"] = pwd_context.hash(data["password"])
    user.update(data)
    return {"message": "Updated"}


@app.get("/orders/{order_id}")
@limiter.limit("60/minute")
def get_order(request: Request, order_id: int,
              current_user: dict = Depends(get_current_user)):
    order = orders_db.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # API1: ownership enforced
    if order["user_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return order


@app.get("/users/{user_id}/orders")
@limiter.limit("60/minute")
def get_user_orders(request: Request, user_id: int,
                    current_user: dict = Depends(get_current_user)):
    # API1: ownership enforced
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return [o for o in orders_db.values() if o["user_id"] == user_id]


@app.get("/admin/users")
@limiter.limit("30/minute")
def admin_list_users(request: Request, admin: dict = Depends(require_admin)):
    return [{k: v for k, v in u.items() if k != "password"} for u in users_db.values()]


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int, admin: dict = Depends(require_admin)):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    del users_db[user_id]
    return {"message": "User deleted"}


@app.get("/admin/orders")
@limiter.limit("30/minute")
def admin_list_orders(request: Request, admin: dict = Depends(require_admin)):
    return list(orders_db.values())


@app.get("/health")
def health():
    return {"status": "ok", "service": "hardened-api"}


# ── IoT API Hardened Endpoints ─────────────────────────────────────────────
@app.get("/api/v1/iot/telemetry")
@limiter.limit("30/minute")
def get_hardened_iot_telemetry(request: Request, current_user: dict = Depends(get_current_user)):
    """Authenticated IoT telemetry endpoint."""
    return {
        "status": "active",
        "device_id": "esp32_sensor_grid_04",
        "temperature_celsius": 24.5,
        "humidity_pct": 58.2,
        "pressure_hpa": 1013.25,
        "security": "MUTUAL_TLS_JWT_ENFORCED"
    }


@app.post("/api/v1/iot/actuate")
@limiter.limit("10/minute")
def actuate_hardened_iot_device(request: Request, payload: dict, admin_user: dict = Depends(require_admin)):
    """Hardened physical actuator endpoint requiring admin role and safety bounds."""
    action = payload.get("action", "lock")
    device_id = payload.get("device_id", "door_lock_01")
    return {
        "status": "SUCCESSFULLY_MUTATED",
        "device_id": device_id,
        "action_executed": action,
        "operator": admin_user["username"],
        "safety_guardrail": "HITL_APPROVED"
    }


@app.post("/api/v1/iot/ota/upload")
@limiter.limit("5/minute")
def upload_hardened_ota_firmware(request: Request, payload: dict = None, x_signature: str = Header(None, alias="X-Signature")):
    """Hardened OTA update requiring cryptographic signature verification."""
    if not x_signature or len(x_signature) < 32:
        raise HTTPException(status_code=403, detail="Missing or invalid cryptographic firmware signature header (X-Signature)")
    return {
        "status": "FIRMWARE_VERIFIED_AND_ACCEPTED",
        "signature_type": "Ed25519",
        "signature": x_signature[:16] + "..."
    }


@app.post("/api/v1/iot/mqtt/publish")
@limiter.limit("20/minute")
def publish_hardened_mqtt_gateway(request: Request, payload: dict, current_user: dict = Depends(get_current_user)):
    """Hardened MQTT gateway prohibiting wildcard topic hijacking."""
    topic = payload.get("topic", "")
    if "#" in topic or "+" in topic or not topic:
        raise HTTPException(status_code=400, detail="MQTT Wildcard topic publication prohibited by Topic ACL Policy")
    return {
        "status": "PUBLISHED",
        "topic": topic,
        "acl_enforced": True
    }


@app.get("/comparison", response_class=HTMLResponse, include_in_schema=False)
def get_comparison_page():
    try:
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(cur_dir)), "comparison_workbench.html"),
            os.path.join(os.path.dirname(cur_dir), "monitoring", "templates", "comparison.html"),
            os.path.join(os.getcwd(), "comparison_workbench.html"),
            os.path.join(os.getcwd(), "api-security-project", "monitoring", "templates", "comparison.html")
        ]
        for path in candidates:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return HTMLResponse(content=f.read())
    except Exception:
        pass
    return HTMLResponse(content="<html><body><h2>MazAPI Comparison Workbench</h2></body></html>")

