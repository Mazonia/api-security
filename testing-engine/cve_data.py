"""CVE mappings and remediation advice for each OWASP API category."""

CVE_DB = {
    "API1:2023 - Broken Object Level Authorization": {
        "cves": ["CVE-2019-14234", "CVE-2020-7927", "CVE-2021-21302"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "severity": "HIGH",
        "description": (
            "The API retrieves data based on a client-supplied identifier without verifying "
            "that the requesting user is authorised to access that specific object."
        ),
        "fixes": [
            "Verify ownership on every request: check <code>current_user.id == resource.owner_id</code> before returning data.",
            "Use unpredictable UUIDs instead of sequential integer IDs to reduce guessability.",
            "Apply an authorization middleware/dependency that enforces ownership rather than repeating checks per endpoint.",
            "Write integration tests that log in as User A and attempt to access User B's resources — expect 403.",
        ],
        "impact": (
            "Any authenticated user can enumerate all sequential object IDs and exfiltrate every record in the "
            "system — user profiles, orders, messages, or payment details — without requiring elevated privileges. "
            "In regulated environments this constitutes a mandatory-notification data breach under GDPR/HIPAA."
        ),
        "poc_steps": [
            "Authenticate as a low-privilege user (e.g., alice) and capture the returned JWT token.",
            "Call GET /users/1 — confirm your own profile is returned.",
            "Change the path ID to /users/2 — the server returns another user's full profile with no ownership check.",
            "Automate: for i in range(1, 10000): GET /users/{i} — the entire user table is now exfiltrable.",
        ],
        "code_before": (
            '@app.get("/users/{user_id}")\n'
            'async def get_user(user_id: int, token=Depends(decode_token)):\n'
            '    user = db.get(user_id)  # no ownership check — any authed user reads any record\n'
            '    if not user:\n'
            '        raise HTTPException(404)\n'
            '    return user'
        ),
        "code_after": (
            '@app.get("/users/{user_id}")\n'
            'async def get_user(user_id: int, current=Depends(get_current_user)):\n'
            '    if user_id != current.id:  # ownership enforced\n'
            '        raise HTTPException(status_code=403, detail="Forbidden")\n'
            '    return db.get(user_id)'
        ),
    },
    "API2:2023 - Broken Authentication": {
        "cves": ["CVE-2018-1000531", "CVE-2022-21449", "CVE-2021-27958"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        "severity": "CRITICAL",
        "description": (
            "Authentication mechanisms are implemented incorrectly, allowing attackers to "
            "forge tokens, brute-force credentials, or bypass authentication entirely."
        ),
        "fixes": [
            "Load JWT secrets from environment variables — never hard-code them in source code.",
            "Always set an expiry claim (<code>exp</code>) in JWTs; 15–30 minutes is typical for access tokens.",
            "Rate-limit login endpoints to 5 attempts per minute per IP and implement account lockout.",
            "Use a well-audited library and verify the <code>alg</code> header to prevent algorithm confusion attacks.",
        ],
        "impact": (
            "A forged JWT grants persistent, unrestricted API access under any identity — including admin — "
            "without knowing a password. Hard-coded secrets rarely rotate, so a single source-code leak "
            "of the signing key compromises every user account across all environments permanently."
        ),
        "poc_steps": [
            "Identify the JWT signing algorithm from the token header (e.g., alg: HS256).",
            "Try the well-known weak key 'secret': jose.jwt.encode({'sub':'1','role':'admin'}, 'secret', 'HS256').",
            "Send the forged token to any protected endpoint — a 200 response confirms the secret is compromised.",
            "With a valid admin token, call GET /admin/users, PUT /users/{id}, DELETE /users/{id} freely.",
        ],
        "code_before": (
            "SECRET = 'secret'  # hard-coded, committed to version control\n\n"
            "def decode_token(token: str):\n"
            "    return jose.jwt.decode(token, SECRET, algorithms=['HS256'])\n"
            "    # no expiry check — tokens are valid forever"
        ),
        "code_after": (
            "import os\n"
            "SECRET = os.environ['JWT_SECRET']  # from .env or secret manager, never in source\n\n"
            "def decode_token(token: str):\n"
            "    payload = jose.jwt.decode(token, SECRET, algorithms=['HS256'])\n"
            "    if payload.get('exp', 0) < time.time():\n"
            "        raise HTTPException(401, 'Token expired')\n"
            "    return payload"
        ),
    },
    "API3:2023 - Broken Object Property Level Authorization": {
        "cves": ["CVE-2012-2676", "CVE-2022-32532", "CVE-2021-41079"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "severity": "HIGH",
        "description": (
            "The API accepts more fields than intended, allowing clients to modify "
            "properties they should never control — such as role or balance."
        ),
        "fixes": [
            "Define strict input schemas that explicitly list allowed fields (email, password only for profile updates).",
            "Never pass user input directly to ORM <code>.update()</code> calls — always use an allowlist.",
            "Treat privilege fields (role, is_admin, balance) as server-controlled — strip them from all client input models.",
            "Return a separate response schema that omits sensitive fields like password hash.",
        ],
        "impact": (
            "Any authenticated user can self-promote to administrator, set their account balance to an arbitrary "
            "value, or overwrite other users' sensitive fields. Mass assignment bypasses the entire role-based "
            "access control model in a single API call without exploiting any other vulnerability."
        ),
        "poc_steps": [
            "Log in as a regular user and obtain a JWT token.",
            "Send PUT /users/1 with body {\"email\": \"alice@x.com\", \"role\": \"admin\", \"balance\": 999999}.",
            "If the response echoes role: 'admin' and balance: 999999, mass assignment is confirmed.",
            "Now call GET /admin/users — as a self-promoted admin the endpoint returns all user records.",
        ],
        "code_before": (
            "class UserUpdate(BaseModel):\n"
            "    email: str\n"
            "    password: str\n"
            "    role: str       # client can set any role\n"
            "    balance: float  # client controls their own balance\n\n"
            "@app.put('/users/{uid}')\n"
            "async def update(uid: int, body: UserUpdate, ...):\n"
            "    db.update(uid, **body.dict())  # all fields passed through"
        ),
        "code_after": (
            "class UserUpdate(BaseModel):\n"
            "    email: str      # only user-editable fields exposed\n"
            "    password: str\n"
            "    # role and balance are NOT in this schema\n\n"
            "@app.put('/users/{uid}')\n"
            "async def update(uid: int, body: UserUpdate, ...):\n"
            "    db.update(uid, email=body.email, password=hash(body.password))"
        ),
    },
    "API4:2023 - Unrestricted Resource Consumption": {
        "cves": ["CVE-2019-11324", "CVE-2020-26258", "CVE-2021-25742"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "severity": "MEDIUM",
        "description": (
            "The API does not limit the rate or volume of requests, enabling brute-force "
            "attacks, credential stuffing, and denial-of-service."
        ),
        "fixes": [
            "Apply per-IP rate limiting on authentication endpoints (e.g., <code>slowapi</code> for FastAPI).",
            "Apply per-user rate limiting on resource endpoints to prevent data scraping.",
            "Set maximum request body sizes and reject oversized payloads early.",
            "Implement exponential backoff or temporary IP bans after repeated failures.",
        ],
        "impact": (
            "Without rate limiting an attacker can attempt millions of password combinations per hour "
            "using credential stuffing tools (Hydra, Burp Intruder), enumerate valid usernames via "
            "response timing differences, or saturate the server to cause a denial of service — "
            "all using publicly available tooling with no special privileges."
        ),
        "poc_steps": [
            "Send 12 rapid POST /auth/login requests with an incorrect password — observe no 429 response.",
            "Run: for i in range(10000): POST /auth/login {username:'alice', password:'guess'+str(i)}",
            "With no delay between requests, a 6-character lowercase password is brutable in under 1 hour.",
            "Confirm fix: add a 5/min rate limit and re-run — a 429 should appear after the 5th attempt.",
        ],
        "code_before": (
            "@app.post('/auth/login')\n"
            "async def login(body: LoginRequest):\n"
            "    user = db.get_by_username(body.username)\n"
            "    if not user or user.password != body.password:\n"
            "        raise HTTPException(401)  # unlimited attempts, no lockout"
        ),
        "code_after": (
            "from slowapi import Limiter\n"
            "from slowapi.util import get_remote_address\n"
            "limiter = Limiter(key_func=get_remote_address)\n\n"
            "@app.post('/auth/login')\n"
            "@limiter.limit('5/minute')\n"
            "async def login(request: Request, body: LoginRequest):\n"
            "    user = db.get_by_username(body.username)\n"
            "    if not user or user.password != body.password:\n"
            "        raise HTTPException(401)"
        ),
    },
    "API5:2023 - Broken Function Level Authorization": {
        "cves": ["CVE-2021-41773", "CVE-2022-22947", "CVE-2020-14882"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        "severity": "HIGH",
        "description": (
            "Administrative or privileged endpoints are accessible to regular users because "
            "the API checks authentication but not the user's role or permissions."
        ),
        "fixes": [
            "Default to deny — every endpoint must explicitly declare the required role/permission.",
            "Use a shared authorization dependency/guard that verifies role on every admin route.",
            "Keep admin functionality on a separate service or subdomain with network-level controls.",
            "Audit all routes regularly to ensure no admin path is reachable without explicit role validation.",
        ],
        "impact": (
            "Any authenticated user can invoke administrator-only functions: listing all user accounts, "
            "modifying or deleting arbitrary records, accessing billing data, or changing system settings. "
            "The only requirement is knowing the endpoint path — often exposed in JavaScript bundles, "
            "API documentation, or Shodan results."
        ),
        "poc_steps": [
            "Authenticate as a regular (non-admin) user and capture the JWT.",
            "Send GET /admin/users with the regular user token.",
            "If the API returns a list of all users (200 OK), function-level authorization is absent.",
            "Attempt POST /admin/users/{id}/promote — if it succeeds the attacker now has an admin peer.",
        ],
        "code_before": (
            "@app.get('/admin/users')\n"
            "async def list_users(token=Depends(decode_token)):\n"
            "    # checks authentication only — not the user's role\n"
            "    return db.all_users()"
        ),
        "code_after": (
            "def require_admin(current=Depends(get_current_user)):\n"
            "    if current.role != 'admin':\n"
            "        raise HTTPException(403, 'Admin only')\n"
            "    return current\n\n"
            "@app.get('/admin/users')\n"
            "async def list_users(admin=Depends(require_admin)):\n"
            "    return db.all_users()  # role enforced by dependency"
        ),
    },
    "API8:2023 - Security Misconfiguration": {
        "cves": ["CVE-2021-44228", "CVE-2020-1938", "CVE-2019-0232"],
        "owasp_ref": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
        "severity": "MEDIUM",
        "description": (
            "The API exposes sensitive information through debug endpoints, verbose error "
            "messages, permissive CORS, or publicly accessible API documentation."
        ),
        "fixes": [
            "Remove all debug/development endpoints before deploying to production — use ENV flags to gate them.",
            "Configure CORS to allow only known, trusted origins; never use wildcard (*) with credentialed requests.",
            "Return generic error messages — never reveal whether a username exists or a password is wrong.",
            "Disable interactive API documentation (Swagger UI, ReDoc) in production environments.",
        ],
        "impact": (
            "Debug endpoints routinely expose JWT signing secrets, database connection strings, internal IP "
            "addresses, environment variables, and API keys in a single unauthenticated GET request. "
            "A leaked JWT_SECRET enables admin token forgery across every user and environment without "
            "any further exploitation."
        ),
        "poc_steps": [
            "Without any authentication, send GET /debug/config.",
            "If the response contains 'JWT_SECRET', 'DB_PASSWORD', or internal hostnames — misconfiguration confirmed.",
            "Use the leaked JWT_SECRET to forge admin tokens: jwt.encode({'sub':'1','role':'admin'}, leaked_secret).",
            "Combine with CORS wildcard: any web page on the internet can now call the API as an authenticated admin.",
        ],
        "code_before": (
            "import os\n\n"
            "@app.get('/debug/config')\n"
            "async def debug():  # no auth, no ENV check\n"
            "    return {\n"
            "        'jwt_secret': SECRET,\n"
            "        'db_url': DB_URL,\n"
            "        'env': dict(os.environ)\n"
            "    }"
        ),
        "code_after": (
            "ENV = os.getenv('ENV', 'production')\n\n"
            "@app.get('/debug/config')\n"
            "async def debug(admin=Depends(require_admin)):\n"
            "    if ENV != 'development':  # disabled in production\n"
            "        raise HTTPException(404)\n"
            "    return {'status': 'debug mode active'}"
        ),
    },
}
