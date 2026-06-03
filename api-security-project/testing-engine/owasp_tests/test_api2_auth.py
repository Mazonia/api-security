"""API2:2023 — Broken Authentication"""
import httpx


def run(base_url: str) -> dict:
    tests = []

    # Test 1: brute-force — no lockout after repeated failures
    blocked = 0
    for _ in range(10):
        r = httpx.post(f"{base_url}/auth/login",
                       json={"username": "alice", "password": "wrongpass"}, timeout=10)
        if r.status_code == 429:
            blocked += 1

    tests.append({
        "test": "Brute-force login — no rate limiting / lockout",
        "request": "POST /auth/login x10 with wrong password",
        "expected": "429 Too Many Requests before 10 attempts",
        "actual": f"{blocked}/10 requests returned 429",
        "vulnerable": blocked == 0,
        "severity": "HIGH",
    })

    # Test 2: forge JWT with well-known weak secret "secret"
    try:
        from jose import jwt
        forged = jwt.encode({"sub": "3", "username": "hacker", "role": "admin"}, "secret",
                            algorithm="HS256")
        r = httpx.get(f"{base_url}/admin/users",
                      headers={"Authorization": f"Bearer {forged}"}, timeout=10)
        tests.append({
            "test": "JWT forged with weak hardcoded secret",
            "request": "GET /admin/users with JWT signed using 'secret'",
            "expected": "401 Unauthorized",
            "actual": r.status_code,
            "vulnerable": r.status_code == 200,
            "severity": "CRITICAL",
        })
    except Exception as e:
        tests.append({
            "test": "JWT forged with weak hardcoded secret",
            "request": "GET /admin/users with forged JWT",
            "expected": "401 Unauthorized",
            "actual": f"Error: {e}",
            "vulnerable": False,
            "severity": "CRITICAL",
        })

    # Test 3: JWT missing expiry claim
    r = httpx.post(f"{base_url}/auth/login",
                   json={"username": "alice", "password": "alice123"}, timeout=10)
    token = r.json().get("access_token", "")
    try:
        from jose import jwt as jose_jwt
        payload = jose_jwt.decode(token, options={"verify_signature": False, "verify_exp": False},
                                  algorithms=["HS256"], key="")
        has_exp = "exp" in payload
        tests.append({
            "test": "JWT issued without expiry claim",
            "request": "Decode token payload from POST /auth/login",
            "expected": "'exp' claim present in payload",
            "actual": f"'exp' present: {has_exp}",
            "vulnerable": not has_exp,
            "severity": "MEDIUM",
        })
    except Exception:
        tests.append({
            "test": "JWT issued without expiry claim",
            "request": "Decode token payload",
            "expected": "'exp' claim present",
            "actual": "Could not decode",
            "vulnerable": False,
            "severity": "MEDIUM",
        })

    # Test 4: JWT alg:none — unsigned token must be rejected
    import base64 as _b64
    try:
        _h = _b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        _p = _b64.urlsafe_b64encode(
            b'{"sub":"1","username":"alice","role":"admin"}'
        ).rstrip(b"=").decode()
        none_tok = f"{_h}.{_p}."
        r = httpx.get(
            f"{base_url}/admin/users",
            headers={"Authorization": f"Bearer {none_tok}"},
            timeout=10,
        )
        tests.append({
            "test": "JWT algorithm confusion — alg:none (unsigned token)",
            "request": "GET /admin/users with JWT alg=none (no signature)",
            "expected": "401 Unauthorized — unsigned tokens must be rejected",
            "actual": r.status_code,
            "vulnerable": r.status_code == 200,
            "severity": "CRITICAL",
        })
    except Exception as e:
        tests.append({
            "test": "JWT algorithm confusion — alg:none (unsigned token)",
            "request": "GET /admin/users with JWT alg=none",
            "expected": "401 Unauthorized",
            "actual": f"Error: {e}",
            "vulnerable": False,
            "severity": "CRITICAL",
        })

    return {
        "category": "API2:2023 - Broken Authentication",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
