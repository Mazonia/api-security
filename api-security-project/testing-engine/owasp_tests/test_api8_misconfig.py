"""API8:2023 — Security Misconfiguration"""
import httpx


def run(base_url: str) -> dict:
    tests = []

    # Debug endpoint exposed without auth
    r = httpx.get(f"{base_url}/debug/config", timeout=10)
    tests.append({
        "test": "Debug endpoint exposes secret key unauthenticated",
        "request": "GET /debug/config  [no auth]",
        "expected": "404 Not Found",
        "actual": f"{r.status_code} — secret_key in body: {'secret_key' in r.text}",
        "vulnerable": r.status_code == 200 and "secret_key" in r.text,
        "severity": "CRITICAL",
    })

    # Swagger UI publicly accessible
    r = httpx.get(f"{base_url}/docs", timeout=10)
    tests.append({
        "test": "Swagger UI docs accessible without authentication",
        "request": "GET /docs  [no auth]",
        "expected": "404 Not Found",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "LOW",
    })

    # Verbose error reveals username existence
    r = httpx.post(f"{base_url}/auth/login",
                   json={"username": "alice", "password": "wrongpass"}, timeout=10)
    body = r.text
    verbose = r.status_code == 401 and ("alice" in body or "Wrong password" in body)
    tests.append({
        "test": "Verbose auth error reveals username existence",
        "request": "POST /auth/login with wrong password for known user 'alice'",
        "expected": "Generic 'Invalid credentials' message",
        "actual": body[:120],
        "vulnerable": verbose,
        "severity": "MEDIUM",
    })

    # CORS wildcard allows any origin
    r = httpx.get(f"{base_url}/health",
                  headers={"Origin": "http://evil.com"}, timeout=10)
    acao = r.headers.get("access-control-allow-origin", "")
    tests.append({
        "test": "CORS wildcard (*) allows any origin",
        "request": "GET /health  Origin: http://evil.com",
        "expected": "No wildcard Access-Control-Allow-Origin header",
        "actual": f"Access-Control-Allow-Origin: {acao or '(not set)'}",
        "vulnerable": acao == "*",
        "severity": "MEDIUM",
    })

    return {
        "category": "API8:2023 - Security Misconfiguration",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
