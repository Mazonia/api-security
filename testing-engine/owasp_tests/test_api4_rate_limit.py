"""API4:2023 — Unrestricted Resource Consumption (Rate Limiting)"""
import httpx


def run(base_url: str) -> dict:
    tests = []

    r = httpx.post(f"{base_url}/auth/login",
                   json={"username": "alice", "password": "alice123"}, timeout=10)
    token = r.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    # Hammer a data endpoint — expect 429 before 50 requests
    accepted = 0
    for _ in range(50):
        r = httpx.get(f"{base_url}/users/1", headers=headers, timeout=10)
        if r.status_code == 200:
            accepted += 1

    tests.append({
        "test": "No rate limiting on authenticated data endpoint",
        "request": "GET /users/1 x50 rapid succession",
        "expected": "429 Too Many Requests before 50 requests",
        "actual": f"{accepted}/50 requests returned 200",
        "vulnerable": accepted >= 45,
        "severity": "MEDIUM",
    })

    # Hammer login — expect 429 within 10 attempts
    throttled = 0
    for _ in range(10):
        r = httpx.post(f"{base_url}/auth/login",
                       json={"username": "nobody", "password": "x"}, timeout=10)
        if r.status_code == 429:
            throttled += 1

    tests.append({
        "test": "No rate limiting on login endpoint (brute-force vector)",
        "request": "POST /auth/login x10 rapid attempts",
        "expected": "429 after 5 attempts",
        "actual": f"{throttled}/10 requests returned 429",
        "vulnerable": throttled == 0,
        "severity": "HIGH",
    })

    return {
        "category": "API4:2023 - Unrestricted Resource Consumption",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
