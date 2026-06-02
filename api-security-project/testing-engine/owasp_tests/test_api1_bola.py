"""API1:2023 — Broken Object Level Authorization"""
import httpx


def run(base_url: str) -> dict:
    r = httpx.post(f"{base_url}/auth/login",
                   json={"username": "alice", "password": "alice123"}, timeout=10)
    alice_token = r.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {alice_token}"}

    tests = []

    # Alice reads Bob's profile (user_id=2)
    r = httpx.get(f"{base_url}/users/2", headers=headers, timeout=10)
    tests.append({
        "test": "Read another user's profile by guessing ID",
        "request": "GET /users/2  [authenticated as alice, user_id=1]",
        "expected": "403 Forbidden",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "HIGH",
    })

    # Alice reads Bob's order (order_id=2 belongs to bob)
    r = httpx.get(f"{base_url}/orders/2", headers=headers, timeout=10)
    tests.append({
        "test": "Read another user's order by guessing ID",
        "request": "GET /orders/2  [authenticated as alice, user_id=1]",
        "expected": "403 Forbidden",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "HIGH",
    })

    # Alice lists Bob's orders
    r = httpx.get(f"{base_url}/users/2/orders", headers=headers, timeout=10)
    tests.append({
        "test": "List another user's orders by guessing user ID",
        "request": "GET /users/2/orders  [authenticated as alice, user_id=1]",
        "expected": "403 Forbidden",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "HIGH",
    })

    return {
        "category": "API1:2023 - Broken Object Level Authorization",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
