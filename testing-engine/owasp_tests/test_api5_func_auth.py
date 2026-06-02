"""API5:2023 — Broken Function Level Authorization"""
import httpx


def run(base_url: str) -> dict:
    tests = []

    r = httpx.post(f"{base_url}/auth/login",
                   json={"username": "alice", "password": "alice123"}, timeout=10)
    token = r.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    # Regular user lists all users via admin endpoint
    r = httpx.get(f"{base_url}/admin/users", headers=headers, timeout=10)
    tests.append({
        "test": "Regular user calls GET /admin/users",
        "request": "GET /admin/users  [as alice, role=user]",
        "expected": "403 Forbidden",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "HIGH",
    })

    # Regular user lists all orders via admin endpoint
    r = httpx.get(f"{base_url}/admin/orders", headers=headers, timeout=10)
    tests.append({
        "test": "Regular user calls GET /admin/orders",
        "request": "GET /admin/orders  [as alice, role=user]",
        "expected": "403 Forbidden",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "HIGH",
    })

    # Regular user deletes another user via admin endpoint
    r = httpx.delete(f"{base_url}/admin/users/2", headers=headers, timeout=10)
    tests.append({
        "test": "Regular user calls DELETE /admin/users/2",
        "request": "DELETE /admin/users/2  [as alice, role=user]",
        "expected": "403 Forbidden",
        "actual": r.status_code,
        "vulnerable": r.status_code == 200,
        "severity": "CRITICAL",
    })

    return {
        "category": "API5:2023 - Broken Function Level Authorization",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
