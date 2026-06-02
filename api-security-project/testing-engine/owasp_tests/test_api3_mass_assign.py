"""API3:2023 — Broken Object Property Level Authorization (Mass Assignment)"""
import httpx


def run(base_url: str) -> dict:
    tests = []

    r = httpx.post(f"{base_url}/auth/login",
                   json={"username": "alice", "password": "alice123"}, timeout=10)
    token = r.json().get("access_token", "")
    headers = {"Authorization": f"Bearer {token}"}

    # Privilege escalation: set role=admin
    r = httpx.put(f"{base_url}/users/1", headers=headers,
                  json={"role": "admin"}, timeout=10)
    if r.status_code == 200:
        check = httpx.get(f"{base_url}/users/1", headers=headers, timeout=10)
        new_role = check.json().get("role", "unknown")
        vulnerable = new_role == "admin"
        actual = f"HTTP {r.status_code} — role is now '{new_role}'"
    else:
        vulnerable = False
        actual = f"HTTP {r.status_code} — update rejected"

    tests.append({
        "test": "Privilege escalation via role field in PUT body",
        "request": 'PUT /users/1  body: {"role": "admin"}  [as alice, role=user]',
        "expected": "422 Unprocessable Entity or role field silently ignored",
        "actual": actual,
        "vulnerable": vulnerable,
        "severity": "CRITICAL",
    })

    # Balance manipulation
    r = httpx.put(f"{base_url}/users/1", headers=headers,
                  json={"balance": 999999.99}, timeout=10)
    if r.status_code == 200:
        check = httpx.get(f"{base_url}/users/1", headers=headers, timeout=10)
        new_balance = check.json().get("balance", 0)
        vulnerable2 = new_balance == 999999.99
        actual2 = f"HTTP {r.status_code} — balance is now {new_balance}"
    else:
        vulnerable2 = False
        actual2 = f"HTTP {r.status_code} — update rejected"

    tests.append({
        "test": "Arbitrary balance injection via PUT body",
        "request": 'PUT /users/1  body: {"balance": 999999.99}  [as alice]',
        "expected": "422 Unprocessable Entity or balance field silently ignored",
        "actual": actual2,
        "vulnerable": vulnerable2,
        "severity": "HIGH",
    })

    return {
        "category": "API3:2023 - Broken Object Property Level Authorization",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
