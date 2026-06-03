"""PII / sensitive data exposure in API responses — GDPR Art.32 / CWE-312."""
import re
import httpx


_PII_PATTERNS = [
    ("Email address",        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("Phone number",         re.compile(r"(?:\+?\d{1,3}[\-.\s]?)?\(?\d{3}\)?[\-.\s]?\d{3}[\-.\s]?\d{4}")),
    ("Credit card number",   re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")),
    ("US Social Security",   re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("AWS Access Key",       re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Password in response", re.compile(r'"password"\s*:\s*"[^"]{3,}"')),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

_PROBE_PATHS = [
    "/api/users", "/users", "/api/user", "/api/profile",
    "/profile", "/api/me", "/me", "/api/customers",
    "/api/orders", "/api/accounts",
]


def run(base_url: str, token: str = "") -> dict:
    tests = []
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    # Acquire a token if not provided (attempt login)
    if not token:
        try:
            r = httpx.post(f"{base_url}/auth/login",
                           json={"username": "alice", "password": "alice123"}, timeout=8)
            if r.status_code == 200:
                token = r.json().get("access_token", "")
                if token:
                    headers = {"Authorization": f"Bearer {token}"}
        except Exception:
            pass

    for path in _PROBE_PATHS:
        try:
            r = httpx.get(f"{base_url}{path}", headers=headers, timeout=8)
        except Exception:
            continue
        if r.status_code not in (200, 206):
            continue
        body = r.text
        if len(body) < 10:
            continue

        found_pii = []
        for name, pattern in _PII_PATTERNS:
            matches = pattern.findall(body)
            if matches:
                found_pii.append(f"{name} (×{len(matches)}, e.g. {str(matches[0])[:30]})")

        if found_pii:
            tests.append({
                "test": f"PII exposure at {path}",
                "request": f"GET {path} (authenticated)",
                "expected": "Response must not contain unnecessary PII",
                "actual": f"Found: {'; '.join(found_pii[:4])}",
                "vulnerable": True,
                "severity": "HIGH",
            })
        else:
            tests.append({
                "test": f"PII check at {path}",
                "request": f"GET {path}",
                "expected": "No unnecessary PII in response",
                "actual": f"No PII patterns detected (HTTP {r.status_code})",
                "vulnerable": False,
                "severity": "HIGH",
            })

    if not tests:
        tests.append({
            "test": "PII endpoint scan",
            "request": f"GET common data paths",
            "expected": "No PII exposure",
            "actual": "No data endpoints responded — not applicable",
            "vulnerable": False,
            "severity": "HIGH",
        })

    return {
        "category": "CWE-312 / GDPR - PII Exposure in API Responses",
        "tests": tests,
        "vulnerable_count": sum(1 for t in tests if t["vulnerable"]),
        "total": len(tests),
    }
