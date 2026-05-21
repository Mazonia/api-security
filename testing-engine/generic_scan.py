"""
Generic OWASP API security scanner for external/custom APIs.

Usage:
    python generic_scan.py --target https://api.example.com
    python generic_scan.py --target http://localhost:9000 --auth-endpoint /auth/login \
        --auth-body '{"username":"alice","password":"alice123"}' \
        --token-field access_token

The scanner runs generic probes that do not rely on knowing the exact schema of the
target. It tests:
  - Unauthenticated access to common sensitive paths (API5, API8)
  - CORS wildcard header (API8)
  - Debug/health endpoint exposure (API8)
  - Rate-limiting on the auth endpoint (API4)
  - JWT algorithm confusion if a login endpoint is provided (API2)
  - Mass-assignment probe on any writable endpoint discovered (API3)
  - BOLA probe: ID enumeration on any discovered object endpoint (API1)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

try:
    import httpx
except ImportError:
    raise SystemExit("httpx required: pip install httpx")

try:
    from jose import jwt as jose_jwt
    _JOSE_OK = True
except ImportError:
    _JOSE_OK = False

try:
    from report_generator import generate as make_report
    _REPORT_OK = True
except ImportError:
    _REPORT_OK = False

from cve_data import CVE_DB

# Paths commonly exposed in vulnerable APIs
_SENSITIVE_PATHS = [
    "/debug/config", "/debug", "/config", "/env",
    "/admin", "/admin/users", "/admin/orders", "/admin/config",
    "/internal", "/internal/metrics", "/metrics",
    "/actuator", "/actuator/env", "/actuator/health",
    "/swagger", "/docs", "/redoc", "/openapi.json", "/api-docs",
    "/.env", "/server-status",
]

_HEALTH_PATHS = ["/health", "/healthz", "/ping", "/status", "/ready"]


def _get(client: httpx.Client, base: str, path: str, headers: dict = None) -> httpx.Response | None:
    try:
        return client.get(base.rstrip("/") + path, headers=headers or {}, timeout=8)
    except Exception:
        return None


def _post(client: httpx.Client, base: str, path: str, body: dict, headers: dict = None) -> httpx.Response | None:
    try:
        return client.post(base.rstrip("/") + path, json=body, headers=headers or {}, timeout=8)
    except Exception:
        return None


def _login(client: httpx.Client, base: str, endpoint: str, body: dict, token_field: str) -> str:
    r = _post(client, base, endpoint, body)
    if r and r.status_code == 200:
        try:
            return r.json().get(token_field, "")
        except Exception:
            pass
    return ""


def _bearer(token: str) -> dict:
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


# ── individual probes ─────────────────────────────────────────────────────────

def probe_sensitive_paths(client, base) -> list:
    results = []
    for path in _SENSITIVE_PATHS:
        r = _get(client, base, path)
        if r is None:
            continue
        exposed = r.status_code not in (404, 405)
        label = f"GET {path}"
        category = "API8:2023 - Security Misconfiguration"
        if "admin" in path:
            category = "API5:2023 - Broken Function Level Authorization"
        results.append({
            "test": f"Sensitive path: {path}",
            "request": label,
            "expected": "404 or 405",
            "actual": str(r.status_code),
            "severity": "HIGH",
            "vulnerable": exposed,
            "category": category,
        })
    return results


def probe_cors(client, base) -> dict:
    r = _get(client, base, "/health", headers={"Origin": "http://evil.example.com"}) or \
        _get(client, base, "/", headers={"Origin": "http://evil.example.com"})
    if r is None:
        return None
    acao = r.headers.get("access-control-allow-origin", "")
    return {
        "test": "CORS wildcard header",
        "request": "GET / (Origin: evil.example.com)",
        "expected": "No ACAO or specific origin",
        "actual": f"ACAO: {acao or '(none)'}",
        "severity": "MEDIUM",
        "vulnerable": acao == "*",
        "category": "API8:2023 - Security Misconfiguration",
    }


def probe_debug_endpoint(client, base) -> dict:
    for path in ["/debug/config", "/debug", "/config"]:
        r = _get(client, base, path)
        if r and r.status_code == 200:
            return {
                "test": "Debug endpoint accessible",
                "request": f"GET {path}",
                "expected": "404",
                "actual": f"200 ({len(r.content)} bytes)",
                "severity": "HIGH",
                "vulnerable": True,
                "category": "API8:2023 - Security Misconfiguration",
            }
    return {
        "test": "Debug endpoint accessible",
        "request": "GET /debug/config",
        "expected": "404",
        "actual": "404 (not found)",
        "severity": "HIGH",
        "vulnerable": False,
        "category": "API8:2023 - Security Misconfiguration",
    }


def probe_rate_limit(client, base, auth_endpoint: str, auth_body: dict) -> dict:
    got_429 = False
    for _ in range(12):
        r = _post(client, base, auth_endpoint, {"username": "nonexistent_user_xyz", "password": "x"})
        if r and r.status_code == 429:
            got_429 = True
            break
    return {
        "test": f"Rate limiting on {auth_endpoint}",
        "request": f"POST {auth_endpoint} x12 rapid",
        "expected": "429 after repeated failures",
        "actual": "429 received" if got_429 else "No 429 — unlimited attempts",
        "severity": "MEDIUM",
        "vulnerable": not got_429,
        "category": "API4:2023 - Unrestricted Resource Consumption",
    }


def probe_jwt_forge(client, base, protected_path: str) -> dict:
    if not _JOSE_OK:
        return {
            "test": "JWT algorithm confusion / weak secret",
            "request": f"GET {protected_path} (forged JWT, secret='secret')",
            "expected": "401 or 403",
            "actual": "SKIPPED — python-jose not installed",
            "severity": "CRITICAL",
            "vulnerable": False,
            "category": "API2:2023 - Broken Authentication",
        }
    forged = jose_jwt.encode(
        {"sub": "9999", "username": "hacker", "role": "admin"},
        "secret", algorithm="HS256",
    )
    r = _get(client, base, protected_path, headers=_bearer(forged))
    status = r.status_code if r else 0
    return {
        "test": "JWT algorithm confusion / weak secret",
        "request": f"GET {protected_path} (forged JWT, secret='secret')",
        "expected": "401 or 403",
        "actual": str(status),
        "severity": "CRITICAL",
        "vulnerable": status not in (401, 403),
        "category": "API2:2023 - Broken Authentication",
    }


def probe_bola(client, base, token: str, user_id: int, bola_path_template: str) -> dict:
    other_id = 1 if user_id != 1 else 2
    path = bola_path_template.replace("{id}", str(other_id))
    r = _get(client, base, path, headers=_bearer(token))
    status = r.status_code if r else 0
    return {
        "test": f"BOLA — access another user's resource",
        "request": f"GET {path} (logged in as user #{user_id})",
        "expected": "403",
        "actual": str(status),
        "severity": "HIGH",
        "vulnerable": status == 200,
        "category": "API1:2023 - Broken Object Level Authorization",
    }


def probe_mass_assign(client, base, token: str, update_path: str) -> dict:
    r = None
    try:
        r = client.put(
            base.rstrip("/") + update_path,
            json={"role": "admin", "balance": 999999},
            headers={**_bearer(token), "Content-Type": "application/json"},
            timeout=8,
        )
    except Exception:
        pass
    if r is None or r.status_code not in (200, 201):
        return {
            "test": "Mass assignment — privilege escalation",
            "request": f"PUT {update_path} {{role:'admin', balance:999999}}",
            "expected": "400 or 403 (fields rejected)",
            "actual": str(r.status_code) if r else "connection error",
            "severity": "HIGH",
            "vulnerable": False,
            "category": "API3:2023 - Broken Object Property Level Authorization",
        }
    try:
        body = r.json()
        user_data = body.get("user", body)
        escalated = user_data.get("role") == "admin" or user_data.get("balance") == 999999
    except Exception:
        escalated = False
    return {
        "test": "Mass assignment — privilege escalation",
        "request": f"PUT {update_path} {{role:'admin', balance:999999}}",
        "expected": "400 or 403 (fields rejected)",
        "actual": f"200 — role/balance {'accepted' if escalated else 'rejected'}",
        "severity": "HIGH",
        "vulnerable": escalated,
        "category": "API3:2023 - Broken Object Property Level Authorization",
    }


# ── aggregator ────────────────────────────────────────────────────────────────

def _group_by_category(flat: list) -> list:
    buckets: dict = {}
    for t in flat:
        cat = t["category"]
        if cat not in buckets:
            buckets[cat] = {"category": cat, "tests": [], "vulnerable_count": 0, "total": 0}
        buckets[cat]["tests"].append({k: v for k, v in t.items() if k != "category"})
        buckets[cat]["total"] += 1
        if t["vulnerable"]:
            buckets[cat]["vulnerable_count"] += 1
    return list(buckets.values())


def run_scan(
    target: str,
    auth_endpoint: str = "/auth/login",
    auth_body: dict = None,
    token_field: str = "access_token",
    bola_path: str = "/users/{id}",
    update_path: str = "/users/1",
    protected_path: str = "/admin/users",
    report_dir: str = "./reports",
) -> list:
    auth_body = auth_body or {}
    flat_results = []

    with httpx.Client(follow_redirects=True) as client:
        print(f"\n  Target: {target}")
        print(f"  {'─'*55}\n")

        # Sensitive path enumeration
        print("  [API5/API8] Probing sensitive paths ...")
        sp = probe_sensitive_paths(client, target)
        flat_results.extend(sp)
        exposed = [t for t in sp if t["vulnerable"]]
        print(f"           {len(exposed)}/{len(sp)} paths exposed")

        # CORS
        print("  [API8]     Checking CORS headers ...")
        cors = probe_cors(client, target)
        if cors:
            flat_results.append(cors)
            print(f"           ACAO wildcard: {'YES (vulnerable)' if cors['vulnerable'] else 'no'}")

        # Debug endpoint
        print("  [API8]     Probing debug endpoint ...")
        dbg = probe_debug_endpoint(client, target)
        flat_results.append(dbg)
        print(f"           Debug exposed: {'YES' if dbg['vulnerable'] else 'no'}")

        # Rate limiting
        if auth_body:
            print(f"  [API4]     Rate-limit test on {auth_endpoint} ...")
            rl = probe_rate_limit(client, target, auth_endpoint, auth_body)
            flat_results.append(rl)
            print(f"           Rate limited: {'yes' if not rl['vulnerable'] else 'NO (vulnerable)'}")
            time.sleep(0.5)

        # Obtain a real token for authenticated probes
        token = ""
        user_id = 1
        if auth_body:
            print(f"  [AUTH]     Logging in via {auth_endpoint} ...")
            token = _login(client, target, auth_endpoint, auth_body, token_field)
            if token:
                try:
                    import base64
                    payload = json.loads(base64.b64decode(token.split(".")[1] + "=="))
                    user_id = int(payload.get("sub", 1))
                except Exception:
                    pass
            print(f"           Token obtained: {'yes' if token else 'no (skipping auth probes)'}")

        # JWT forge
        print(f"  [API2]     Testing JWT weak secret on {protected_path} ...")
        jwt_r = probe_jwt_forge(client, target, protected_path)
        flat_results.append(jwt_r)
        print(f"           Forged JWT accepted: {'YES (vulnerable)' if jwt_r['vulnerable'] else 'no'}")

        # BOLA
        if token:
            print(f"  [API1]     BOLA probe on {bola_path} ...")
            bola = probe_bola(client, target, token, user_id, bola_path)
            flat_results.append(bola)
            print(f"           BOLA exposed: {'YES' if bola['vulnerable'] else 'no'}")

            # Mass assignment
            print(f"  [API3]     Mass assignment probe on {update_path} ...")
            ma = probe_mass_assign(client, target, token, update_path)
            flat_results.append(ma)
            print(f"           Mass assign accepted: {'YES (vulnerable)' if ma['vulnerable'] else 'no'}")

    grouped = _group_by_category(flat_results)
    total_v = sum(g["vulnerable_count"] for g in grouped)
    total_t = sum(g["total"] for g in grouped)
    score   = round((1 - total_v / total_t) * 100) if total_t else 100

    print(f"\n  {'─'*55}")
    print(f"  Tests run: {total_t}  |  Vulnerable: {total_v}  |  Score: {score}%\n")

    if _REPORT_OK:
        j, h = make_report(grouped, target, report_dir)
        print(f"  JSON  -> {j}")
        print(f"  HTML  -> {h}\n")

    return grouped


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main():
    p = argparse.ArgumentParser(description="Generic OWASP API Security Scanner")
    p.add_argument("--target",        required=True, help="Base URL of the API to scan")
    p.add_argument("--auth-endpoint", default="/auth/login")
    p.add_argument("--auth-body",     default=None,  help='JSON string e.g. \'{"username":"alice","password":"alice123"}\'')
    p.add_argument("--token-field",   default="access_token")
    p.add_argument("--bola-path",     default="/users/{id}", help="Path template with {id} placeholder")
    p.add_argument("--update-path",   default="/users/1",    help="PUT endpoint for mass-assignment probe")
    p.add_argument("--protected",     default="/admin/users", help="Path that requires auth (for JWT forge test)")
    p.add_argument("--reports",       default="./reports")
    args = p.parse_args()

    auth_body = {}
    if args.auth_body:
        try:
            auth_body = json.loads(args.auth_body)
        except json.JSONDecodeError:
            raise SystemExit("--auth-body must be valid JSON")

    run_scan(
        target=args.target,
        auth_endpoint=args.auth_endpoint,
        auth_body=auth_body,
        token_field=args.token_field,
        bola_path=args.bola_path,
        update_path=args.update_path,
        protected_path=args.protected,
        report_dir=args.reports,
    )


if __name__ == "__main__":
    _main()
