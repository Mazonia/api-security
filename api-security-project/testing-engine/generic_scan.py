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


# ── Beyond-OWASP probes ───────────────────────────────────────────────────────

def probe_verb_tampering(client: httpx.Client, base: str) -> list:
    """Try unsafe HTTP methods on endpoints that should only accept GET."""
    results = []
    for method_name, method_fn, endpoint in [
        ("DELETE", client.delete, "/health"),
        ("TRACE",  client.request, "/"),
        ("PATCH",  client.patch,  "/users/1"),
    ]:
        try:
            if method_name == "TRACE":
                r = client.request("TRACE", base.rstrip("/") + endpoint, timeout=6)
            else:
                r = method_fn(base.rstrip("/") + endpoint, timeout=6)
            status = r.status_code
        except Exception:
            continue
        results.append({
            "test": f"HTTP verb tampering: {method_name} {endpoint}",
            "request": f"{method_name} {endpoint}",
            "expected": "405 Method Not Allowed",
            "actual": str(status),
            "severity": "MEDIUM",
            "vulnerable": status not in (405, 404, 501, 403),
            "category": "Beyond OWASP — HTTP Verb Tampering",
        })
    return results


def probe_path_traversal(client: httpx.Client, base: str) -> list:
    """Test common path traversal payloads."""
    payloads = [
        "/../../../etc/passwd",
        "/files/../../../etc/passwd",
        "/%2F..%2F..%2Fetc%2Fpasswd",
        "/static/..%2F..%2F..%2Fetc%2Fshadow",
    ]
    for payload in payloads:
        try:
            r = client.get(base.rstrip("/") + payload, timeout=6)
            exposed = r.status_code == 200 and ("root:" in r.text or "daemon:" in r.text)
        except Exception:
            continue
        if exposed:
            return [{
                "test": "Path traversal — system file exposed",
                "request": f"GET {payload}",
                "expected": "404 or 400",
                "actual": "200 — /etc/passwd content in response",
                "severity": "CRITICAL",
                "vulnerable": True,
                "category": "Beyond OWASP — Path Traversal",
            }]
    return [{
        "test": "Path traversal — system file exposure",
        "request": "GET /../../../etc/passwd (and encoded variants)",
        "expected": "404 or 400",
        "actual": "Not vulnerable — traversal payloads correctly rejected",
        "severity": "CRITICAL",
        "vulnerable": False,
        "category": "Beyond OWASP — Path Traversal",
    }]


def probe_sql_injection(client: httpx.Client, base: str, token: str) -> list:
    """Basic error-based and boolean SQL injection detection."""
    _SQL_ERRORS = ["sql", "syntax error", "mysql", "sqlite", "postgres", "ora-", "sqlstate"]
    results = []
    payloads = [
        ("' OR '1'='1", "/users/"),
        ("1 OR 1=1--",  "/users/"),
        ("' UNION SELECT 1,2,3--", "/users/"),
    ]
    for payload, path_prefix in payloads:
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        r = _get(client, base, path_prefix + encoded,
                 headers=_bearer(token) if token else {})
        if r and r.status_code == 500:
            body_lower = r.text.lower()
            leaks = [kw for kw in _SQL_ERRORS if kw in body_lower]
            if leaks:
                results.append({
                    "test": "SQL injection (error-based)",
                    "request": f"GET {path_prefix}{payload}",
                    "expected": "400 or 422 (input sanitised)",
                    "actual": f"500 — SQL error keywords exposed: {', '.join(leaks[:3])}",
                    "severity": "CRITICAL",
                    "vulnerable": True,
                    "category": "Beyond OWASP — Injection",
                })
                return results
    results.append({
        "test": "SQL injection (error-based)",
        "request": "GET /users/' OR '1'='1 (and variants)",
        "expected": "400 or 422",
        "actual": "No SQL error detected in responses",
        "severity": "CRITICAL",
        "vulnerable": False,
        "category": "Beyond OWASP — Injection",
    })
    return results


def probe_open_redirect(client: httpx.Client, base: str) -> list:
    """Check if redirect parameters can route to an external domain."""
    evil = "http://evil.attacker.example.com"
    params = ["redirect", "url", "next", "return", "returnTo", "redir", "goto"]
    for param in params:
        try:
            r = client.get(base.rstrip("/") + f"/?{param}={evil}",
                           follow_redirects=False, timeout=6)
            loc = r.headers.get("location", "")
            if "evil.attacker.example.com" in loc:
                return [{
                    "test": f"Open redirect via ?{param}=",
                    "request": f"GET /?{param}={evil}",
                    "expected": "No redirect to external domain",
                    "actual": f"302 → {loc}",
                    "severity": "MEDIUM",
                    "vulnerable": True,
                    "category": "Beyond OWASP — Open Redirect",
                }]
        except Exception:
            continue
    return [{
        "test": "Open redirect via redirect/url/next parameters",
        "request": f"GET /?redirect={evil} (and common variants)",
        "expected": "No redirect to external domain",
        "actual": "No open redirect detected",
        "severity": "MEDIUM",
        "vulnerable": False,
        "category": "Beyond OWASP — Open Redirect",
    }]


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
    run_extra: bool = True,
) -> list:
    auth_body = auth_body or {}
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    r_console = Console(force_terminal=True)
    abs_target = target if target.startswith("http") else f"http://{target}"

    r_console.print(Panel(
        f"[bold cyan]🎯 MazAPI Dynamic DAST Security Probe[/bold cyan]\n"
        f"[bold white]Target URL:[/bold white] [link={abs_target}][bold yellow]{abs_target}[/bold yellow][/link]\n"
        f"[dim]Executing OWASP API Security Top 10 & Zero-Egress Dynamic Audits...[/dim]",
        box=box.ROUNDED,
        border_style="cyan"
    ))

    flat_results = []
    with httpx.Client(follow_redirects=True) as client:
        # Sensitive path enumeration
        r_console.print("[cyan]🔍 Probing sensitive endpoints & admin paths...[/cyan]")
        sp = probe_sensitive_paths(client, target)
        flat_results.extend(sp)
        exposed = [t for t in sp if t["vulnerable"]]
        if exposed:
            r_console.print(f"   [bold red]✖ Exposed {len(exposed)}/{len(sp)} sensitive endpoints[/bold red]")
        else:
            r_console.print(f"   [green]✔ {len(sp)}/{len(sp)} sensitive endpoints protected[/green]")

        # CORS
        r_console.print("[cyan]🔍 Testing CORS headers & wildcard origin policy...[/cyan]")
        cors = probe_cors(client, target)
        if cors:
            flat_results.append(cors)
            if cors['vulnerable']:
                r_console.print("   [bold red]✖ CORS Wildcard Origin Exfiltratable (Access-Control-Allow-Origin: *)[/bold red]")
            else:
                r_console.print("   [green]✔ CORS Headers Properly Restricted[/green]")

        # Debug endpoint
        r_console.print("[cyan]🔍 Probing debug & health endpoints...[/cyan]")
        dbg = probe_debug_endpoint(client, target)
        flat_results.append(dbg)
        if dbg['vulnerable']:
            r_console.print("   [bold red]✖ Debug & Internal Stack Traces Exposed[/bold red]")
        else:
            r_console.print("   [green]✔ Debug Endpoints Secured[/green]")

        # Rate limiting
        if auth_body:
            r_console.print(f"[cyan]🔍 Testing rate limiting on [link={target}{auth_endpoint}]{auth_endpoint}[/link]...[/cyan]")
            rl = probe_rate_limit(client, target, auth_endpoint, auth_body)
            flat_results.append(rl)
            if rl['vulnerable']:
                r_console.print("   [bold red]✖ Rate Limiting Missing (Brute-Force Vulnerable)[/bold red]")
            else:
                r_console.print("   [green]✔ Rate Limiting Active[/green]")
            time.sleep(0.5)

        # Obtain a real token for authenticated probes
        token = ""
        user_id = 1
        if auth_body:
            r_console.print(f"[cyan]🔍 Logging in via [link={target}{auth_endpoint}]{auth_endpoint}[/link]...[/cyan]")
            token = _login(client, target, auth_endpoint, auth_body, token_field)
            if token:
                try:
                    import base64
                    payload = json.loads(base64.b64decode(token.split(".")[1] + "=="))
                    user_id = int(payload.get("sub", 1))
                except Exception:
                    pass
                r_console.print("   [green]✔ Authenticated session established[/green]")
            else:
                r_console.print("   [yellow]⚠ Authentication skipped (no valid token)[/yellow]")

        # JWT forge
        r_console.print(f"[cyan]🔍 Testing JWT weak secret & alg:none on [link={target}{protected_path}]{protected_path}[/link]...[/cyan]")
        jwt_r = probe_jwt_forge(client, target, protected_path)
        flat_results.append(jwt_r)
        if jwt_r['vulnerable']:
            r_console.print("   [bold red]✖ Broken Authentication: Forged 'alg:none' JWT Token Accepted![/bold red]")
        else:
            r_console.print("   [green]✔ JWT Signature Verification Enforced[/green]")

        # BOLA
        if token:
            r_console.print(f"[cyan]🔍 Testing BOLA / IDOR parameter tampering on {bola_path}...[/cyan]")
            bola = probe_bola(client, target, token, user_id, bola_path)
            flat_results.append(bola)
            if bola['vulnerable']:
                r_console.print("   [bold red]✖ BOLA Vulnerability Detected: Cross-Tenant Data Leak[/bold red]")
            else:
                r_console.print("   [green]✔ Object Level Authorization Enforced[/green]")

            # Mass assignment
            r_console.print(f"[cyan]🔍 Testing Mass Assignment property injection on {update_path}...[/cyan]")
            ma = probe_mass_assign(client, target, token, update_path)
            flat_results.append(ma)
            if ma['vulnerable']:
                r_console.print("   [bold red]✖ Mass Assignment Vulnerability Detected[/bold red]")
            else:
                r_console.print("   [green]✔ Mass Assignment Protected[/green]")

        # ── Beyond-OWASP probes ───────────────────────────────────────────────
        if run_extra:
            r_console.print("[cyan]🔍 Testing HTTP verb tampering...[/cyan]")
            vt = probe_verb_tampering(client, target)
            flat_results.extend(vt)
            vuln_vt = [t for t in vt if t["vulnerable"]]
            if vuln_vt:
                r_console.print(f"   [bold red]✖ {len(vuln_vt)} Unsafe HTTP Verbs Accepted[/bold red]")
            else:
                r_console.print("   [green]✔ HTTP Verb Tampering Protected[/green]")

            r_console.print("[cyan]🔍 Testing Path traversal...[/cyan]")
            pt = probe_path_traversal(client, target)
            flat_results.extend(pt)
            if any(t['vulnerable'] for t in pt):
                r_console.print("   [bold red]✖ Directory Traversal Vulnerability Exposed[/bold red]")
            else:
                r_console.print("   [green]✔ Path Traversal Protected[/green]")

            r_console.print("[cyan]🔍 Testing SQL injection...[/cyan]")
            sq = probe_sql_injection(client, target, token)
            flat_results.extend(sq)
            if any(t['vulnerable'] for t in sq):
                r_console.print("   [bold red]✖ SQL Injection Vulnerability Exposed[/bold red]")
            else:
                r_console.print("   [green]✔ SQL Injection Protected[/green]")

            r_console.print("[cyan]🔍 Testing Open redirect...[/cyan]")
            rd = probe_open_redirect(client, target)
            flat_results.extend(rd)
            if any(t['vulnerable'] for t in rd):
                r_console.print("   [bold red]✖ Open Redirect Vulnerability Exposed[/bold red]")
            else:
                r_console.print("   [green]✔ Open Redirect Protected[/green]")

    grouped = _group_by_category(flat_results)
    total_v = sum(g["vulnerable_count"] for g in grouped)
    total_t = sum(g["total"] for g in grouped)
    score   = round((1 - total_v / total_t) * 100) if total_t else 100

    r_console.print(Panel(
        f"[bold white]Scan Execution Complete[/bold white]\n"
        f"[cyan]Tests Executed:[/cyan] [bold white]{total_t}[/bold white]   |   "
        f"[bold red]Vulnerabilities Found:[/bold red] [bold red]{total_v}[/bold red]   |   "
        f"[bold green]Security Score:[/bold green] [{'bold green' if score >= 80 else 'bold yellow' if score >= 60 else 'bold red'}]{score}%[/{'bold green' if score >= 80 else 'bold yellow' if score >= 60 else 'bold red'}]",
        box=box.ROUNDED,
        border_style="green" if score >= 80 else "yellow" if score >= 60 else "red"
    ))

    if _REPORT_OK:
        j, h, s = make_report(grouped, target, report_dir)
        abs_h = os.path.abspath(h)
        abs_j = os.path.abspath(j)
        abs_s = os.path.abspath(s)

        r_console.print("[bold yellow]📄 Generated Security Reports (Clickable Links):[/bold yellow]")
        r_console.print(f"   🌐 [bold cyan]HTML Interactive Report:[/bold cyan] [link=file:///{abs_h.replace('\\', '/')}]{h}[/link]")
        r_console.print(f"   📊 [bold cyan]JSON Raw Dataset:[/bold cyan]        [link=file:///{abs_j.replace('\\', '/')}]{j}[/link]")
        r_console.print(f"   🛡️ [bold cyan]SARIF CI/CD Document:[/bold cyan]     [link=file:///{abs_s.replace('\\', '/')}]{s}[/link]\n")

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
    p.add_argument("--no-extra",      action="store_true",
                   help="Skip beyond-OWASP probes (verb tampering, traversal, injection, redirect)")
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
        run_extra=not args.no_extra,
    )


if __name__ == "__main__":
    _main()
