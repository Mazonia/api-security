#!/usr/bin/env python3
"""CY384 API Security Framework — Live Demo Script.

Usage (from the api-security-project directory, with Docker Compose running):
    python demo.py

Runs 6 OWASP API Top 10:2023 attack scenarios against both the vulnerable
API (localhost:8000) and hardened API (localhost:8001), then generates a
comparison report via the monitoring service (localhost:9000).
"""
import sys

try:
    import httpx
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Missing dependencies. Run:  pip install httpx rich")
    sys.exit(1)

console = Console()

VULN = "http://localhost:8000"
HARD = "http://localhost:8001"
MON  = "http://localhost:9000"

SEV_COLOR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}


# ── helpers ────────────────────────────────────────────────────────────────────

def pause() -> None:
    console.input("\n  [dim]Press Enter to continue…[/dim] ")


def _get(url, token="", origin=""):
    h = {}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if origin:
        h["Origin"] = origin
    try:
        return httpx.get(url, headers=h, timeout=8, follow_redirects=True)
    except Exception:
        return None


def _post(url, body, token=""):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        return httpx.post(url, json=body, headers=h, timeout=8)
    except Exception:
        return None


def _put(url, body, token=""):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        return httpx.put(url, json=body, headers=h, timeout=8)
    except Exception:
        return None


def login(base):
    r = _post(base + "/auth/login", {"username": "alice", "password": "alice123"})
    if r and r.status_code == 200:
        return r.json().get("access_token", "")
    return ""


def show_table(attack, rows):
    """rows: list of (api_label, http_code, is_vulnerable)"""
    console.print(f"  [dim]Attack:[/dim] [italic]{attack}[/italic]")
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("API",         style="white",    width=24)
    tbl.add_column("HTTP Code",   justify="center", width=12)
    tbl.add_column("Verdict",     justify="center", width=18)
    for label, code, is_vuln in rows:
        c = "red" if is_vuln else "green"
        v = f"[bold {c}]{'VULNERABLE' if is_vuln else 'SECURE'}[/bold {c}]"
        tbl.add_row(label,
                    f"[{c}]{code}[/{c}]" if code else "[dim]—[/dim]",
                    v)
    console.print(tbl)


# ── scenario runners ──────────────────────────────────────────────────────────

def run_bola(v_tok, h_tok):
    vr = _get(VULN + "/users/2", v_tok)
    hr = _get(HARD + "/users/2", h_tok)
    v_code = vr.status_code if vr else None
    h_code = hr.status_code if hr else None
    show_table(
        "GET /users/2  (authenticated as alice, user_id=1)",
        [
            ("[red]Vulnerable (8000)[/red]", v_code, v_code == 200),
            ("[green]Hardened   (8001)[/green]", h_code, h_code == 200),
        ]
    )
    return v_code == 200, h_code == 200


def run_jwt():
    try:
        from jose import jwt as _jose
        forged = _jose.encode({"sub": "1", "username": "alice", "role": "admin"},
                               "secret", algorithm="HS256")
        vr = _get(VULN + "/users/1", forged)
        hr = _get(HARD + "/users/1", forged)
        v_code = vr.status_code if vr else None
        h_code = hr.status_code if hr else None
        show_table(
            "GET /users/1  (forged JWT, alg=HS256, key='secret', role='admin')",
            [
                ("[red]Vulnerable (8000)[/red]", v_code, v_code == 200),
                ("[green]Hardened   (8001)[/green]", h_code, h_code == 200),
            ]
        )
        return v_code == 200, h_code == 200
    except ImportError:
        console.print("  [yellow]python-jose not installed — skipping JWT forge test[/yellow]")
        return False, False


def run_mass(v_tok, h_tok):
    vr = _put(VULN + "/users/1", {"role": "admin", "balance": 999999}, v_tok)
    hr = _put(HARD + "/users/1", {"role": "admin", "balance": 999999}, h_tok)

    def mass_vuln(r):
        if r and r.status_code in (200, 201):
            d = r.json()
            d = d.get("user", d)
            return d.get("role") == "admin" or d.get("balance") == 999999
        return False

    v_code = vr.status_code if vr else None
    h_code = hr.status_code if hr else None
    v_vuln = mass_vuln(vr)
    h_vuln = mass_vuln(hr)

    console.print('  [dim]Attack:[/dim] [italic]PUT /users/1  {"role":"admin","balance":999999}[/italic]')
    tbl = Table(box=box.SIMPLE)
    tbl.add_column("API",       style="white",    width=24)
    tbl.add_column("HTTP Code", justify="center", width=12)
    tbl.add_column("Verdict",   justify="center", width=34)
    for label, code, is_vuln in [
        ("[red]Vulnerable (8000)[/red]", v_code, v_vuln),
        ("[green]Hardened   (8001)[/green]", h_code, h_vuln),
    ]:
        c = "red" if is_vuln else "green"
        msg = "fields accepted — VULNERABLE" if is_vuln else "fields stripped — SECURE"
        tbl.add_row(label, f"[{c}]{code}[/{c}]" if code else "[dim]—[/dim]",
                    f"[bold {c}]{msg}[/bold {c}]")
    console.print(tbl)
    return v_vuln, h_vuln


def run_rate():
    console.print("  [dim]Sending 12 rapid login attempts to each API…[/dim]")

    def test(base):
        for _ in range(12):
            r = _post(base + "/auth/login", {"username": "__probe__", "password": "x"})
            if r and r.status_code == 429:
                return True
        return False

    v_limited = test(VULN)
    h_limited = test(HARD)
    show_table(
        "POST /auth/login  x12 rapid (wrong password)",
        [
            ("[red]Vulnerable (8000)[/red]",
             "429" if v_limited else "401 (no 429)", not v_limited),
            ("[green]Hardened   (8001)[/green]",
             "429" if h_limited else "401 (no 429)", not h_limited),
        ]
    )
    return not v_limited, not h_limited


def run_func(v_tok, h_tok):
    vr = _get(VULN + "/admin/users", v_tok)
    hr = _get(HARD + "/admin/users", h_tok)
    v_code = vr.status_code if vr else None
    h_code = hr.status_code if hr else None
    show_table(
        "GET /admin/users  (regular user JWT, role='user')",
        [
            ("[red]Vulnerable (8000)[/red]", v_code, v_code == 200),
            ("[green]Hardened   (8001)[/green]", h_code, h_code == 200),
        ]
    )
    return v_code == 200, h_code == 200


def run_debug():
    vr = _get(VULN + "/debug/config")
    hr = _get(HARD + "/debug/config")
    v_code = vr.status_code if vr else None
    h_code = hr.status_code if hr else None
    show_table(
        "GET /debug/config  (no authentication)",
        [
            ("[red]Vulnerable (8000)[/red]", v_code, v_code == 200),
            ("[green]Hardened   (8001)[/green]", h_code, h_code == 200),
        ]
    )
    if vr and vr.status_code == 200:
        try:
            leaked = list(vr.json().keys())[:4]
            console.print(f"  [red]Keys exposed: {leaked}[/red]")
        except Exception:
            pass
    return v_code == 200, h_code == 200


SCENARIOS = [
    ("API1:2023", "BOLA — Broken Object Level Authorization",    "HIGH",
     "Changing the user ID in /users/{id} to access another user's data without authorisation."),
    ("API2:2023", "Broken Authentication — JWT Forgery",         "CRITICAL",
     "Forging a JWT token using the well-known weak secret 'secret' to impersonate admin."),
    ("API3:2023", "Mass Assignment — Privilege Escalation",      "HIGH",
     'Sending {"role":"admin","balance":999999} in a PUT request to self-promote to administrator.'),
    ("API4:2023", "Unrestricted Resource Consumption",           "MEDIUM",
     "Sending 12 rapid login attempts with wrong password — testing for brute-force protection."),
    ("API5:2023", "Broken Function Level Authorization",         "HIGH",
     "A regular user calling the admin-only GET /admin/users endpoint."),
    ("API8:2023", "Security Misconfiguration — Debug Endpoint",  "MEDIUM",
     "Fetching /debug/config without any credentials to leak secrets and environment variables."),
]


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel.fit(
        "[bold purple]CY384 API Security Framework[/bold purple]\n"
        "[dim]Live Demonstration — University of Mines and Technology, Ghana[/dim]\n\n"
        "[white]6 OWASP API Top 10:2023 attack scenarios[/white]\n"
        "[dim]Vulnerable API: localhost:8000  vs  Hardened API: localhost:8001[/dim]",
        box=box.DOUBLE_EDGE,
        border_style="purple",
    ))

    pause()

    # ── service check ──────────────────────────────────────────────────────────
    console.rule("[bold blue]Service Health Check[/bold blue]")
    tbl = Table(box=box.SIMPLE)
    tbl.add_column("Service",  style="white", width=22)
    tbl.add_column("URL",      style="dim",   width=32)
    tbl.add_column("Status",   justify="center", width=10)
    all_up = True
    for name, url in [("Vulnerable API", VULN), ("Hardened API", HARD), ("Monitoring", MON)]:
        r = _get(url + "/health")
        up = r is not None and r.status_code < 500
        tbl.add_row(name, url,
                    "[bold green]UP[/bold green]" if up else "[bold red]DOWN[/bold red]")
        if not up:
            all_up = False
    console.print(tbl)
    if not all_up:
        console.print("\n[red bold]One or more services are down. Start the lab first:[/red bold]")
        console.print("[dim]  docker compose up -d --build[/dim]\n")
        sys.exit(1)

    pause()

    # ── login ──────────────────────────────────────────────────────────────────
    console.print("[yellow]Authenticating as alice on both APIs…[/yellow]")
    v_token = login(VULN)
    h_token = login(HARD)
    console.print(
        f"  Vulnerable API: [{'green' if v_token else 'red'}]"
        f"{'token obtained' if v_token else 'login failed'}[/]"
    )
    console.print(
        f"  Hardened   API: [{'green' if h_token else 'red'}]"
        f"{'token obtained' if h_token else 'login failed'}[/]"
    )

    scenario_fns = [
        lambda: run_bola(v_token, h_token),
        run_jwt,
        lambda: run_mass(v_token, h_token),
        run_rate,
        lambda: run_func(v_token, h_token),
        run_debug,
    ]

    v_total_vuln = 0
    h_total_vuln = 0

    for i, ((owasp_id, title, severity, desc), fn) in enumerate(
            zip(SCENARIOS, scenario_fns), 1):
        sev_c = SEV_COLOR.get(severity, "white")
        pause()
        console.rule(f"[bold cyan]Scenario {i}/{len(SCENARIOS)}[/bold cyan]")
        console.print(Panel(
            f"[bold]{owasp_id}[/bold] — {title}\n[dim]{desc}[/dim]",
            subtitle=f"[{sev_c}]Severity: {severity}[/{sev_c}]",
            border_style="cyan",
            padding=(0, 1),
        ))
        v_vuln, h_vuln = fn()
        if v_vuln:
            v_total_vuln += 1
        if h_vuln:
            h_total_vuln += 1

    # ── summary ────────────────────────────────────────────────────────────────
    pause()
    console.rule("[bold]Results Summary[/bold]")
    n = len(SCENARIOS)
    v_score = round((n - v_total_vuln) / n * 100)
    h_score = round((n - h_total_vuln) / n * 100)
    improvement = h_score - v_score
    imp_c = "green" if improvement > 0 else "red" if improvement < 0 else "yellow"
    imp_s = "+" if improvement > 0 else ""

    console.print(Panel(
        f"[bold red]Vulnerable API:[/bold red]  {v_total_vuln}/{n} vulnerable  —  "
        f"[bold]{v_score}%[/bold] security score\n"
        f"[bold green]Hardened API:[/bold green]    {h_total_vuln}/{n} vulnerable  —  "
        f"[bold]{h_score}%[/bold] security score\n"
        f"[bold {imp_c}]Improvement:[/bold {imp_c}]       [{imp_c}]{imp_s}{improvement} pp[/{imp_c}]\n\n"
        f"[dim]The hardened API blocked {max(0, v_total_vuln - h_total_vuln)} "
        f"of {v_total_vuln} vulnerabilities.[/dim]",
        title="[bold]DEMO COMPLETE[/bold]",
        box=box.DOUBLE_EDGE,
    ))

    # ── generate report ────────────────────────────────────────────────────────
    pause()
    console.print("[yellow]Generating comparison report via monitoring API…[/yellow]")
    try:
        r = httpx.post(f"{MON}/monitor/run-comparison", json={}, timeout=90)
        if r.status_code == 200:
            data = r.json()
            console.print(f"[green]Report saved:[/green]  {data.get('html_file', '?')}")
            console.print(
                f"[blue]Open in browser:[/blue]  "
                f"http://localhost:9000/monitor/reports/{data.get('html_file', '')}"
            )
        else:
            console.print(f"[red]HTTP {r.status_code} from monitoring API[/red]")
    except Exception as e:
        console.print(f"[yellow]Could not reach monitoring API: {e}[/yellow]")
        console.print(
            "[dim]Generate manually: "
            "http://localhost:9000/dashboard → Reports tab → Run Comparison[/dim]"
        )

    console.print()


if __name__ == "__main__":
    main()
