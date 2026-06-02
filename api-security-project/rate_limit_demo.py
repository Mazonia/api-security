#!/usr/bin/env python3
"""
API4:2023 — Unrestricted Resource Consumption
Rate-limit brute-force demonstration script.

Sends rapid login attempts against both the Vulnerable API (no rate limiting)
and the Hardened API (5 requests/minute limit per IP) so you can see the
difference side by side in the terminal and on the monitoring dashboard.

Usage:
    python rate_limit_demo.py
"""
import sys
import time

try:
    import httpx
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.rule import Rule
except ImportError:
    print("Missing dependencies. Run:  pip install httpx rich")
    sys.exit(1)

console = Console()

PROXY = "http://localhost:9000"   # all traffic routed through monitoring proxy

# ── Preset options — controlled so the user cannot send unreasonable volumes ──
PRESETS = {
    "1": {
        "label": "Light   --  6 requests, 0.3 s apart",
        "count": 6,
        "delay": 0.3,
        "desc":  "Just enough to trip the 5/min limit on the hardened API.",
    },
    "2": {
        "label": "Medium  -- 12 requests, 0.1 s apart",
        "count": 12,
        "delay": 0.1,
        "desc":  "Simulates a slow password-spray attack.",
    },
    "3": {
        "label": "Heavy   -- 20 requests, no delay (rapid fire)",
        "count": 20,
        "delay": 0.0,
        "desc":  "Simulates automated brute-force, triggers 429 early.",
    },
    "4": {
        "label": "Burst   -- 30 requests, no delay (full demo)",
        "count": 30,
        "delay": 0.0,
        "desc":  "Maximum demo preset. Shows sustained blocking on hardened API.",
    },
}


def print_menu() -> str:
    console.print()
    console.print(Panel.fit(
        "[bold yellow]API4:2023 - Unrestricted Resource Consumption[/bold yellow]\n"
        "[dim]Brute-force login simulation against Vulnerable vs Hardened API[/dim]",
        border_style="yellow",
        box=box.DOUBLE_EDGE,
    ))
    console.print()
    console.print("  [bold]Select a preset:[/bold]\n")
    for key, p in PRESETS.items():
        console.print(f"  [cyan]{key}[/cyan]  {p['label']}")
        console.print(f"      [dim]{p['desc']}[/dim]")
    console.print()

    while True:
        choice = Prompt.ask("  Enter preset number", choices=list(PRESETS.keys()))
        return choice


def run_attack(label: str, color: str, count: int, delay: float,
               extra_headers: dict | None = None) -> list[dict]:
    results = []
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    console.print(f"\n  [bold {color}]{label}[/bold {color}]")

    for i in range(1, count + 1):
        t0 = time.perf_counter()
        try:
            r = httpx.post(
                f"{PROXY}/auth/login",
                json={"username": "attacker", "password": f"guess{i}"},
                headers=headers,
                timeout=6,
            )
            code = r.status_code
        except Exception:
            code = None
        elapsed = round((time.perf_counter() - t0) * 1000)

        if code == 429:
            status_str = f"[bold red]429 BLOCKED[/bold red]"
        elif code == 401:
            status_str = f"[yellow]401 wrong creds[/yellow]"
        elif code is None:
            status_str = f"[dim]ERR timeout[/dim]"
        else:
            status_str = f"[dim]{code}[/dim]"

        console.print(f"    Attempt {i:>2}/{count}  {status_str}  [dim]{elapsed} ms[/dim]")
        results.append({"attempt": i, "code": code, "ms": elapsed})

        if delay > 0 and i < count:
            time.sleep(delay)

    return results


def summary_table(vuln_results: list, hard_results: list, count: int):
    vuln_blocked = sum(1 for r in vuln_results if r["code"] == 429)
    hard_blocked = sum(1 for r in hard_results if r["code"] == 429)

    vuln_first_block = next((r["attempt"] for r in vuln_results if r["code"] == 429), None)
    hard_first_block = next((r["attempt"] for r in hard_results if r["code"] == 429), None)

    console.print()
    console.rule("[bold]Results Summary[/bold]")
    console.print()

    tbl = Table(box=box.ROUNDED, show_header=True)
    tbl.add_column("",               style="white",  width=28)
    tbl.add_column("Vulnerable API", justify="center", width=20)
    tbl.add_column("Hardened API",   justify="center", width=20)

    tbl.add_row(
        "Total attempts sent",
        str(count), str(count),
    )
    tbl.add_row(
        "Requests blocked (429)",
        f"[{'red' if vuln_blocked else 'green'}]{vuln_blocked}[/]",
        f"[{'green' if hard_blocked else 'red'}]{hard_blocked}[/]",
    )
    tbl.add_row(
        "First block at attempt #",
        "[dim]Never[/dim]" if vuln_first_block is None else f"[red]{vuln_first_block}[/red]",
        "[dim]Never[/dim]" if hard_first_block is None else f"[green]{hard_first_block}[/green]",
    )
    tbl.add_row(
        "Rate-limit enforced?",
        "[bold red]NO  — VULNERABLE[/bold red]",
        "[bold green]YES — SECURE[/bold green]",
    )

    console.print(tbl)
    console.print()

    if hard_blocked:
        console.print(
            f"  [green]The hardened API started blocking after attempt "
            f"{hard_first_block} (HTTP 429 Too Many Requests).[/green]\n"
            f"  [dim]The vulnerable API accepted all {count} attempts with no throttling.[/dim]"
        )
    else:
        console.print(
            f"  [yellow]The hardened API did not return 429 in this run.[/yellow]\n"
            f"  [dim]Try the Heavy or Burst preset — the limit is 5 per minute per IP.[/dim]"
        )

    console.print()
    console.print(
        "  [blue]Open the monitoring dashboard to see these requests logged:[/blue]\n"
        "  [dim]http://localhost:9000/dashboard  →  Anomalies tab[/dim]\n"
        "  [dim]429 responses are flagged as [bold]rate_limit_triggered[/bold] (score -0.5)[/dim]"
    )
    console.print()


def main():
    choice = print_menu()
    preset = PRESETS[choice]
    count  = preset["count"]
    delay  = preset["delay"]

    console.print()
    console.rule(f"[yellow]Running: {preset['label']}[/yellow]")
    console.print(
        f"\n  [dim]Sending [bold]{count}[/bold] login attempts with wrong credentials "
        f"({'no delay' if delay == 0 else f'{delay}s between each'}).[/dim]\n"
        f"  [dim]All traffic routes through the monitoring proxy (port 9000)[/dim]\n"
        f"  [dim]Watch the dashboard live: "
        f"http://localhost:9000/dashboard -> Anomalies tab[/dim]"
    )

    vuln_results = run_attack("Vulnerable API  (via proxy, no rate limit)", "red",   count, delay)
    hard_results = run_attack("Hardened API    (via proxy, 5/min limit)",   "green", count, delay,
                              extra_headers={"X-Target": "hardened"})

    summary_table(vuln_results, hard_results, count)


if __name__ == "__main__":
    main()
