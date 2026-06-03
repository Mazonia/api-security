#!/usr/bin/env python3
"""OWASP API Security Testing Engine — runs all 6 test modules and emits reports."""
import os
import sys
import time

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from owasp_tests import (test_api1_bola, test_api2_auth, test_api3_mass_assign,
                         test_api4_rate_limit, test_api5_func_auth, test_api8_misconfig,
                         test_graphql, test_pii)
import report_generator

console = Console()

MODULES = [
    ("API1:2023 — BOLA",                      test_api1_bola),
    ("API2:2023 — Broken Authentication",      test_api2_auth),
    ("API3:2023 — Mass Assignment",            test_api3_mass_assign),
    ("API4:2023 — Rate Limiting",              test_api4_rate_limit),
    ("API5:2023 — Function Level Auth",        test_api5_func_auth),
    ("API8:2023 — Misconfiguration",           test_api8_misconfig),
    ("API9:2023 — GraphQL Security",           test_graphql),
    ("GDPR/CWE-312 — PII Exposure",           test_pii),
]

SEV_COLOR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}


def wait_for_target(url: str, timeout: int = 90) -> bool:
    console.print(f"[yellow]Waiting for {url} ...[/yellow]")
    for _ in range(timeout):
        try:
            httpx.get(f"{url}/health", timeout=2)
            console.print("[green]Target ready.[/green]")
            return True
        except Exception:
            time.sleep(1)
    return False


def main() -> None:
    target     = os.getenv("TARGET", "http://vulnerable-api:8000")
    report_dir = os.getenv("REPORT_DIR", "/reports")

    console.print(Panel.fit(
        f"[bold blue]OWASP API Security Scanner[/bold blue]\n[dim]Target: {target}[/dim]",
        box=box.DOUBLE_EDGE,
    ))

    if not wait_for_target(target):
        console.print("[red]Target not reachable after 90 s — aborting.[/red]")
        sys.exit(1)

    all_results = []

    for name, module in MODULES:
        console.print(f"\n[bold cyan]▶ {name}[/bold cyan]")
        try:
            result = module.run(target)
            all_results.append(result)

            tbl = Table(box=box.SIMPLE, show_header=True)
            tbl.add_column("Test", style="white", max_width=45)
            tbl.add_column("Severity", justify="center", width=10)
            tbl.add_column("Result",   justify="center", width=12)

            for t in result["tests"]:
                col = SEV_COLOR.get(t["severity"], "white")
                res = "[red]VULNERABLE[/red]" if t["vulnerable"] else "[green]SECURE[/green]"
                tbl.add_row(t["test"], f"[{col}]{t['severity']}[/{col}]", res)

            console.print(tbl)
            v, tot = result["vulnerable_count"], result["total"]
            console.print(f"  [dim]{v}/{tot} tests vulnerable[/dim]")
        except Exception as exc:
            console.print(f"[red]  Error running {name}: {exc}[/red]")

    total_vuln  = sum(r["vulnerable_count"] for r in all_results)
    total_tests = sum(r["total"] for r in all_results)
    score = max(0, (1 - total_vuln / total_tests) * 100) if total_tests else 100

    console.print(Panel(
        f"[bold]Tests run:[/bold] {total_tests}\n"
        f"[bold red]Vulnerable:[/bold red] {total_vuln}\n"
        f"[bold green]Secure:[/bold green] {total_tests - total_vuln}\n"
        f"[bold cyan]Security score:[/bold cyan] {score:.0f}%",
        title="[bold]SCAN COMPLETE[/bold]",
        box=box.DOUBLE_EDGE,
    ))

    json_path, html_path, sarif_path = report_generator.generate(
        all_results, target, report_dir,
        detail=os.getenv("REPORT_DETAIL", "brief"),
    )
    console.print(f"\n[green]Reports saved:[/green]")
    console.print(f"  JSON  → {json_path}")
    console.print(f"  HTML  → {html_path}")
    console.print(f"  SARIF → {sarif_path}")

    # Optional webhook notification
    webhook_url = os.getenv("WEBHOOK_URL", "")
    if webhook_url:
        try:
            import urllib.request, json as _json
            vuln_list = [t for r in all_results for t in r["tests"] if t.get("vulnerable")]
            critical  = [t for t in vuln_list if t.get("severity") == "CRITICAL"]
            payload   = {
                "source": "MazAPI Testing Engine",
                "target": target,
                "score": round(score, 1),
                "total_tests": total_tests,
                "vulnerable": total_vuln,
                "critical": len(critical),
                "text": f"*MazAPI Scan* — `{target}`\nScore: *{score:.0f}%* | Vulnerable: {total_vuln}/{total_tests} | Critical: {len(critical)}",
            }
            data = _json.dumps(payload).encode()
            req  = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=8)
            console.print("[green]  Webhook notification sent.[/green]")
        except Exception as exc:
            console.print(f"[yellow]  Webhook failed: {exc}[/yellow]")


if __name__ == "__main__":
    main()
