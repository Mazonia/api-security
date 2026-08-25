#!/usr/bin/env python3
"""MazAPI Unified CLI — Enterprise App Surface, Agent Audit, MCP Audit, IoT & DAST Security Suite."""

import argparse
import json
import os
import sys

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console(force_terminal=True)

BANNER_ART = """[bold cyan]
 █▀▄▀█ █▀█ ▀█ⴁ █▀█ █▀█ █
 █ ▀ █ █▀█ █▄▄ █▀█ █▀▀ █[/bold cyan] [bold green]v2.5.0[/bold green] [dim]— Enterprise API & AI Security Intelligence Platform[/dim]
"""

def print_welcome_banner():
    console.print(Panel(
        f"{BANNER_ART}\n"
        "[bold white]Open-Source Zero-Egress Security Discovery, AI Agent Governance & Dynamic DAST[/bold white]\n\n"
        "[dim]Repository: https://github.com/Mazonia/api-security | UMaT Cybersecurity Lab II[/dim]",
        box=box.ROUNDED,
        border_style="cyan",
        title="[bold green]⚡ MazAPI CLI Security Suite[/bold green]",
        subtitle="[bold yellow]Type 'mazapi <command> --help' for details[/bold yellow]"
    ))

    table = Table(title="[bold white]Available MazAPI CLI Subcommands & Capabilities[/bold white]", header_style="bold magenta", box=box.SIMPLE_HEAD)
    table.add_column("Command", style="bold cyan", width=16)
    table.add_column("Subcommand / Action", style="yellow", width=22)
    table.add_column("Description & Key Features", style="white")

    table.add_row(
        "app-surface",
        "scan <path>",
        "Static AST route & parameter discovery across 7 ecosystems (Python, Node, Java, .NET, Go, PHP, C/C++)"
    )
    table.add_row(
        "agent-audit",
        "scan <path>",
        "Audit 11+ AI Agent frameworks for authorization gaps, confused deputy & export CycloneDX 1.6 AI-BOM"
    )
    table.add_row(
        "mcp-audit",
        "scan | source-scan",
        "Scan local IDE & repository Model Context Protocol (MCP) servers for shell/path injection sinks"
    )
    table.add_row(
        "iot-audit",
        "--target <url>",
        "Dynamic & static IoT protocol security scanner for MQTT wildcard topics, CoAP, and unsigned OTA updates"
    )
    table.add_row(
        "scan",
        "--target <url>",
        "Active OWASP API Top 10 dynamic DAST security scanner with automated SARIF & HTML reports"
    )
    table.add_row(
        "train-models",
        "train-models",
        "Train 32-feature calibrated ML anomaly detector (Random Forest + Isolation Forest ensemble)"
    )

    console.print(table)

    console.print(Panel(
        "[bold yellow]💡 Quick Start Examples:[/bold yellow]\n\n"
        "  [cyan]mazapi app-surface scan ./api-security-project/vulnerable-api --format table[/cyan]\n"
        "  [cyan]mazapi agent-audit scan ./api-security-project/agent_audit --governance[/cyan]\n"
        "  [cyan]mazapi iot-audit --target http://localhost:8000[/cyan]\n"
        "  [cyan]mazapi scan --target http://localhost:8000 --format sarif -o report.sarif[/cyan]\n"
        "  [cyan]mazapi mcp-audit registry[/cyan]",
        box=box.ROUNDED,
        border_style="cyan"
    ))


def cmd_app_surface(args):
    from app_surface.scanner import AppSurfaceScanner
    scanner = AppSurfaceScanner(target_dir=args.path)
    res = scanner.scan(baseline_path=args.baseline)

    if args.update_baseline:
        scanner.diff_engine.save_baseline(res["endpoints"], args.update_baseline)
        console.print(f"[green]✔ Baseline snapshot updated -> {args.update_baseline}[/]")

    if args.format == "table":
        scanner.print_report(res)
    elif args.format == "json":
        out = json.dumps(res, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]✔ JSON report saved -> {args.output}[/]")
        else:
            print(out)
    elif args.format in ("openapi", "openapi-yaml", "openapi-json"):
        fmt = "json" if args.format == "openapi-json" else "yaml"
        out_path = args.output or f"openapi_spec.{fmt}"
        scanner.export_openapi(res["endpoints"], out_path, fmt=fmt)
        console.print(f"[green]✔ OpenAPI 3.0 specification exported -> {out_path}[/]")
    elif args.format == "asyncapi":
        out_path = args.output or "asyncapi_spec.json"
        scanner.export_asyncapi(res["endpoints"], out_path)
        console.print(f"[green]✔ AsyncAPI 3.0 IoT specification exported -> {out_path}[/]")
    elif args.format == "sarif":
        out_path = args.output or "app-surface.sarif"
        scanner.export_sarif(res, out_path)
        console.print(f"[green]✔ SARIF 2.1.0 report exported -> {out_path}[/]")

    # CI Gating
    if args.fail_on:
        threshold = args.fail_on.lower()
        if threshold in ("high", "critical") and res["high_risk_count"] > 0:
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['high_risk_count']} high-risk endpoints.[/]")
            sys.exit(1)
        elif threshold == "critical" and res["bfla_candidates"] > 0:
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['bfla_candidates']} critical BFLA endpoints.[/]")
            sys.exit(1)


def cmd_agent_audit(args):
    from agent_audit.auditor import AgentAuditor
    auditor = AgentAuditor(target_dir=args.path)
    res = auditor.audit()

    if args.format == "table":
        auditor.print_report(res, show_governance=args.governance)
    elif args.format == "json":
        out = json.dumps(res, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]✔ JSON report saved -> {args.output}[/]")
        else:
            print(out)
    elif args.format in ("cyclonedx", "ai-bom"):
        out_path = args.output or "ai-bom.json"
        auditor.export_ai_bom(res, out_path)
        console.print(f"[green]✔ CycloneDX 1.6 AI-BOM exported -> {out_path}[/]")
    elif args.format == "sarif":
        out_path = args.output or "agent-audit.sarif"
        auditor.export_sarif(res, out_path)
        console.print(f"[green]✔ SARIF 2.1.0 report exported -> {out_path}[/]")

    # CI Gating
    if args.fail_on:
        threshold = args.fail_on.lower()
        if threshold == "critical" and res["critical_count"] > 0:
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['critical_count']} critical AI agent findings.[/]")
            sys.exit(1)
        elif threshold == "high" and (res["critical_count"] > 0 or res["high_count"] > 0):
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['critical_count'] + res['high_count']} high/critical AI agent findings.[/]")
            sys.exit(1)


def cmd_mcp_audit(args):
    te_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing-engine")
    if te_dir not in sys.path:
        sys.path.insert(0, te_dir)
    import mcp_audit

    if args.mcp_cmd == "scan":
        res = mcp_audit.scan_workspace_mcp(args.path)
        print(json.dumps(res, indent=2))
    elif args.mcp_cmd == "source-scan":
        res = mcp_audit.source_scan_directory(args.path)
        console.print(f"[cyan]Scanned {res['scanned_files']} MCP server source files. Critical findings: [bold red]{res['critical_count']}[/bold red][/cyan]")
        for f in res.get("findings", []):
            console.print(f"[{f['severity']}] {f['title']} in {f['file']}:{f['line']}\n  Snippet: {f['snippet']}")
        if args.exit_code and res["critical_count"] > 0:
            sys.exit(1)
    elif args.mcp_cmd == "registry":
        table = Table(title="[bold blue]Known Model Context Protocol (MCP) Server Registry & Risk Posture[/bold blue]", header_style="bold blue")
        table.add_column("MCP Name", style="cyan", width=22)
        table.add_column("Risk Level", style="bold", width=12)
        table.add_column("Scope", style="yellow", width=22)
        table.add_column("Description", style="dim", width=45)
        for name, info in mcp_audit.MCP_REGISTRY.items():
            r_color = "red" if info["risk"] == "CRITICAL" else ("orange3" if info["risk"] == "HIGH" else "green")
            table.add_row(name, f"[{r_color}]{info['risk']}[/]", info["scope"], info["desc"])
        console.print(table)
    elif args.mcp_cmd == "explain":
        flag = args.flag
        if flag in mcp_audit.RISK_EXPLANATIONS:
            info = mcp_audit.RISK_EXPLANATIONS[flag]
            console.print(f"[bold red]{info['title']} ({info['severity']})[/]\n\n{info['description']}\n\n[bold green]Remediation Guidance:[/] {info['remediation']}")
        else:
            console.print(f"[yellow]Available risk flags:[/] {', '.join(mcp_audit.RISK_EXPLANATIONS.keys())}")


def cmd_iot_audit(args):
    te_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing-engine")
    if te_dir not in sys.path:
        sys.path.insert(0, te_dir)
    from owasp_tests.test_iot_api import run_iot_security_tests
    findings = run_iot_security_tests(args.target)
    console.print(f"[bold cyan]⚡ MazAPI IoT Security Audit Target:[/] {args.target}")
    console.print(f"Discovered [bold red]{len(findings)}[/bold red] IoT vulnerability findings.\n")
    for f in findings:
        console.print(f"[bold { 'red' if f['severity'] == 'CRITICAL' else 'yellow' }][{f['severity']}][/bold] [white]{f['title']}[/white] on [cyan]{f['endpoint']}[/cyan]\n  CWE: {f['cwe']}\n  Evidence: {f['evidence']}\n")


def cmd_dast_scan(args):
    te_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing-engine")
    if te_dir not in sys.path:
        sys.path.insert(0, te_dir)
    from generic_scan import scan_target
    console.print(f"[bold cyan]🎯 Starting MazAPI Dynamic DAST Scan for:[/] {args.target}")
    results = scan_target(args.target, auth_token=args.auth)
    
    if args.format == "json":
        out = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]✔ DAST JSON report saved -> {args.output}[/]")
        else:
            print(out)
    elif args.format == "sarif":
        from report_generator import generate_sarif_report
        sarif = generate_sarif_report(results, args.target)
        out_path = args.output or "scan-results.sarif"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        console.print(f"[green]✔ SARIF 2.1.0 report saved -> {out_path}[/]")
    else:
        # Table format summary
        table = Table(title=f"OWASP API Security DAST Scan Summary ({args.target})", header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Pass / Total", style="yellow")
        table.add_column("Status", style="bold")
        
        for cat, data in results.items():
            vuln_count = sum(1 for t in data.get("tests", []) if t.get("vulnerable"))
            tot_count = len(data.get("tests", []))
            status_str = f"[red]VULNERABLE ({vuln_count})[/red]" if vuln_count > 0 else "[green]SECURE[/green]"
            table.add_row(cat, f"{tot_count - vuln_count}/{tot_count}", status_str)
            
        console.print(table)


def cmd_train_models(args):
    from monitoring.train_model import train_and_save
    console.print("[bold cyan]🧠 Training 32-feature Random Forest & Isolation Forest ML Anomaly Ensemble...[/bold cyan]")
    train_and_save()
    console.print("[bold green]✔ ML anomaly model trained & saved successfully.[/bold green]")


def main():
    parser = argparse.ArgumentParser(
        prog="mazapi",
        description="MazAPI Enterprise API & AI Surface Security Platform",
        add_help=True
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. app-surface
    p_app = subparsers.add_parser("app-surface", help="Static code API & route discovery at PR time")
    p_app.add_argument("action", choices=["scan"], default="scan", nargs="?")
    p_app.add_argument("path", default=".", nargs="?")
    p_app.add_argument("--format", choices=["table", "json", "openapi", "openapi-yaml", "openapi-json", "asyncapi", "sarif"], default="table")
    p_app.add_argument("--output", "-o", help="Output file destination")
    p_app.add_argument("--baseline", help="Compare against baseline JSON file")
    p_app.add_argument("--update-baseline", help="Save current endpoints as new baseline JSON")
    p_app.add_argument("--fail-on", choices=["high", "critical"], help="Exit with non-zero on high or critical findings")

    # 2. agent-audit
    p_agent = subparsers.add_parser("agent-audit", help="Audit AI agents for authorization & tool call gaps")
    p_agent.add_argument("action", choices=["scan"], default="scan", nargs="?")
    p_agent.add_argument("path", default=".", nargs="?")
    p_agent.add_argument("--format", choices=["table", "json", "cyclonedx", "ai-bom", "sarif"], default="table")
    p_agent.add_argument("--output", "-o", help="Output file destination")
    p_agent.add_argument("--governance", action="store_true", help="Print EU AI Act, NIST AI RMF, and ISO 42001 clauses")
    p_agent.add_argument("--fail-on", choices=["high", "critical"], help="Exit with non-zero on high or critical findings")

    # 3. mcp-audit
    p_mcp = subparsers.add_parser("mcp-audit", help="MCP server configuration and source-level security audit")
    p_mcp.add_argument("mcp_cmd", choices=["scan", "source-scan", "registry", "explain"], default="scan")
    p_mcp.add_argument("path", default=".", nargs="?")
    p_mcp.add_argument("--flag", default="shell-injection-in-source", help="Risk flag for explain command")
    p_mcp.add_argument("--exit-code", action="store_true", help="Exit with non-zero code on critical findings")

    # 4. iot-audit
    p_iot = subparsers.add_parser("iot-audit", help="Audit IoT endpoints, MQTT brokers, CoAP, and OTA update surfaces")
    p_iot.add_argument("--target", default="http://localhost:8000", help="Target IoT API URL")

    # 5. scan (Dynamic DAST Scanner)
    p_scan = subparsers.add_parser("scan", help="Run active OWASP API Top 10 dynamic DAST security scanner")
    p_scan.add_argument("--target", default="http://localhost:8000", help="Target API URL")
    p_scan.add_argument("--auth", help="Auth token or header value (e.g. 'Bearer <jwt>')")
    p_scan.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    p_scan.add_argument("--output", "-o", help="Output report file path")

    # 6. train-models
    subparsers.add_parser("train-models", help="Train 32-feature calibrated ML anomaly and threat models")

    # Filter out stray '?' argument if user passed it
    sys_args = [arg for arg in sys.argv[1:] if arg != "?"]

    if not sys_args or sys_args[0] in ("-h", "--help"):
        print_welcome_banner()
        return

    try:
        args = parser.parse_args(sys_args)
    except SystemExit:
        return

    if args.subcommand == "app-surface":
        cmd_app_surface(args)
    elif args.subcommand == "agent-audit":
        cmd_agent_audit(args)
    elif args.subcommand == "mcp-audit":
        cmd_mcp_audit(args)
    elif args.subcommand == "iot-audit":
        cmd_iot_audit(args)
    elif args.subcommand == "scan":
        cmd_dast_scan(args)
    elif args.subcommand == "train-models":
        cmd_train_models(args)
    else:
        print_welcome_banner()


if __name__ == "__main__":
    main()
