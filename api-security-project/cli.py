#!/usr/bin/env python3
"""MazAPI Unified CLI — Enterprise App Surface, Agent Audit, MCP Audit, IoT & DAST Security Suite."""

import argparse
import json
import os
import shlex
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
 █ ▀ █ █▀█ █▄▄ █▀█ █▀▀ █[/bold cyan] [bold green]v2.5.0[/bold green] [dim]— Enterprise Security Intelligence Console[/dim]
"""

def print_welcome_banner():
    console.print(Panel(
        f"{BANNER_ART}\n"
        "[bold white]Open-Source Zero-Egress Security Discovery, AI Agent Governance & Dynamic DAST[/bold white]\n"
        "[dim]Repository: https://github.com/Mazonia/api-security | UMaT Cybersecurity Lab II[/dim]",
        box=box.ROUNDED,
        border_style="cyan",
        title="[bold green]⚡ MazAPI Security Suite[/bold green]",
        subtitle="[bold yellow]Type 'help' or 'mazapi <command> -h' for guidance[/bold yellow]"
    ))

    table = Table(
        title="[bold white]Subcommands & Short Single-Letter Aliases[/bold white]",
        header_style="bold magenta",
        box=box.SIMPLE_HEAD
    )
    table.add_column("Alias", style="bold yellow", width=8)
    table.add_column("Full Command", style="bold cyan", width=18)
    table.add_column("Action / Flags", style="green", width=22)
    table.add_column("Description", style="white")

    table.add_row(
        "s",
        "scan",
        "-t <url> [-f s|j|t]",
        "Active OWASP API Top 10 dynamic DAST vulnerability scanner"
    )
    table.add_row(
        "a",
        "app-surface",
        "scan [path] [-f t|j|o|a|s]",
        "Static AST route discovery across 7 languages & PR diffs"
    )
    table.add_row(
        "g",
        "agent-audit",
        "scan [path] [-g] [-f ai-bom]",
        "Audit AI agent graphs, confused deputy & export CycloneDX AI-BOM"
    )
    table.add_row(
        "m",
        "mcp-audit",
        "scan | source-scan | registry",
        "Audit Model Context Protocol (MCP) server configs & code"
    )
    table.add_row(
        "i",
        "iot-audit",
        "-t <url>",
        "Audit IoT endpoints, MQTT wildcard ACLs, CoAP & OTA firmware"
    )
    table.add_row(
        "t",
        "train-models",
        "train-models",
        "Train 32-feature Random Forest & Isolation Forest ML model"
    )
    table.add_row(
        "sh",
        "shell",
        "interactive",
        "Launch interactive Cyber REPL console with custom prompt"
    )

    console.print(table)

    console.print(Panel(
        "[bold yellow]💡 Quick Single-Letter Command Examples:[/bold yellow]\n\n"
        "  [cyan]s -t http://localhost:8000[/cyan]                               [dim]# Run active DAST scan[/dim]\n"
        "  [cyan]a scan ./api-security-project/vulnerable-api -f t[/cyan]     [dim]# Scan code AST routes[/dim]\n"
        "  [cyan]g scan ./api-security-project/agent_audit -g[/cyan]          [dim]# Audit AI agent governance[/dim]\n"
        "  [cyan]m registry[/cyan]                                                [dim]# View MCP server risk registry[/dim]\n"
        "  [cyan]i -t http://localhost:8000[/cyan]                               [dim]# Audit IoT security surface[/dim]",
        box=box.ROUNDED,
        border_style="cyan"
    ))


def run_interactive_shell(parser):
    """Launches an interactive Cyber REPL Shell with custom prompt."""
    console.clear()
    console.print(Panel(
        f"{BANNER_ART}\n"
        "[bold green]Interactive MazAPI Cyber REPL Console Enabled![/bold green]\n"
        "[dim]You are now inside the custom MazAPI environment. No need to type 'mazapi' before commands.[/dim]\n"
        "[bold yellow]Type 's', 'a', 'g', 'm', 'i', 't' or 'help'. Type 'exit' or 'q' to quit.[/bold yellow]",
        box=box.ROUNDED,
        border_style="cyan",
        title="[bold green]⚡ MazAPI Cyber Console REPL[/bold green]"
    ))

    prompt = "[bold cyan]⚡ mazapi[/bold cyan] [bold green](security-suite)[/bold green] [bold yellow]❯[/bold yellow] "

    while True:
        try:
            cmd_line = console.input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Exiting MazAPI Cyber Console. Goodbye![/yellow]")
            break

        if not cmd_line:
            continue

        if cmd_line.lower() in ("exit", "quit", "q"):
            console.print("[green]✔ Exiting MazAPI Cyber Console. Have a secure day![/green]")
            break
        elif cmd_line.lower() in ("clear", "cls"):
            console.clear()
            continue
        elif cmd_line.lower() in ("help", "h", "?"):
            print_welcome_banner()
            continue

        try:
            tokens = shlex.split(cmd_line)
        except Exception as err:
            console.print(f"[red]Error parsing command tokens: {err}[/red]")
            continue

        # Process single command execution within REPL
        execute_args(tokens, parser, in_repl=True)


def cmd_app_surface(args):
    from app_surface.scanner import AppSurfaceScanner
    scanner = AppSurfaceScanner(target_dir=args.path)
    res = scanner.scan(baseline_path=args.baseline)

    if args.update_baseline:
        scanner.diff_engine.save_baseline(res["endpoints"], args.update_baseline)
        console.print(f"[green]✔ Baseline snapshot updated -> {args.update_baseline}[/green]")

    fmt = args.format.lower()
    if fmt in ("table", "t"):
        scanner.print_report(res)
    elif fmt in ("json", "j"):
        out = json.dumps(res, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]✔ JSON report saved -> {args.output}[/green]")
        else:
            print(out)
    elif fmt in ("openapi", "openapi-yaml", "openapi-json", "o"):
        out_fmt = "json" if fmt == "openapi-json" else "yaml"
        out_path = args.output or f"openapi_spec.{out_fmt}"
        scanner.export_openapi(res["endpoints"], out_path, fmt=out_fmt)
        console.print(f"[green]✔ OpenAPI 3.0 specification exported -> {out_path}[/green]")
    elif fmt in ("asyncapi", "a"):
        out_path = args.output or "asyncapi_spec.json"
        scanner.export_asyncapi(res["endpoints"], out_path)
        console.print(f"[green]✔ AsyncAPI 3.0 IoT specification exported -> {out_path}[/green]")
    elif fmt in ("sarif", "s"):
        out_path = args.output or "app-surface.sarif"
        scanner.export_sarif(res, out_path)
        console.print(f"[green]✔ SARIF 2.1.0 report exported -> {out_path}[/green]")

    # CI Gating
    if args.fail_on:
        threshold = args.fail_on.lower()
        if threshold in ("high", "critical") and res["high_risk_count"] > 0:
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['high_risk_count']} high-risk endpoints.[/red bold]")
            sys.exit(1)
        elif threshold == "critical" and res["bfla_candidates"] > 0:
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['bfla_candidates']} critical BFLA endpoints.[/red bold]")
            sys.exit(1)


def cmd_agent_audit(args):
    from agent_audit.auditor import AgentAuditor
    auditor = AgentAuditor(target_dir=args.path)
    res = auditor.audit()

    fmt = args.format.lower()
    if fmt in ("table", "t"):
        auditor.print_report(res, show_governance=args.governance)
    elif fmt in ("json", "j"):
        out = json.dumps(res, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]✔ JSON report saved -> {args.output}[/green]")
        else:
            print(out)
    elif fmt in ("cyclonedx", "ai-bom", "a"):
        out_path = args.output or "ai-bom.json"
        auditor.export_ai_bom(res, out_path)
        console.print(f"[green]✔ CycloneDX 1.6 AI-BOM exported -> {out_path}[/green]")
    elif fmt in ("sarif", "s"):
        out_path = args.output or "agent-audit.sarif"
        auditor.export_sarif(res, out_path)
        console.print(f"[green]✔ SARIF 2.1.0 report exported -> {out_path}[/green]")

    # CI Gating
    if args.fail_on:
        threshold = args.fail_on.lower()
        if threshold == "critical" and res["critical_count"] > 0:
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['critical_count']} critical AI agent findings.[/red bold]")
            sys.exit(1)
        elif threshold == "high" and (res["critical_count"] > 0 or res["high_count"] > 0):
            console.print(f"[red bold]✖ CI Gate Failed: Found {res['critical_count'] + res['high_count']} high/critical AI agent findings.[/red bold]")
            sys.exit(1)


def cmd_mcp_audit(args):
    te_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing-engine")
    if te_dir not in sys.path:
        sys.path.insert(0, te_dir)
    import mcp_audit

    mcp_action = args.mcp_cmd.lower()
    if mcp_action in ("scan", "s"):
        res = mcp_audit.scan_workspace_mcp(args.path)
        print(json.dumps(res, indent=2))
    elif mcp_action in ("source-scan", "src"):
        res = mcp_audit.source_scan_directory(args.path)
        console.print(f"[cyan]Scanned {res['scanned_files']} MCP server source files. Critical findings: [bold red]{res['critical_count']}[/bold red][/cyan]")
        for f in res.get("findings", []):
            console.print(f"[{f['severity']}] {f['title']} in {f['file']}:{f['line']}\n  Snippet: {f['snippet']}")
        if args.exit_code and res["critical_count"] > 0:
            sys.exit(1)
    elif mcp_action in ("registry", "reg", "r"):
        table = Table(title="[bold blue]Known Model Context Protocol (MCP) Server Registry & Risk Posture[/bold blue]", header_style="bold blue")
        table.add_column("MCP Name", style="cyan", width=22)
        table.add_column("Risk Level", style="bold", width=12)
        table.add_column("Scope", style="yellow", width=22)
        table.add_column("Description", style="dim", width=45)
        for name, info in mcp_audit.MCP_REGISTRY.items():
            r_color = "red" if info["risk"] == "CRITICAL" else ("orange3" if info["risk"] == "HIGH" else "green")
            table.add_row(name, f"[{r_color}]{info['risk']}[/]", info["scope"], info["desc"])
        console.print(table)
    elif mcp_action in ("explain", "e"):
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

    fmt = args.format.lower()
    if fmt in ("json", "j"):
        out = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            console.print(f"[green]✔ DAST JSON report saved -> {args.output}[/green]")
        else:
            print(out)
    elif fmt in ("sarif", "s"):
        from report_generator import generate_sarif_report
        sarif = generate_sarif_report(results, args.target)
        out_path = args.output or "scan-results.sarif"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        console.print(f"[green]✔ SARIF 2.1.0 report saved -> {out_path}[/green]")
    else:
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


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mazapi",
        description="MazAPI Enterprise API & AI Surface Security Platform",
        add_help=True
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. app-surface (aliases: a, app)
    p_app = subparsers.add_parser("app-surface", aliases=["a", "app"], help="Static code API & route discovery at PR time")
    p_app.add_argument("action", choices=["scan"], default="scan", nargs="?")
    p_app.add_argument("path", default=".", nargs="?")
    p_app.add_argument("--format", "-f", choices=["table", "t", "json", "j", "openapi", "o", "openapi-yaml", "openapi-json", "asyncapi", "a", "sarif", "s"], default="table")
    p_app.add_argument("--output", "-o", help="Output file destination")
    p_app.add_argument("--baseline", "-b", help="Compare against baseline JSON file")
    p_app.add_argument("--update-baseline", "-u", help="Save current endpoints as new baseline JSON")
    p_app.add_argument("--fail-on", help="Exit with non-zero on high or critical findings")

    # 2. agent-audit (aliases: g, agent)
    p_agent = subparsers.add_parser("agent-audit", aliases=["g", "agent"], help="Audit AI agents for authorization & tool call gaps")
    p_agent.add_argument("action", choices=["scan"], default="scan", nargs="?")
    p_agent.add_argument("path", default=".", nargs="?")
    p_agent.add_argument("--format", "-f", choices=["table", "t", "json", "j", "cyclonedx", "ai-bom", "a", "sarif", "s"], default="table")
    p_agent.add_argument("--output", "-o", help="Output file destination")
    p_agent.add_argument("--governance", "-g", action="store_true", help="Print EU AI Act, NIST AI RMF, and ISO 42001 clauses")
    p_agent.add_argument("--fail-on", help="Exit with non-zero on high or critical findings")

    # 3. mcp-audit (aliases: m, mcp)
    p_mcp = subparsers.add_parser("mcp-audit", aliases=["m", "mcp"], help="MCP server configuration and source-level security audit")
    p_mcp.add_argument("mcp_cmd", choices=["scan", "s", "source-scan", "src", "registry", "reg", "r", "explain", "e"], default="scan")
    p_mcp.add_argument("path", default=".", nargs="?")
    p_mcp.add_argument("--flag", default="shell-injection-in-source", help="Risk flag for explain command")
    p_mcp.add_argument("--exit-code", action="store_true", help="Exit with non-zero code on critical findings")

    # 4. iot-audit (aliases: i, iot)
    p_iot = subparsers.add_parser("iot-audit", aliases=["i", "iot"], help="Audit IoT endpoints, MQTT brokers, CoAP, and OTA update surfaces")
    p_iot.add_argument("--target", "-t", default="http://localhost:8000", help="Target IoT API URL")

    # 5. scan (alias: s)
    p_scan = subparsers.add_parser("scan", aliases=["s"], help="Run active OWASP API Top 10 dynamic DAST security scanner")
    p_scan.add_argument("--target", "-t", default="http://localhost:8000", help="Target API URL")
    p_scan.add_argument("--auth", "-a", help="Auth token or header value (e.g. 'Bearer <jwt>')")
    p_scan.add_argument("--format", "-f", choices=["table", "t", "json", "j", "sarif", "s"], default="table")
    p_scan.add_argument("--output", "-o", help="Output report file path")

    # 6. train-models (aliases: t, train)
    subparsers.add_parser("train-models", aliases=["t", "train"], help="Train 32-feature calibrated ML anomaly models")

    # 7. shell (aliases: sh, console)
    subparsers.add_parser("shell", aliases=["sh", "console"], help="Launch interactive Cyber REPL console shell")

    return parser


def execute_args(sys_args, parser, in_repl=False):
    # Filter out stray '?' argument if user passed it
    sys_args = [arg for arg in sys_args if arg != "?"]

    if not sys_args or sys_args[0] in ("-h", "--help"):
        print_welcome_banner()
        return

    try:
        args = parser.parse_args(sys_args)
    except SystemExit:
        return

    sub = args.subcommand
    if sub in ("app-surface", "a", "app"):
        cmd_app_surface(args)
    elif sub in ("agent-audit", "g", "agent"):
        cmd_agent_audit(args)
    elif sub in ("mcp-audit", "m", "mcp"):
        cmd_mcp_audit(args)
    elif sub in ("iot-audit", "i", "iot"):
        cmd_iot_audit(args)
    elif sub in ("scan", "s"):
        cmd_dast_scan(args)
    elif sub in ("train-models", "t", "train"):
        cmd_train_models(args)
    elif sub in ("shell", "sh", "console"):
        run_interactive_shell(parser)
    else:
        print_welcome_banner()


def main():
    parser = build_parser()
    sys_args = sys.argv[1:]

    # If user ran `mazapi` with no arguments, open the interactive Cyber REPL Shell!
    if not sys_args:
        run_interactive_shell(parser)
    else:
        execute_args(sys_args, parser, in_repl=False)


if __name__ == "__main__":
    main()
