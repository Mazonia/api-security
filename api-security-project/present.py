"""
MazAPI Live Presentation Script (v2.1 - Extensions & Spotlight HUD Edition)
===========================================================================
Drives a real visible Chromium browser through every feature scenario automatically,
with on-screen element highlighting, presenter narration banners, browser extension
live scanning, and visible CLI execution.

Run from the api-security-project folder:
    python present.py

Requires: pip install playwright && python -m playwright install chromium
"""

import os
import subprocess
import sys
import time
from playwright.sync_api import sync_playwright, Page


# ─── Presenter HUD & Element Highlighter ──────────────────────────────────────

HUD_INJECTION_JS = """
(() => {
    if (document.getElementById('mazapi-presenter-hud')) return;
    
    // Inject style
    const style = document.createElement('style');
    style.id = 'mazapi-hud-style';
    style.innerHTML = `
        #mazapi-presenter-hud {
            position: fixed;
            top: 18px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 999999;
            background: rgba(14, 20, 36, 0.94);
            border: 2px solid #6366f1;
            border-radius: 16px;
            padding: 14px 24px;
            color: #ffffff;
            font-family: 'Inter', system-ui, sans-serif;
            box-shadow: 0 12px 40px rgba(0,0,0,0.6), 0 0 25px rgba(99,102,241,0.4);
            backdrop-filter: blur(16px);
            max-width: 780px;
            width: 90%;
            pointer-events: none;
            transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            display: flex;
            align-items: center;
            gap: 16px;
        }
        #mazapi-presenter-hud .hud-icon {
            font-size: 1.8rem;
            flex-shrink: 0;
            animation: hudPulse 1.5s infinite;
        }
        #mazapi-presenter-hud .hud-badge {
            font-size: 0.72rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            background: rgba(99,102,241,0.25);
            color: #a5b4fc;
            padding: 3px 8px;
            border-radius: 6px;
            display: inline-block;
            margin-bottom: 4px;
            border: 1px solid rgba(99,102,241,0.4);
        }
        #mazapi-presenter-hud .hud-title {
            font-size: 0.95rem;
            font-weight: 800;
            color: #f3f4f6;
            letter-spacing: -0.01em;
        }
        #mazapi-presenter-hud .hud-desc {
            font-size: 0.85rem;
            color: #cbd5e1;
            margin-top: 2px;
            line-height: 1.4;
        }
        #mazapi-presenter-hud .hud-close {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: #ffffff;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.95rem;
            padding: 6px 12px;
            font-weight: 700;
            pointer-events: auto;
            transition: all 0.15s ease;
            margin-left: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        #mazapi-presenter-hud .hud-close:hover {
            background: #f43f5e;
            border-color: #f43f5e;
            box-shadow: 0 0 10px rgba(244, 63, 94, 0.5);
        }
        @keyframes hudPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.15); }
        }
        .mazapi-pulse-target {
            outline: 3px solid #f43f5e !important;
            box-shadow: 0 0 0 8px rgba(244, 63, 94, 0.35), 0 0 25px rgba(244, 63, 94, 0.6) !important;
            animation: targetBeacon 1s infinite alternate !important;
            transition: all 0.2s ease !important;
            position: relative;
        }
        @keyframes targetBeacon {
            from { box-shadow: 0 0 0 4px rgba(244, 63, 94, 0.3), 0 0 15px rgba(244, 63, 94, 0.4); }
            to { box-shadow: 0 0 0 10px rgba(244, 63, 94, 0.5), 0 0 35px rgba(244, 63, 94, 0.8); }
        }
    `;
    document.head.appendChild(style);

    // Create HUD element
    const hud = document.createElement('div');
    hud.id = 'mazapi-presenter-hud';
    hud.innerHTML = `
        <div class="hud-icon" id="mazapi-hud-icon">🎯</div>
        <div style="flex:1">
            <div class="hud-badge" id="mazapi-hud-badge">MAZAPI DEMO</div>
            <div class="hud-title" id="mazapi-hud-title">Demonstration Step</div>
            <div class="hud-desc" id="mazapi-hud-desc">Initializing scenario...</div>
        </div>
        <button class="hud-close" onclick="(() => {
            const h = document.getElementById('mazapi-presenter-hud');
            if (h) {
                h.style.opacity = '0';
                h.style.transform = 'translateX(-50%) translateY(-100px)';
            }
            document.querySelectorAll('.mazapi-pulse-target').forEach(el => el.classList.remove('mazapi-pulse-target'));
        })()">✕ Dismiss</button>
    `;
    document.body.appendChild(hud);
})();
"""


def explain_action(page: Page, title: str, description: str, selector: str = None, icon: str = "🎯", badge: str = "PRESENTATION", wait_sec: float = 7.0):
    """Shows an on-screen HUD banner and highlights the target element before clicking."""
    try:
        # Inject HUD
        page.evaluate(HUD_INJECTION_JS)

        # Update HUD content
        page.evaluate(f"""
        (() => {{
            const hud = document.getElementById('mazapi-presenter-hud');
            if (hud) {{
                document.getElementById('mazapi-hud-icon').innerText = {repr(icon)};
                document.getElementById('mazapi-hud-badge').innerText = {repr(badge)};
                document.getElementById('mazapi-hud-title').innerText = {repr(title)};
                document.getElementById('mazapi-hud-desc').innerText = {repr(description)};
                hud.style.opacity = '1';
                hud.style.transform = 'translateX(-50%) translateY(0)';
            }}
            // Remove previous highlights
            document.querySelectorAll('.mazapi-pulse-target').forEach(el => el.classList.remove('mazapi-pulse-target'));
        }})();
        """)

        # If selector provided, highlight element
        if selector:
            loc = page.locator(selector).first
            loc.scroll_into_view_if_needed()
            page.evaluate(f"""
            (() => {{
                const el = document.querySelector({repr(selector)});
                if (el) {{
                    el.classList.add('mazapi-pulse-target');
                    el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                }}
            }})();
            """)

        # Console log
        print(f"\n  👉  [{badge}] {title}")
        print(f"      {description}")

        # Enforce minimum presentation duration of 7 seconds
        time.sleep(max(wait_sec, 7.0))

    except Exception as e:
        print(f"  [HUD notice]: {e}")


def clear_highlight(page: Page):
    try:
        page.evaluate("""
        (() => {
            document.querySelectorAll('.mazapi-pulse-target').forEach(el => el.classList.remove('mazapi-pulse-target'));
        })();
        """)
    except Exception:
        pass


def heading(title: str):
    border = "═" * (len(title) + 4)
    print(f"\n╔{border}╗")
    print(f"║  {title}  ║")
    print(f"╚{border}╝")


# ─── Interactive Browser Scenarios ────────────────────────────────────────────

def login_as_alice(page: Page):
    heading("LOGIN  —  Signing in as Alice (Regular User)")
    page.goto("http://localhost:8000/ui", wait_until="networkidle")
    time.sleep(1)

    explain_action(
        page,
        title="Selecting Test Account: Alice (Regular User)",
        description="Choosing regular user 'alice' with standard account permissions to begin testing.",
        selector="button:has-text('Select') >> nth=0",
        icon="👤",
        badge="STEP 1: AUTHENTICATION",
        wait_sec=2.0
    )
    page.click("button:has-text('Select') >> nth=0")
    clear_highlight(page)

    explain_action(
        page,
        title="Submitting Login Request",
        description="Authenticating to obtain Alice's JSON Web Token (JWT) from the backend API.",
        selector="button:has-text('Sign In')",
        icon="🔑",
        badge="STEP 1: AUTHENTICATION",
        wait_sec=1.5
    )
    page.click("button:has-text('Sign In')")
    clear_highlight(page)
    time.sleep(2)
    print("  ✅  Logged in as Alice successfully.")


def scenario_admin_bfla(page: Page):
    heading("SCENARIO 1  —  Broken Function Level Authorization (API5 BFLA)")
    
    explain_action(
        page,
        title="Navigating to Admin Panel Tab",
        description="Alice is an unprivileged regular user. We are navigating to the restricted Admin Panel.",
        selector="text=Admin Panel",
        icon="🛡️",
        badge="API5: BFLA TEST",
        wait_sec=2.0
    )
    page.click("text=Admin Panel")
    clear_highlight(page)
    time.sleep(1)

    explain_action(
        page,
        title="Executing Unauthorized Request: GET /admin/users",
        description="Alice is calling the administrative endpoint to see if the server enforces role authorization.",
        selector="button:has-text('Request Admin Accounts')",
        icon="⚡",
        badge="API5: ATTACK TRIGGER",
        wait_sec=2.2
    )
    btn = page.locator("button:has-text('Request Admin Accounts')")
    btn.scroll_into_view_if_needed()
    btn.click()
    clear_highlight(page)
    time.sleep(2)

    result = page.inner_text("#admin-result")
    print(f"\n  🔴  VULNERABLE API RESPONSE:\n{result[:400]}...")
    
    explain_action(
        page,
        title="VULNERABILITY CONFIRMED: Admin Data Leaked!",
        description="The backend accepted Alice's request without verifying her admin role, returning password hashes for all users!",
        selector="#admin-result",
        icon="🚨",
        badge="API5: VULNERABLE",
        wait_sec=3.0
    )
    clear_highlight(page)


def scenario_debug_misconfiguration(page: Page):
    heading("SCENARIO 2  —  Security Misconfiguration (API8 Debug Exposure)")

    explain_action(
        page,
        title="Navigating to Server Configuration Tab",
        description="Probing unauthenticated maintenance and debug routes on the backend.",
        selector="text=Server Configuration",
        icon="⚙️",
        badge="API8: MISCONFIG TEST",
        wait_sec=2.0
    )
    page.click("text=Server Configuration")
    clear_highlight(page)
    time.sleep(1)

    explain_action(
        page,
        title="Requesting Debug Endpoint: GET /debug/config",
        description="Attempting to read internal environment settings without providing any credentials.",
        selector="button:has-text('Request Debug Configuration')",
        icon="🔓",
        badge="API8: ATTACK TRIGGER",
        wait_sec=2.2
    )
    btn = page.locator("button:has-text('Request Debug Configuration')")
    btn.scroll_into_view_if_needed()
    btn.click()
    clear_highlight(page)
    time.sleep(2)

    result = page.inner_text("#debug-result")
    print(f"\n  🔴  VULNERABLE API RESPONSE:\n{result[:400]}...")

    explain_action(
        page,
        title="CRITICAL LEAK: JWT Secret Key Exposed!",
        description="The debug endpoint revealed the signing key 'secret'. Attackers can now forge arbitrary admin tokens!",
        selector="#debug-result",
        icon="🚨",
        badge="API8: CRITICAL RISK",
        wait_sec=3.0
    )
    clear_highlight(page)


def scenario_bola_profile(page: Page):
    heading("SCENARIO 3  —  Broken Object Level Authorization (API1 BOLA Profile)")

    explain_action(
        page,
        title="Navigating to Profile BOLA Tab",
        description="Alice is User ID #1. We will test accessing Bob's private profile (ID #2) by tampering with the URL parameter.",
        selector="text=Profile BOLA",
        icon="🎯",
        badge="API1: BOLA TEST",
        wait_sec=2.0
    )
    page.click("text=Profile BOLA")
    clear_highlight(page)
    time.sleep(1)

    explain_action(
        page,
        title="Setting Target User ID to 2 (Bob's Account)",
        description="Changing the requested object ID in the API query to target another user's private data.",
        selector="#bola-id",
        icon="✏️",
        badge="API1: OBJECT ID TAMPERING",
        wait_sec=1.8
    )
    bola_input = page.locator("#bola-id")
    bola_input.scroll_into_view_if_needed()
    bola_input.fill("2")
    clear_highlight(page)

    explain_action(
        page,
        title="Sending Request: GET /users/2",
        description="Sending authenticated request as Alice to fetch Bob's confidential record.",
        selector="button:has-text('Fetch Profile')",
        icon="⚡",
        badge="API1: BOLA EXECUTION",
        wait_sec=2.0
    )
    fetch_btn = page.locator("button:has-text('Fetch Profile')")
    fetch_btn.click()
    clear_highlight(page)
    time.sleep(2)

    explain_action(
        page,
        title="BOLA CONFIRMED: Bob's Private Profile Leaked!",
        description="The API returned Bob's balance and email because it failed to verify object ownership.",
        selector="#bola-result",
        icon="🚨",
        badge="API1: VULNERABILITY FOUND",
        wait_sec=3.0
    )
    clear_highlight(page)


def scenario_bola_orders(page: Page):
    heading("SCENARIO 4  —  Broken Object Level Authorization (API1 BOLA Orders)")

    explain_action(
        page,
        title="Navigating to Order BOLA Tab",
        description="Alice only owns Order Receipt #1. We will attempt to retrieve Bob's Order Receipt #2.",
        selector="text=Order BOLA",
        icon="📦",
        badge="API1: ORDER BOLA",
        wait_sec=2.0
    )
    page.click("text=Order BOLA")
    clear_highlight(page)
    time.sleep(1)

    explain_action(
        page,
        title="Setting Target Order ID to 2 (Bob's Order)",
        description="Specifying Order ID #2 without owning the corresponding transaction record.",
        selector="#order-id",
        icon="✏️",
        badge="API1: PARAMETER TAMPERING",
        wait_sec=1.8
    )
    order_input = page.locator("#order-id")
    order_input.scroll_into_view_if_needed()
    order_input.fill("2")
    clear_highlight(page)

    explain_action(
        page,
        title="Sending Request: GET /orders/2",
        description="Attempting unauthorized cross-account receipt inspection.",
        selector="button:has-text('Fetch Order Detail')",
        icon="⚡",
        badge="API1: ATTACK TRIGGER",
        wait_sec=2.0
    )
    order_btn = page.locator("button:has-text('Fetch Order Detail')")
    order_btn.click()
    clear_highlight(page)
    time.sleep(2)

    explain_action(
        page,
        title="BOLA CONFIRMED: Cross-Account Order Data Leaked!",
        description="The server revealed Bob's item purchases and shipping details with zero access control.",
        selector="#order-result",
        icon="🚨",
        badge="API1: DATA EXPOSURE",
        wait_sec=3.0
    )
    clear_highlight(page)


def scenario_mass_assignment(page: Page):
    heading("SCENARIO 5  —  Mass Assignment Privilege Escalation (API3)")

    explain_action(
        page,
        title="Navigating to Update Settings Tab",
        description="Alice is attempting to update her user profile with hidden administrative parameters.",
        selector="text=Update Settings",
        icon="📝",
        badge="API3: MASS ASSIGNMENT",
        wait_sec=2.0
    )
    page.click("text=Update Settings")
    clear_highlight(page)
    time.sleep(1)

    explain_action(
        page,
        title="Injecting Privileged Role: 'admin'",
        description="Selecting the forbidden 'admin' role in the profile update payload.",
        selector="#u-role",
        icon="👑",
        badge="API3: PRIVILEGE ESCALATION",
        wait_sec=1.8
    )
    role_sel = page.locator("#u-role")
    role_sel.scroll_into_view_if_needed()
    role_sel.select_option(value="admin")
    clear_highlight(page)

    explain_action(
        page,
        title="Injecting Arbitrary Balance: 99999",
        description="Overwriting the account balance field directly through client input.",
        selector="#u-balance",
        icon="💰",
        badge="API3: STATE TAMPERING",
        wait_sec=1.8
    )
    bal_input = page.locator("#u-balance")
    bal_input.scroll_into_view_if_needed()
    bal_input.fill("99999")
    clear_highlight(page)

    explain_action(
        page,
        title="Submitting Payload: PUT /users/1",
        description="Sending the modified JSON object to test if the API binds sensitive properties automatically.",
        selector="button:has-text('Save Changes')",
        icon="⚡",
        badge="API3: PAYLOAD DISPATCH",
        wait_sec=2.0
    )
    save_btn = page.locator("button:has-text('Save Changes')")
    save_btn.click()
    clear_highlight(page)
    time.sleep(2.5)

    explain_action(
        page,
        title="PRIVILEGE ESCALATION SUCCESSFUL!",
        description="Alice's account has been promoted to Admin and balance set to $99,999! The server accepted unvalidated fields.",
        selector="#u-msg",
        icon="🚨",
        badge="API3: PRIVILEGE ESCALATED",
        wait_sec=3.2
    )
    clear_highlight(page)


def show_hardened_mode(page: Page):
    heading("COMPARISON  —  Switching to Hardened API to Verify Remediation")

    explain_action(
        page,
        title="Switching Active Routing to Hardened API",
        description="Toggling the gateway to route traffic to the secured, remediated API service on Port 8001.",
        selector="#mode-hard-btn",
        icon="🛡️",
        badge="DEFENSIVE REMEDIATION",
        wait_sec=2.2
    )
    hard_btn = page.locator("#mode-hard-btn")
    hard_btn.click()
    clear_highlight(page)
    time.sleep(1.5)

    explain_action(
        page,
        title="Re-Testing BFLA Attack on Hardened API",
        description="Alice attempts to request administrative accounts again on the secured endpoint.",
        selector="button:has-text('Request Admin Accounts')",
        icon="🔒",
        badge="RE-TESTING SECURITY",
        wait_sec=2.0
    )
    page.click("text=Admin Panel")
    admin_btn = page.locator("button:has-text('Request Admin Accounts')")
    admin_btn.scroll_into_view_if_needed()
    admin_btn.click()
    clear_highlight(page)
    time.sleep(2)

    explain_action(
        page,
        title="ATTACK BLOCKED: HTTP 403 Forbidden!",
        description="The Hardened API enforces strict role verification and rejected Alice's unauthorized request.",
        selector="#admin-result",
        icon="✅",
        badge="SECURE DEFENSE VERIFIED",
        wait_sec=3.2
    )
    clear_highlight(page)

    page.locator("#mode-vuln-btn").click()
    time.sleep(1)


def show_monitoring_dashboard(context):
    heading("MONITORING DASHBOARD  —  Real-Time Anomaly & ML Detection")
    dash_page = context.new_page()
    dash_page.goto("http://localhost:9000/dashboard", wait_until="networkidle")
    time.sleep(2)
    explain_action(
        dash_page,
        title="Live Monitoring & Anomaly Detection Dashboard",
        description="All API requests and attacks performed during the demo are intercepted and analyzed in real-time by the ML proxy.",
        icon="📊",
        badge="TELEMETRY & ML",
        wait_sec=3.0
    )
    return dash_page


def show_scanner_ui(context):
    heading("SCANNER UI  —  Web-Based Automated Security Testing Engine")
    scan_page = context.new_page()
    scan_page.goto("http://localhost:9000/scan-ui", wait_until="networkidle")
    time.sleep(2)
    explain_action(
        scan_page,
        title="Interactive Security Scanner Workbench",
        description="Web-based interface for configuring targets, selecting test suites, and triggering comprehensive security scans.",
        icon="🔍",
        badge="SCANNER WORKBENCH",
        wait_sec=3.0
    )
    return scan_page


def show_swagger_docs(context):
    heading("SWAGGER API DOCS  —  OpenAPI Endpoint Reference")
    docs_page = context.new_page()
    docs_page.goto("http://localhost:8000/docs", wait_until="networkidle")
    time.sleep(2)
    explain_action(
        docs_page,
        title="Interactive Swagger / OpenAPI Documentation",
        description="Complete specification of REST endpoints, data models, and authentication schemas.",
        icon="📖",
        badge="API SPECIFICATION",
        wait_sec=2.5
    )
    return docs_page


def show_browser_extension_scan(context, extension_id: str):
    heading("BROWSER EXTENSION  —  Unpacked Extension In-Browser Security Scan")
    if not extension_id:
        print("  ⚠️  Skipping Browser Extension Scan: Extension ID not found.")
        return

    ext_page = context.new_page()
    ext_url = f"chrome-extension://{extension_id}/popup.html"
    print(f"  🔌  Opening MazAPI Extension Panel: {ext_url}")
    ext_page.goto(ext_url, wait_until="networkidle")
    time.sleep(2)

    # 1. Settings tab to enable streaming link
    explain_action(
        ext_page,
        title="Configuring Browser Extension Links",
        description="Linking the browser extension to our centralized monitoring dashboard on Port 9000.",
        selector="button[data-tab='settings']",
        icon="⚙️",
        badge="EXTENSION SETTINGS",
        wait_sec=2.0
    )
    ext_page.click("button[data-tab='settings']")
    time.sleep(1)

    # Ensure link dashboard is checked
    checkbox = ext_page.locator("#set-link-dashboard")
    if not checkbox.is_checked():
        explain_action(
            ext_page,
            title="Enabling Real-time Dashboard Sync",
            description="Checking the sync options to automatically stream completed scans to the monitoring service.",
            selector="#set-link-dashboard",
            icon="🔄",
            badge="EXTENSION CONFIG",
            wait_sec=1.5
        )
        ext_page.check("#set-link-dashboard")
    
    # Save Settings
    ext_page.click("#btn-save-settings")
    time.sleep(1)

    # 2. Go to Scan tab
    explain_action(
        ext_page,
        title="Navigating to Scan Config",
        description="Setting target URL inside the extension to scan the vulnerable API sandbox.",
        selector="button[data-tab='scan']",
        icon="⚡",
        badge="EXTENSION SCANNER",
        wait_sec=2.0
    )
    ext_page.click("button[data-tab='scan']")
    time.sleep(1)

    # Enter target
    target_input = ext_page.locator("#scan-target")
    target_input.fill("http://localhost:8000")
    time.sleep(1)

    # Run Scan
    explain_action(
        ext_page,
        title="Running Scan via Web Extension",
        description="Running the active DAST vulnerability scanner directly from the Chrome unpacked extension.",
        selector="#btn-scan",
        icon="🚀",
        badge="RUNNING EXTENSION SCAN",
        wait_sec=2.5
    )
    ext_page.click("#btn-scan")
    
    # Wait for completion (typically takes 10-15 seconds)
    print("  ⏳  Waiting for extension scan to complete in background...")
    time.sleep(12)

    # Go to results tab if not auto switched
    ext_page.click("button[data-tab='results']")
    time.sleep(2)

    explain_action(
        ext_page,
        title="Scan Finished: Viewing Extension Findings",
        description="The extension successfully discovered the OWASP API Top 10 vulnerabilities directly from the page side panel!",
        icon="📋",
        badge="EXTENSION SCAN RESULTS",
        wait_sec=3.0
    )

    # 3. View live extension page on port 9000
    live_page = context.new_page()
    live_page.goto("http://localhost:9000/extension/live", wait_until="networkidle")
    time.sleep(2)

    explain_action(
        live_page,
        title="Streamed Reports on Central Dashboard",
        description="The extension securely streamed the results live to the centralized /extension/live dashboard on Port 9000!",
        icon="🌐",
        badge="CENTRAL STREAMING",
        wait_sec=4.0
    )


def run_visible_cli_demos():
    heading("MazAPI CLI  —  Live Terminal Demonstration")
    print("  🖥  Launching external visible terminal window running MazAPI commands...")
    
    try:
        # Launch visible external terminal executing the pre-built CLI demonstration batch file
        subprocess.Popen(
            ["cmd.exe", "/c", "start", "MazAPI Live CLI Scan", "run_cli_presentation.bat"],
            shell=True
        )
        print("  ✅  External live CLI terminal window launched successfully.")
    except Exception as e:
        print(f"  ⚠️  Could not launch external terminal: {e}")
    time.sleep(3)


def show_upgraded_report(context):
    heading("GENERATED REPORT  —  New Interactive Report with Charts & Bookmarks")
    import glob
    reports = glob.glob("reports/report_vulnerable*.html") or glob.glob("reports/*.html")
    if reports:
        latest = max(reports, key=os.path.getmtime)
        report_url = "file:///" + os.path.abspath(latest).replace("\\", "/")
        print(f"  📄  Opening latest upgraded report: {os.path.basename(latest)}")
        rep_page = context.new_page()
        rep_page.goto(report_url, wait_until="networkidle")
        time.sleep(2)
        explain_action(
            rep_page,
            title="Upgraded Security Report with Bookmarks & Charts",
            description="Notice the new floating bookmarks sidebar, gradient analytics charts, and the top-right Light/Dark theme toggle!",
            icon="📑",
            badge="EXECUTIVE REPORT",
            wait_sec=4.0
        )
        return rep_page


# ─── Main Execution ───────────────────────────────────────────────────────────

def main():
    print("\n" + "═"*65)
    print("  MazAPI Security Suite — LIVE PRESENTATION (v2.1)")
    print("  Interactive Browser Demo with Element Highlighting & Live HUD")
    print("═"*65)
    print("\n  Starting in 3 seconds...")
    time.sleep(3)

    # Path to unpacked extension
    extension_path = os.path.abspath("../mazapi-extension")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            slow_mo=500,
            args=[
                "--start-maximized",
                f"--disable-extensions-except={extension_path}",
                f"--load-extension={extension_path}"
            ]
        )
        context = browser.new_context(
            viewport=None,
            no_viewport=True
        )
        page = context.new_page()

        # Find extension ID from background service worker
        time.sleep(2)
        extension_id = None
        for worker in context.service_workers:
            if "background.js" in worker.url:
                extension_id = worker.url.split("/")[2]
                break

        if extension_id:
            print(f"  🔌  Detected Loaded Browser Extension ID: {extension_id}")
        else:
            print("  ⚠️  Browser Extension was not detected by Playwright service worker query.")

        try:
            # ── Phase 1: Authentication ──────────────────────────────────────
            login_as_alice(page)

            # ── Phase 2: Web App Attack Scenarios (with Highlights) ──────────
            scenario_admin_bfla(page)
            scenario_debug_misconfiguration(page)
            scenario_bola_profile(page)
            scenario_bola_orders(page)
            scenario_mass_assignment(page)

            # ── Phase 3: Hardened Remediation Verification ───────────────────
            show_hardened_mode(page)

            # ── Phase 4: Supporting Views ────────────────────────────────────
            show_monitoring_dashboard(context)
            show_scanner_ui(context)
            show_swagger_docs(context)

            # ── Phase 5: Live Browser Extension Demonstration ────────────────
            if extension_id:
                show_browser_extension_scan(context, extension_id)

            # ── Phase 6: Live Visible Terminal Execution ─────────────────────
            run_visible_cli_demos()

            # ── Phase 7: Upgraded HTML Report with Bookmarks & Theme ─────────
            show_upgraded_report(context)

            # ── Completed ────────────────────────────────────────────────────
            heading("PRESENTATION COMPLETE")
            print("  🎉 All scenarios, highlights, extensions, and scans completed successfully!")
            print("  The browser window remains open for audience discussion & Q&A.")
            print("  Press Ctrl+C in this terminal when you are ready to exit.\n")

            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n  Presentation ended. Closing browser...")
            browser.close()
        except Exception as e:
            print(f"\n  ❌ Presentation error: {e}")
            import traceback
            traceback.print_exc()
            while True:
                time.sleep(1)


if __name__ == "__main__":
    main()
