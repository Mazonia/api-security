#!/usr/bin/env python3
"""Generates CY384_Presenter_Guide.html and converts to PDF via Edge/Chrome headless."""
import os, subprocess, sys

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CY384 API Security Framework — Presenter Guide</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;font-size:10.5pt;color:#1a1a2e;line-height:1.65;background:#fff}
/* ── layout ── */
.cover{page-break-after:always;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);color:#fff;text-align:center;padding:60px 40px}
.cover h1{font-size:26pt;font-weight:800;color:#58a6ff;margin-bottom:10px;letter-spacing:-.5px}
.cover h2{font-size:14pt;font-weight:400;color:#8b949e;margin-bottom:40px}
.cover .meta{font-size:10pt;color:#8b949e;line-height:2}
.cover .meta strong{color:#c9d1d9}
.cover .border-line{width:80px;height:3px;background:linear-gradient(90deg,#58a6ff,#3fb950);border-radius:2px;margin:30px auto}
/* ── toc ── */
.toc-page{page-break-after:always;padding:50px 60px}
.toc-page h2{font-size:16pt;color:#0d1117;margin-bottom:24px;padding-bottom:10px;border-bottom:2px solid #0d1117}
.toc a{display:flex;justify-content:space-between;padding:5px 0;color:#1a1a2e;text-decoration:none;border-bottom:1px dotted #ccc;font-size:10pt}
.toc a:hover{color:#0366d6}
.toc .toc-l2{padding-left:20px;font-size:9.5pt;color:#444}
.toc .toc-l3{padding-left:40px;font-size:9pt;color:#666}
/* ── content ── */
.content{padding:40px 60px}
h1.section{font-size:18pt;color:#0d1117;margin:0 0 16px;padding-bottom:8px;border-bottom:3px solid #0366d6;page-break-before:always}
h1.section:first-child{page-break-before:avoid}
h2.sub{font-size:13pt;color:#0d1117;margin:24px 0 10px;padding-left:10px;border-left:4px solid #0366d6}
h3.sub2{font-size:11pt;color:#333;margin:18px 0 8px}
h4.sub3{font-size:10pt;color:#555;margin:12px 0 6px;text-transform:uppercase;letter-spacing:.04em}
p{margin-bottom:10px}
ul,ol{margin:8px 0 12px 24px}
li{margin-bottom:4px}
/* ── code ── */
pre{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:14px 16px;font-family:'Consolas','Courier New',monospace;font-size:8.5pt;overflow-x:auto;margin:12px 0;line-height:1.55;white-space:pre-wrap;word-break:break-word}
code{font-family:'Consolas','Courier New',monospace;font-size:8.5pt;background:#f6f8fa;border:1px solid #e1e4e8;border-radius:3px;padding:1px 5px}
.vuln-code{background:#fff5f5;border-color:#f1a7a7}
.hard-code{background:#f0fff4;border-color:#a3d9a5}
/* ── compare ── */
.compare{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0 20px}
.compare-hdr{font-size:8pt;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:4px 10px;border-radius:4px 4px 0 0;margin-bottom:-1px}
.vuln-hdr{background:#ffeaea;color:#c0392b;border:1px solid #f1a7a7;border-bottom:none}
.hard-hdr{background:#e8f5e9;color:#1a7a3c;border:1px solid #a3d9a5;border-bottom:none}
.compare pre{margin:0;border-radius:0 6px 6px 6px}
/* ── table ── */
table{width:100%;border-collapse:collapse;margin:12px 0 20px;font-size:9.5pt}
th{background:#0d1117;color:#fff;padding:8px 12px;text-align:left;font-size:8.5pt;font-weight:600;letter-spacing:.03em}
td{padding:8px 12px;border-bottom:1px solid #e1e4e8;vertical-align:top}
tr:nth-child(even) td{background:#f6f8fa}
/* ── badges ── */
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:8pt;font-weight:700;margin-right:4px}
.badge-crit{background:#ffeaea;color:#c0392b;border:1px solid #f1a7a7}
.badge-high{background:#fff3e0;color:#e65100;border:1px solid #ffcc80}
.badge-med{background:#e3f2fd;color:#1565c0;border:1px solid #90caf9}
.badge-low{background:#e8f5e9;color:#1a7a3c;border:1px solid #a3d9a5}
.badge-info{background:#f3e5f5;color:#6a1b9a;border:1px solid #ce93d8}
.owasp{background:#fff3e0;color:#e65100;border:1px solid #ffcc80;font-size:7.5pt;font-weight:800;letter-spacing:.05em}
/* ── callout ── */
.callout{padding:12px 16px;border-radius:6px;margin:12px 0;font-size:9.5pt}
.callout-warn{background:#fff3e0;border-left:4px solid #f57c00}
.callout-info{background:#e3f2fd;border-left:4px solid #1976d2}
.callout-good{background:#e8f5e9;border-left:4px solid #388e3c}
.callout-danger{background:#ffeaea;border-left:4px solid #c62828}
/* ── qa ── */
.qa-item{margin-bottom:20px;padding:14px 16px;border:1px solid #e1e4e8;border-radius:8px;page-break-inside:avoid}
.qa-q{font-weight:700;color:#0d1117;margin-bottom:8px;font-size:10pt}
.qa-q::before{content:"Q: ";color:#0366d6}
.qa-a{color:#333;font-size:9.5pt}
.qa-a::before{content:"A: ";font-weight:600;color:#1a7a3c}
/* ── arch diagram ── */
.arch{background:#0d1117;color:#c9d1d9;padding:20px;border-radius:8px;font-family:'Consolas',monospace;font-size:8pt;line-height:1.8;margin:12px 0;white-space:pre}
/* ── print ── */
@media print{
  body{font-size:9.5pt}
  .cover{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  h1.section{page-break-before:always}
  h1.section:first-of-type{page-break-before:avoid}
  .qa-item,.compare{page-break-inside:avoid}
  pre{page-break-inside:avoid}
  .arch{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  th{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════
     COVER PAGE
═══════════════════════════════════════════ -->
<div class="cover">
  <h1>CY384 API Security Framework</h1>
  <h2>Presenter's Reference Guide</h2>
  <div class="border-line"></div>
  <div class="meta">
    <div><strong>Institution:</strong> University of Mines and Technology (UMaT), Ghana</div>
    <div><strong>Course:</strong> CY384 — Network and Application Security</div>
    <div><strong>Team:</strong> Team One &nbsp;|&nbsp; Topic #27</div>
    <div><strong>Topic:</strong> OWASP API Security Top 10:2023 — Live Demonstration Framework</div>
    <div style="margin-top:20px"><strong>Date:</strong> May 2026</div>
  </div>
  <div style="margin-top:50px;font-size:8.5pt;color:#555">
    This document is a personal practice reference for live demonstrations.<br>
    It is not for academic submission.
  </div>
</div>

<!-- ═══════════════════════════════════════════
     TABLE OF CONTENTS
═══════════════════════════════════════════ -->
<div class="toc-page">
  <h2>Table of Contents</h2>
  <div class="toc">
    <a href="#s1"><span>1. Project Overview</span><span>3</span></a>
    <a href="#s2"><span>2. System Architecture</span><span>3</span></a>
    <a href="#s3" class="toc-l2"><span>2.1 Network &amp; Container Layout</span><span>3</span></a>
    <a href="#s4" class="toc-l2"><span>2.2 Request Flow Through the System</span><span>4</span></a>
    <a href="#s5"><span>3. Docker Infrastructure</span><span>4</span></a>
    <a href="#s6" class="toc-l2"><span>3.1 docker-compose.yml Explained</span><span>4</span></a>
    <a href="#s7" class="toc-l2"><span>3.2 What Makes Each Container Unique</span><span>5</span></a>
    <a href="#s8"><span>4. Component Deep Dive</span><span>6</span></a>
    <a href="#s8a" class="toc-l2"><span>4.1 Vulnerable API (port 8000)</span><span>6</span></a>
    <a href="#s8b" class="toc-l2"><span>4.2 Hardened API (port 8001)</span><span>7</span></a>
    <a href="#s8c" class="toc-l2"><span>4.3 Monitoring Service (port 9000)</span><span>8</span></a>
    <a href="#s8d" class="toc-l2"><span>4.4 Testing Engine</span><span>9</span></a>
    <a href="#s8e" class="toc-l2"><span>4.5 Shop App UI</span><span>10</span></a>
    <a href="#s9"><span>5. OWASP Vulnerabilities — Code-Level Detail</span><span>10</span></a>
    <a href="#api1" class="toc-l2"><span>API1:2023 — BOLA</span><span>11</span></a>
    <a href="#api2" class="toc-l2"><span>API2:2023 — Broken Authentication</span><span>12</span></a>
    <a href="#api3" class="toc-l2"><span>API3:2023 — Mass Assignment</span><span>13</span></a>
    <a href="#api4" class="toc-l2"><span>API4:2023 — Rate Limiting</span><span>14</span></a>
    <a href="#api5" class="toc-l2"><span>API5:2023 — Function Level Auth</span><span>14</span></a>
    <a href="#api8" class="toc-l2"><span>API8:2023 — Security Misconfiguration</span><span>15</span></a>
    <a href="#s10"><span>6. ML Anomaly Detection</span><span>16</span></a>
    <a href="#s11"><span>7. Quick Reference</span><span>17</span></a>
    <a href="#s12"><span>8. How to Start and Stop</span><span>17</span></a>
    <a href="#s13"><span>9. Demonstration Workflows</span><span>18</span></a>
    <a href="#s14"><span>10. Likely Lecturer Questions &amp; Answers</span><span>19</span></a>
  </div>
</div>

<!-- ═══════════════════════════════════════════
     SECTION 1 — PROJECT OVERVIEW
═══════════════════════════════════════════ -->
<div class="content">
<h1 class="section" id="s1">1. Project Overview</h1>
<p>This project is a <strong>live, interactive API security demonstration framework</strong> built for CY384. It simulates a realistic e-commerce API in two states — deliberately broken and properly secured — and runs an intelligent monitoring layer that captures every request, flags attacks using machine learning and rule-based logic, and presents everything on a live dashboard. All components run in Docker containers on the local machine with no internet required during a demonstration.</p>

<p>The primary goal is to make abstract security vulnerabilities concrete and visible. Rather than describing what BOLA or mass assignment means in theory, a presenter can show an actual attack against a real API, watch the traffic appear on the dashboard, and then switch to the hardened version and watch the same attack get blocked — all within a single browser window.</p>

<h3 class="sub2">What was built</h3>
<ul>
  <li>A <strong>Vulnerable API</strong> with six intentional OWASP flaws across five categories</li>
  <li>A <strong>Hardened API</strong> that is the same API with every flaw corrected</li>
  <li>A <strong>Monitoring Service</strong> acting as a transparent proxy with real-time ML anomaly detection and a live dashboard</li>
  <li>An <strong>Automated Testing Engine</strong> that scans either API and generates scored security reports</li>
  <li>A <strong>Shop App UI</strong> that lets a user interact with both APIs through a realistic e-commerce interface</li>
  <li>A <strong>CLI demo script</strong> (<code>demo.py</code>) that walks through all six attack scenarios with press-Enter pacing</li>
  <li>A <strong>Rate Limit Demo script</strong> (<code>rate_limit_demo.py</code>) that interactively brute-forces login endpoints with selectable presets to show API4 in real time</li>
</ul>

<!-- ═══════════════════════════════════════════
     SECTION 2 — ARCHITECTURE
═══════════════════════════════════════════ -->
<h1 class="section" id="s2">2. System Architecture</h1>
<h2 class="sub" id="s3">2.1 Network &amp; Container Layout</h2>
<pre class="arch">  ┌─────────────────────────────────────────────────────────────────┐
  │                    Docker Bridge Network: api-net                │
  │                                                                 │
  │  ┌─────────────────┐      ┌─────────────────┐                  │
  │  │  vulnerable-api  │      │   hardened-api   │                  │
  │  │   :8000          │      │   :8001          │                  │
  │  │  (FastAPI)        │      │  (FastAPI)        │                  │
  │  └────────┬─────────┘      └────────┬─────────┘                  │
  │           │                         │                            │
  │  ┌────────▼─────────────────────────▼─────────┐                 │
  │  │              monitoring  :9000              │                 │
  │  │   Transparent Proxy + SQLite + ML + Dash    │                 │
  │  │   /data/traffic.db   /data/model.joblib     │                 │
  │  └─────────────────────────────────────────────┘                 │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
         ▲                     ▲                    ▲
    localhost:8000        localhost:8001        localhost:9000
   (vulnerable api        (hardened api        (monitoring dash
    + shop app UI)         direct access)       + proxy for shop)</pre>

<h2 class="sub" id="s4">2.2 Request Flow Through the System</h2>
<p>The Shop App always points to <code>http://localhost:9000</code> as its API base. Every request therefore passes through the monitoring proxy first. The proxy inspects the <code>X-Target</code> header: if it reads <code>hardened</code>, the request is forwarded to <code>http://hardened-api:8001</code>; otherwise it goes to <code>http://vulnerable-api:8000</code>. The routing header is stripped before forwarding so the upstream API never sees it. Every request is then logged to SQLite and scored by the anomaly detector before the response is returned to the browser.</p>

<ol>
  <li>Browser sends request to <code>localhost:9000/auth/login</code></li>
  <li>Monitoring proxy receives it, checks <code>X-Target</code> header</li>
  <li>Forwards to the appropriate upstream API</li>
  <li>Receives response, measures elapsed time</li>
  <li>Decodes JWT if present, computes <code>bola_suspected</code></li>
  <li>Passes record to anomaly detector (rule-based then ML)</li>
  <li>Saves record to SQLite with anomaly result</li>
  <li>Returns response to browser</li>
  <li>Dashboard polls every 10 seconds and shows the new record</li>
</ol>

<!-- ═══════════════════════════════════════════
     SECTION 3 — DOCKER INFRASTRUCTURE
═══════════════════════════════════════════ -->
<h1 class="section" id="s5">3. Docker Infrastructure</h1>
<h2 class="sub" id="s6">3.1 docker-compose.yml Explained</h2>
<p>The <code>docker-compose.yml</code> file at the project root defines all four services and the shared network. It is the single command centre — one command starts or stops the entire system.</p>

<pre>networks:
  api-net:
    driver: bridge          # Private internal network — containers talk by name

services:
  vulnerable-api:
    build: ./vulnerable-api # Dockerfile is in this subfolder
    container_name: vulnerable-api
    ports:
      - "8000:8000"         # Host port 8000 maps to container port 8000
    networks:
      - api-net
    environment:
      - ENV=vulnerable       # Used inside the app to identify its mode
    volumes:
      - ./reports:/reports   # Shares report output with the host

  hardened-api:
    build: ./hardened-api
    container_name: hardened-api
    ports:
      - "8001:8001"
    networks:
      - api-net
    env_file:
      - .env                 # Loads JWT_SECRET and ALLOWED_ORIGINS from .env file
    environment:
      - ENV=hardened

  monitoring:
    build: ./monitoring
    container_name: monitoring
    ports:
      - "9000:9000"
    networks:
      - api-net
    volumes:
      - ./data:/data         # Persists traffic.db and model.joblib between restarts
      - ./reports:/reports
    depends_on:
      - vulnerable-api       # Waits for vulnerable-api to start first

  testing-engine:
    build: ./testing-engine
    container_name: testing-engine
    networks:
      - api-net
    volumes:
      - ./reports:/reports
    depends_on:
      - vulnerable-api
    profiles:
      - tools                # ONLY runs when --profile tools is specified
    environment:
      - TARGET=http://vulnerable-api:8000
      - REPORT_DIR=/reports
      - REPORT_DETAIL=brief</pre>

<h2 class="sub" id="s7">3.2 What Makes Each Container Unique</h2>
<table>
  <tr><th>Container</th><th>Base Image</th><th>Port</th><th>Key Dependency</th><th>Persistent Volume</th><th>What differentiates it</th></tr>
  <tr><td><strong>vulnerable-api</strong></td><td>python:3.11-slim</td><td>8000</td><td>fastapi, uvicorn, python-jose, passlib, bcrypt</td><td>./reports</td><td>Intentional flaws, no slowapi (no rate limiting), hardcoded JWT secret, wildcard CORS, docs exposed, debug endpoint active</td></tr>
  <tr><td><strong>hardened-api</strong></td><td>python:3.11-slim</td><td>8001</td><td>+ slowapi, limits</td><td>none</td><td>Reads JWT_SECRET from .env, 30-min token expiry, ownership checks on every route, slowapi rate limiting, docs disabled, no debug endpoint, strict CORS, generic error messages</td></tr>
  <tr><td><strong>monitoring</strong></td><td>python:3.11-slim</td><td>9000</td><td>httpx, scikit-learn, numpy, aiosqlite, jinja2, joblib</td><td>./data (DB + model), ./reports</td><td>The only container with ML libraries. Serves as transparent proxy and dashboard. Bundles Chart.js locally. Auto-trains IsolationForest if model is missing at startup.</td></tr>
  <tr><td><strong>testing-engine</strong></td><td>python:3.11-slim</td><td>none</td><td>httpx, rich, python-jose</td><td>./reports</td><td>Run-once scanner, not a persistent service. Launched with <code>docker compose run --rm --profile tools testing-engine</code>. Uses Python's <code>main.py</code> directly (not uvicorn).</td></tr>
</table>

<h3 class="sub2">How each Dockerfile is structured</h3>
<p>All four Dockerfiles follow the same four-step pattern — only the CMD differs:</p>
<pre>FROM python:3.11-slim          # Minimal Linux image with Python 3.11, no extras
WORKDIR /app                   # All files go here inside the container
COPY requirements.txt .        # Copy dependency list first (layer cache benefit)
RUN pip install --no-cache-dir -r requirements.txt  # Install dependencies
COPY . .                       # Copy all source files
CMD [...]                      # How to start the service</pre>

<p>The CMD for each service:</p>
<table>
  <tr><th>Service</th><th>CMD</th><th>Why</th></tr>
  <tr><td>vulnerable-api</td><td><code>uvicorn main:app --host 0.0.0.0 --port 8000</code></td><td>FastAPI ASGI server, port 8000</td></tr>
  <tr><td>hardened-api</td><td><code>uvicorn main:app --host 0.0.0.0 --port 8001</code></td><td>Same but port 8001</td></tr>
  <tr><td>monitoring</td><td><code>uvicorn main:app --host 0.0.0.0 --port 9000</code></td><td>Same but port 9000</td></tr>
  <tr><td>testing-engine</td><td><code>python main.py</code></td><td>Run-once script, not a web server</td></tr>
</table>

<p>The <code>--host 0.0.0.0</code> flag is critical — without it the server binds only to <code>127.0.0.1</code> inside the container and is unreachable from the host machine or other containers. Binding to <code>0.0.0.0</code> makes it listen on all network interfaces.</p>

<p>The <code>--no-cache-dir</code> pip flag keeps the image small by not storing the pip download cache. The two-stage copy (requirements first, then source) is a Docker layer-caching best practice: if only the Python source changes, Docker reuses the cached dependency layer and skips reinstalling packages.</p>

<!-- ═══════════════════════════════════════════
     SECTION 4 — COMPONENT DEEP DIVE
═══════════════════════════════════════════ -->
<h1 class="section" id="s8">4. Component Deep Dive</h1>

<h2 class="sub" id="s8a">4.1 Vulnerable API — port 8000</h2>
<p><strong>File:</strong> <code>vulnerable-api/main.py</code><br>
<strong>Framework:</strong> FastAPI 0.111 running under Uvicorn<br>
<strong>Purpose:</strong> An intentionally insecure e-commerce backend. Every vulnerability is a realistic mistake a developer might genuinely make. The code is heavily commented so the flaws are visible when shown during a demo.</p>

<h4 class="sub3">Endpoints</h4>
<table>
  <tr><th>Method</th><th>Path</th><th>Auth?</th><th>Flaw</th></tr>
  <tr><td>POST</td><td>/auth/login</td><td>No</td><td>Verbose errors reveal if username exists. No rate limit.</td></tr>
  <tr><td>GET</td><td>/users/{id}</td><td>Yes</td><td>API1 — no ownership check. Returns password hash too.</td></tr>
  <tr><td>PUT</td><td>/users/{id}</td><td>Yes</td><td>API1 + API3 — no ownership check, accepts role &amp; balance.</td></tr>
  <tr><td>GET</td><td>/orders/{id}</td><td>Yes</td><td>API1 — any user can read any order.</td></tr>
  <tr><td>GET</td><td>/users/{id}/orders</td><td>Yes</td><td>API1 — no ownership check.</td></tr>
  <tr><td>GET</td><td>/admin/users</td><td>Yes (any user)</td><td>API5 — no role check, returns all accounts.</td></tr>
  <tr><td>DELETE</td><td>/admin/users/{id}</td><td>Yes (any user)</td><td>API5 — any user can delete accounts.</td></tr>
  <tr><td>GET</td><td>/admin/orders</td><td>Yes (any user)</td><td>API5 — no role check.</td></tr>
  <tr><td>GET</td><td>/debug/config</td><td><strong>None</strong></td><td>API8 — exposes secret key, algorithm, debug state.</td></tr>
  <tr><td>GET</td><td>/health</td><td>No</td><td>Health check endpoint (needed for monitoring).</td></tr>
  <tr><td>GET</td><td>/ui</td><td>No</td><td>Serves the Shop App HTML page.</td></tr>
</table>

<h4 class="sub3">In-memory database</h4>
<p>There is no external database. User and order records live in Python dictionaries (<code>users_db</code>, <code>orders_db</code>) that are initialised when the container starts. This means any PUT/DELETE changes are lost on container restart — intentional, so the demo environment always returns to a clean state.</p>

<h2 class="sub" id="s8b">4.2 Hardened API — port 8001</h2>
<p><strong>File:</strong> <code>hardened-api/main.py</code><br>
<strong>Extra dependency:</strong> <code>slowapi==0.1.9</code> (rate limiting middleware)<br>
<strong>Purpose:</strong> The same API with every security flaw corrected. Used for side-by-side comparison.</p>

<h4 class="sub3">Key differences from the vulnerable API</h4>
<ul>
  <li><strong>JWT secret:</strong> Read from environment variable <code>JWT_SECRET</code> at startup. If the variable is missing, the server refuses to start with a <code>RuntimeError</code>.</li>
  <li><strong>Token expiry:</strong> Every token includes an <code>exp</code> claim set to 30 minutes from issue time. Expired tokens are rejected.</li>
  <li><strong>Ownership checks:</strong> Every user-data endpoint compares <code>current_user["id"]</code> with the requested resource ID. Admins bypass this check; regular users get 403.</li>
  <li><strong>Mass assignment blocked:</strong> The <code>UserUpdate</code> Pydantic model only declares <code>email</code> and <code>password</code>. <code>role</code> and <code>balance</code> are not present, so FastAPI silently ignores them even if sent.</li>
  <li><strong>Rate limiting:</strong> <code>@limiter.limit("5/minute")</code> on login, <code>60/minute</code> on read endpoints, <code>10/minute</code> on PUT. Exceeding these returns HTTP 429.</li>
  <li><strong>Function-level auth:</strong> A <code>require_admin</code> dependency is used on all <code>/admin/*</code> routes. It calls <code>get_current_user</code> first, then checks <code>role == "admin"</code>.</li>
  <li><strong>No debug endpoint:</strong> <code>/debug/config</code> does not exist. Returns 404.</li>
  <li><strong>Docs disabled:</strong> <code>docs_url=None, redoc_url=None</code> — Swagger UI is not accessible.</li>
  <li><strong>CORS:</strong> Only origins listed in <code>ALLOWED_ORIGINS</code> environment variable are permitted.</li>
  <li><strong>Generic errors:</strong> Login always returns <code>"Invalid credentials"</code> regardless of whether the username or password is wrong.</li>
  <li><strong>Password not returned:</strong> The hardened GET /users/{id} also excludes <code>balance</code> — a user cannot see another user's financial data even in the response fields that are returned.</li>
</ul>

<h2 class="sub" id="s8c">4.3 Monitoring Service — port 9000</h2>
<p><strong>File:</strong> <code>monitoring/main.py</code><br>
<strong>Framework:</strong> FastAPI + aiosqlite (async SQLite) + httpx (async HTTP client)<br>
<strong>Purpose:</strong> Three responsibilities in one service — transparent proxy, traffic logger, and live dashboard.</p>

<h4 class="sub3">Startup sequence</h4>
<ol>
  <li>Creates the SQLite <code>traffic</code> table if it does not exist (columns: id, timestamp, method, path, status_code, response_time_ms, has_auth, anomaly, anomaly_score, anomaly_reason)</li>
  <li>Checks if <code>/data/model.joblib</code> exists. If not, runs <code>python train_model.py</code> as a subprocess and reloads the detector</li>
  <li>Mounts <code>/static</code> directory (contains the bundled <code>chart.min.js</code>)</li>
  <li>Starts Uvicorn and begins accepting requests</li>
</ol>

<h4 class="sub3">Key API endpoints</h4>
<table>
  <tr><th>Method</th><th>Path</th><th>Purpose</th></tr>
  <tr><td>GET</td><td>/dashboard</td><td>Serves the live monitoring dashboard HTML</td></tr>
  <tr><td>GET</td><td>/monitor/stats</td><td>Returns aggregate stats (total, anomalies, error rate, avg ms)</td></tr>
  <tr><td>GET</td><td>/monitor/feed</td><td>Returns last N traffic records for the live feed table</td></tr>
  <tr><td>GET</td><td>/monitor/anomalies</td><td>Returns only records where anomaly=1</td></tr>
  <tr><td>GET</td><td>/monitor/timeline</td><td>Returns per-minute request and anomaly counts for the chart</td></tr>
  <tr><td>GET</td><td>/monitor/endpoints</td><td>Returns per-path aggregates (count, error rate, anomaly count)</td></tr>
  <tr><td>GET</td><td>/monitor/health</td><td>Pings vulnerable-api and hardened-api and reports their status</td></tr>
  <tr><td>POST</td><td>/monitor/reset-logs</td><td>Deletes all rows from the traffic table</td></tr>
  <tr><td>GET</td><td>/monitor/reports</td><td>Lists all report files with metadata (score, detail, timestamp)</td></tr>
  <tr><td>GET</td><td>/monitor/reports/{filename}</td><td>Serves a report HTML or JSON file</td></tr>
  <tr><td>DELETE</td><td>/monitor/reports/{filename}</td><td>Deletes report pair (.json + .html)</td></tr>
  <tr><td>POST</td><td>/monitor/run-comparison</td><td>Runs all 7 attack scenarios against both APIs, saves report</td></tr>
  <tr><td>*</td><td>/{path}</td><td>Catch-all transparent proxy (all other paths)</td></tr>
</table>

<h4 class="sub3">Dashboard features</h4>
<ul>
  <li><strong>Overview tab:</strong> Live stats cards, request-rate timeline chart (Chart.js), method breakdown chart, status code breakdown</li>
  <li><strong>Endpoints tab:</strong> Per-path table showing total requests, error rate, anomaly count, avg response time</li>
  <li><strong>Live Feed tab:</strong> Real-time request log with filters (method, status, anomaly-only, path), sortable columns</li>
  <li><strong>Anomalies tab:</strong> Only flagged requests, showing score and reason code</li>
  <li><strong>Reports tab:</strong> All generated reports with type badge (Scan/Comparison), detail badge (Brief/Detailed), scores, Open/JSON/Delete buttons, multi-select delete with checkbox selection toolbar</li>
  <li><strong>Reset Logs button:</strong> Clears the entire traffic database in one click</li>
</ul>

<h2 class="sub" id="s8d">4.4 Testing Engine</h2>
<p><strong>Files:</strong> <code>testing-engine/main.py</code>, <code>owasp_tests/*.py</code>, <code>report_generator.py</code><br>
<strong>Purpose:</strong> An automated black-box scanner. It is not a persistent web service — it runs, scans, saves a report, and exits.</p>

<h4 class="sub3">Test modules</h4>
<table>
  <tr><th>File</th><th>OWASP ID</th><th>What it tests</th></tr>
  <tr><td>test_api1_bola.py</td><td>API1:2023</td><td>Logs in as alice, requests /users/2 and /orders/2 (belong to bob)</td></tr>
  <tr><td>test_api2_auth.py</td><td>API2:2023</td><td>Forges a JWT using the known secret "secret", claims role=admin</td></tr>
  <tr><td>test_api3_mass_assign.py</td><td>API3:2023</td><td>PUT /users/1 with {"role":"admin","balance":999999}</td></tr>
  <tr><td>test_api4_rate_limit.py</td><td>API4:2023</td><td>Sends 15 rapid login attempts, checks for HTTP 429</td></tr>
  <tr><td>test_api5_func_auth.py</td><td>API5:2023</td><td>Calls /admin/users with a regular user (alice) token</td></tr>
  <tr><td>test_api8_misconfig.py</td><td>API8:2023</td><td>Hits /debug/config without credentials; checks CORS headers; checks /docs availability; checks login error verbosity</td></tr>
</table>

<h4 class="sub3">Report generation</h4>
<p>Reports are saved in both JSON and HTML format. The detail level is controlled by the <code>REPORT_DETAIL</code> environment variable:</p>
<ul>
  <li><strong>Brief:</strong> Test name, pass/fail verdict, overall security score percentage</li>
  <li><strong>Detailed:</strong> All of the above plus CVE identifier, proof-of-concept HTTP payload, step-by-step reproduction instructions, and recommended remediation code</li>
</ul>
<p>The security score is calculated as <code>(passed tests / total tests) × 100</code>. A test is passed if the API correctly blocked or did not expose the attack.</p>

<h2 class="sub" id="s8e">4.5 Shop App UI</h2>
<p><strong>Location:</strong> Embedded HTML inside <code>vulnerable-api/main.py</code>, served at <code>http://localhost:8000/ui</code><br>
<strong>Purpose:</strong> A realistic dark-themed e-commerce UI for interactive demonstration. All requests from the shop app go through the monitoring proxy so they appear on the dashboard.</p>

<h4 class="sub3">Features and what they demonstrate</h4>
<table>
  <tr><th>UI Element</th><th>What it calls</th><th>Vulnerability shown</th></tr>
  <tr><td>Sign In button</td><td>POST /auth/login</td><td>API8 — verbose error messages reveal whether username exists</td></tr>
  <tr><td>My Profile panel</td><td>GET /users/{own id}</td><td>Normal (legitimate) traffic</td></tr>
  <tr><td>BOLA panel — Fetch User button</td><td>GET /users/{any id}</td><td>API1 — change the ID field to 2 or 3 to access other users</td></tr>
  <tr><td>Mass Assignment panel — Save Changes</td><td>PUT /users/1 with role/balance</td><td>API3 — fill in role=admin and balance=999999</td></tr>
  <tr><td>Admin Endpoints — GET /admin/users</td><td>GET /admin/users</td><td>API5 — any logged-in user can call admin endpoint</td></tr>
  <tr><td>Debug Config — GET /debug/config</td><td>GET /debug/config</td><td>API8 — returns secret key and server internals (no auth needed)</td></tr>
  <tr><td>Order BOLA panel</td><td>GET /orders/{id}</td><td>API1 — access any order regardless of ownership</td></tr>
  <tr><td>Vulnerable / Hardened toggle</td><td>Adds X-Target: hardened header</td><td>Routes same request to hardened API via proxy</td></tr>
  <tr><td>Monitor link in nav</td><td>Opens localhost:9000/dashboard</td><td>Shows live traffic from shop actions</td></tr>
</table>

<div class="callout callout-info">
  <strong>Note on mode switching:</strong> When toggled to Hardened mode, the shop app does not connect directly to port 8001. All requests still go to <code>localhost:9000</code> (the monitoring proxy) but with the header <code>X-Target: hardened</code> added. The proxy reads this header and routes to <code>hardened-api:8001</code> internally, then strips the header before forwarding. This preserves monitoring visibility for both modes.
</div>

<!-- ═══════════════════════════════════════════
     SECTION 5 — OWASP VULNERABILITIES
═══════════════════════════════════════════ -->
<h1 class="section" id="s9">5. OWASP Vulnerabilities — Code-Level Detail</h1>

<p>Each subsection shows the exact code that is vulnerable, the exact fix applied, and how the monitoring service detects the attack.</p>

<!-- API1 -->
<h2 class="sub" id="api1">API1:2023 — Broken Object Level Authorization (BOLA)</h2>
<p><span class="badge badge-high">HIGH</span> <span class="badge owasp">API1:2023</span> CVE-2019-14234 (Django), CWE-639</p>
<p><strong>What it is:</strong> The server authenticates who you are but does not check whether you are allowed to access the specific object you requested. Any valid token can read or modify any user's data just by changing the numeric ID in the URL.</p>
<p><strong>Real-world impact:</strong> An attacker with one account can enumerate all user IDs and dump the entire user database, read other users' private orders, financial data, and personal information, or modify other users' accounts.</p>

<div class="compare">
  <div>
    <div class="compare-hdr vuln-hdr">Vulnerable — GET /users/{user_id}</div>
    <pre class="vuln-code">@app.get("/users/{user_id}")
def get_user(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    # No ownership check — only verifies
    # that the request carries a valid JWT
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(404, "Not found")
    # Also leaks password hash
    return {k: v for k, v in user.items()
            if k != "password"}</pre>
  </div>
  <div>
    <div class="compare-hdr hard-hdr">Hardened — GET /users/{user_id}</div>
    <pre class="hard-code">@app.get("/users/{user_id}")
def get_user(
    request: Request,
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    # Ownership enforced — must be yourself
    # or an admin
    if (current_user["id"] != user_id
            and current_user["role"] != "admin"):
        raise HTTPException(403, "Access denied")
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(404, "Not found")
    # Also excludes balance from response
    return {k: v for k, v in user.items()
            if k not in ("password", "balance")}</pre>
  </div>
</div>

<h4 class="sub3">How the monitoring service detects this</h4>
<p>The proxy decodes the JWT payload (base64 without signature verification — only the claims are needed) to extract the <code>sub</code> field, which is the authenticated user's ID. It then checks if a numeric user ID appears in the URL path pattern <code>/users/{id}</code>. If the two numbers differ, <code>bola_suspected</code> is set to <code>True</code>. The anomaly detector's rule layer immediately flags this before the ML model is consulted, with reason <code>bola_object_accessed</code> (score -0.8) if the response was HTTP 200, or <code>bola_attempt_detected</code> if it was blocked.</p>

<!-- API2 -->
<h2 class="sub" id="api2">API2:2023 — Broken Authentication (JWT Forgery)</h2>
<p><span class="badge badge-crit">CRITICAL</span> <span class="badge owasp">API2:2023</span> CVE-2015-9235 (JWT none alg), CWE-287</p>
<p><strong>What it is:</strong> The JWT signing secret is hardcoded in the source code as the string <code>"secret"</code>. Anyone who can read the source, find the secret through the <code>/debug/config</code> endpoint, or simply guess it can forge valid tokens with any claims they want, including <code>role: admin</code>.</p>

<div class="compare">
  <div>
    <div class="compare-hdr vuln-hdr">Vulnerable — Secret and token creation</div>
    <pre class="vuln-code">SECRET_KEY = "secret"   # hardcoded in source
ALGORITHM = "HS256"

def create_token(user_id, username, role):
    # No expiry claim — tokens never expire
    return jwt.encode(
        {
          "sub": str(user_id),
          "username": username,
          "role": role
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )</pre>
  </div>
  <div>
    <div class="compare-hdr hard-hdr">Hardened — Secret and token creation</div>
    <pre class="hard-code">SECRET_KEY = os.environ.get("JWT_SECRET", "")
if not SECRET_KEY:
    raise RuntimeError(
      "JWT_SECRET env var must be set"
    )
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

def create_token(user_id, username, role):
    expire = (datetime.utcnow()
              + timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    return jwt.encode(
        {
          "sub": str(user_id),
          "username": username,
          "role": role,
          "exp": expire   # enforced expiry
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )</pre>
  </div>
</div>

<h4 class="sub3">How to forge a token (the attack)</h4>
<p>Using the Python <code>python-jose</code> library:</p>
<pre>from jose import jwt
forged = jwt.encode(
    {"sub": "1", "username": "alice", "role": "admin"},
    "secret",      # the leaked key
    algorithm="HS256"
)
# Use forged as Bearer token — vulnerable API accepts it</pre>

<h4 class="sub3">How the monitoring detects this</h4>
<p>The monitoring proxy cannot distinguish a forged from a genuine token (that would require knowing the secret). Detection relies on the downstream API returning HTTP 401 (invalid signature) for the hardened API, which the anomaly detector picks up as an error. The comparison report explicitly tests this by forging a token with the known key.</p>

<!-- API3 -->
<h2 class="sub" id="api3">API3:2023 — Mass Assignment (Privilege Escalation)</h2>
<p><span class="badge badge-high">HIGH</span> <span class="badge owasp">API3:2023</span> CVE-2012-2054 (GitHub), CWE-915</p>
<p><strong>What it is:</strong> The API accepts more fields in a PUT request than it should. By including <code>role</code> and <code>balance</code> in the JSON body, a regular user can promote themselves to admin or change their account balance without any authorisation check on those fields.</p>

<div class="compare">
  <div>
    <div class="compare-hdr vuln-hdr">Vulnerable — UserUpdate model</div>
    <pre class="vuln-code">class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    # ^ should NEVER be user-settable
    balance: Optional[float] = None
    # ^ should NEVER be user-settable</pre>
  </div>
  <div>
    <div class="compare-hdr hard-hdr">Hardened — UserUpdate model</div>
    <pre class="hard-code">class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    # role and balance are simply absent.
    # FastAPI ignores them even if sent —
    # they never reach the handler.</pre>
  </div>
</div>

<h4 class="sub3">The attack payload</h4>
<pre>PUT /users/1
Content-Type: application/json
Authorization: Bearer {alice_token}

{"role": "admin", "balance": 999999}</pre>
<p>On the vulnerable API this returns HTTP 200 and alice is now an admin with 999999 in her balance. On the hardened API the fields are silently dropped and only whitelisted fields are processed.</p>

<!-- API4 -->
<h2 class="sub" id="api4">API4:2023 — Unrestricted Resource Consumption (Rate Limiting)</h2>
<p><span class="badge badge-med">MEDIUM</span> <span class="badge owasp">API4:2023</span> CWE-770</p>
<p><strong>What it is:</strong> The login endpoint has no rate limiting. An attacker can send thousands of login attempts per second without any throttling, making automated password brute-forcing trivial.</p>

<div class="compare">
  <div>
    <div class="compare-hdr vuln-hdr">Vulnerable — no rate limit</div>
    <pre class="vuln-code">@app.post("/auth/login")
def login(req: LoginRequest):
    # No rate limiting — unlimited attempts
    for user in users_db.values():
        if user["username"] == req.username:
            if pwd_context.verify(req.password,
                                  user["password"]):
                return {"access_token": ...}
            raise HTTPException(401, ...)</pre>
  </div>
  <div>
    <div class="compare-hdr hard-hdr">Hardened — slowapi rate limit</div>
    <pre class="hard-code">limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/auth/login")
@limiter.limit("5/minute")  # 5 per IP per minute
def login(request: Request, req: LoginRequest):
    # Exceeding 5 returns HTTP 429 automatically
    for user in users_db.values():
        if (user["username"] == req.username
            and pwd_context.verify(
                req.password, user["password"])):
            return {"access_token": ...}
    raise HTTPException(401, "Invalid credentials")</pre>
  </div>
</div>

<h4 class="sub3">How to demonstrate this (rate_limit_demo.py)</h4>
<p>A dedicated script is provided for this scenario because brute-forcing from a browser UI is slow and clunky. Run it from the project root:</p>
<pre>python rate_limit_demo.py</pre>
<p>It presents four presets and fires login attempts with wrong credentials at both APIs simultaneously:</p>
<table>
  <tr><th>Preset</th><th>Requests</th><th>Delay</th><th>Best for</th></tr>
  <tr><td>1 -- Light</td><td>6</td><td>0.3 s</td><td>Quick classroom demo (just enough to trip the 5/min limit)</td></tr>
  <tr><td>2 -- Medium</td><td>12</td><td>0.1 s</td><td>Password-spray simulation</td></tr>
  <tr><td>3 -- Heavy</td><td>20</td><td>None</td><td>Rapid brute-force, 429 appears early</td></tr>
  <tr><td>4 -- Burst</td><td>30</td><td>None</td><td>Sustained attack, maximum blocking demo</td></tr>
</table>
<div class="callout callout-warn">
  <strong>Critical architectural note:</strong> The script routes ALL traffic through the monitoring proxy at port 9000 (not directly to port 8000 or 8001). Hardened-API requests use the header <code>X-Target: hardened</code> which the proxy reads and internally forwards to port 8001. Direct access to port 8001 would bypass the proxy entirely and the requests would never appear on the dashboard. This is the same principle as the shop app: the proxy at port 9000 is the single chokepoint for dashboard visibility.
</div>

<h4 class="sub3">How the monitoring detects this</h4>
<p>When the hardened API returns HTTP 429, the anomaly detector's rule layer immediately flags it as <code>rate_limit_triggered</code> with score -0.5 before the ML model is consulted.</p>

<!-- API5 -->
<h2 class="sub" id="api5">API5:2023 — Broken Function Level Authorization</h2>
<p><span class="badge badge-high">HIGH</span> <span class="badge owasp">API5:2023</span> CWE-285</p>
<p><strong>What it is:</strong> The <code>/admin/*</code> endpoints verify that a valid JWT is present (the user is logged in) but never check whether that user's <code>role</code> is actually <code>admin</code>. Any regular user who knows the admin endpoint paths can call them.</p>

<div class="compare">
  <div>
    <div class="compare-hdr vuln-hdr">Vulnerable — admin endpoint</div>
    <pre class="vuln-code">@app.get("/admin/users")
def admin_list_users(
    current_user: dict = Depends(get_current_user)
):
    # get_current_user only checks the JWT is
    # valid — it never checks role.
    # Any authenticated user reaches here.
    return list(users_db.values())</pre>
  </div>
  <div>
    <div class="compare-hdr hard-hdr">Hardened — require_admin dependency</div>
    <pre class="hard-code">def require_admin(
    current_user: dict = Depends(get_current_user)
) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(403,
                            "Admin access required")
    return current_user

@app.get("/admin/users")
def admin_list_users(
    request: Request,
    admin: dict = Depends(require_admin)
):
    # Only reaches here if role == "admin"
    return [{k: v for k, v in u.items()
             if k != "password"}
            for u in users_db.values()]</pre>
  </div>
</div>

<h4 class="sub3">How the monitoring detects this</h4>
<p>Any request containing <code>/admin</code> in the path is immediately flagged by the rule-based layer as <code>admin_endpoint_access</code> with score -0.7, regardless of whether the request succeeds or returns 403.</p>

<!-- API8 -->
<h2 class="sub" id="api8">API8:2023 — Security Misconfiguration</h2>
<p><span class="badge badge-med">MEDIUM</span> <span class="badge owasp">API8:2023</span> CVE-2021-44228 (Log4Shell relates to config exposure), CWE-16</p>
<p><strong>What it is:</strong> This covers multiple related misconfigurations in the vulnerable API: a debug endpoint that leaks secrets, verbose error messages, wildcard CORS, and exposed API documentation. Any one of these individually reduces security; together they are severe.</p>

<table>
  <tr><th>Misconfiguration</th><th>Vulnerable API</th><th>Hardened API</th></tr>
  <tr>
    <td>Debug endpoint</td>
    <td><code>GET /debug/config</code> with no auth returns secret key, algorithm, environment, user count, debug_mode=True</td>
    <td>Endpoint does not exist (404)</td>
  </tr>
  <tr>
    <td>JWT secret</td>
    <td>Hardcoded as <code>"secret"</code> in source code, also leaked via /debug/config</td>
    <td>Loaded from <code>JWT_SECRET</code> environment variable; server refuses to start if missing</td>
  </tr>
  <tr>
    <td>CORS</td>
    <td><code>allow_origins=["*"]</code> — any website can make authenticated cross-origin requests</td>
    <td>Only origins in <code>ALLOWED_ORIGINS</code> env var are allowed</td>
  </tr>
  <tr>
    <td>Error verbosity</td>
    <td>Login returns <em>"Wrong password for user 'alice'"</em> or <em>"User not found: 'bob'"</em> — reveals username validity</td>
    <td>Always returns <em>"Invalid credentials"</em></td>
  </tr>
  <tr>
    <td>API documentation</td>
    <td><code>docs_url="/docs", redoc_url="/redoc"</code> — interactive Swagger UI exposed to anyone</td>
    <td><code>docs_url=None, redoc_url=None</code> — disabled entirely</td>
  </tr>
</table>

<div class="compare">
  <div>
    <div class="compare-hdr vuln-hdr">Vulnerable — debug endpoint</div>
    <pre class="vuln-code">SECRET_KEY = "secret"   # hardcoded

@app.get("/debug/config") # no auth decorator
def debug_config():
    return {
        "secret_key": SECRET_KEY,
        "algorithm": ALGORITHM,
        "environment": "vulnerable",
        "users_count": len(users_db),
        "server_time": time.time(),
        "debug_mode": True,
    }

app = FastAPI(
    docs_url="/docs",    # exposed
    redoc_url="/redoc",
)</pre>
  </div>
  <div>
    <div class="compare-hdr hard-hdr">Hardened — no debug, no docs</div>
    <pre class="hard-code">SECRET_KEY = os.environ.get("JWT_SECRET", "")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET env var must be set"
    )

# No /debug/config endpoint at all.

app = FastAPI(
    docs_url=None,       # disabled
    redoc_url=None,
)

# Generic error — no username leakage
raise HTTPException(401, "Invalid credentials")</pre>
  </div>
</div>

<h4 class="sub3">How the monitoring detects this</h4>
<p>Any request containing <code>/debug</code> in the path is flagged as <code>debug_endpoint_access</code> with score -0.9 by the rule-based layer. This is the highest-severity rule score in the system, reflecting that debug endpoint access is an unambiguous attack indicator.</p>

<!-- ═══════════════════════════════════════════
     SECTION 6 — ML ANOMALY DETECTION
═══════════════════════════════════════════ -->
<h1 class="section" id="s10">6. ML Anomaly Detection — Deep Dive</h1>

<h2 class="sub">6.1 Algorithm: IsolationForest</h2>
<p>IsolationForest is an unsupervised anomaly detection algorithm. It works by building an ensemble of random decision trees. Normal data points require many splits to isolate because they are dense and similar to each other. Anomalous points can be isolated in very few splits because they are rare and different from the norm. The algorithm assigns each data point an anomaly score based on the average depth required to isolate it.</p>

<p><strong>Why IsolationForest was chosen:</strong></p>
<ul>
  <li>Unsupervised — does not need labelled attack examples to train. This mirrors real-world WAF deployments where you cannot label all attacks in advance.</li>
  <li>Efficient — O(n log n) training time, O(log n) prediction time per request.</li>
  <li>Interpretable — the decision_function score is directly meaningful: negative values are anomalous, zero is the boundary, positive values are normal.</li>
</ul>

<h2 class="sub">6.2 Training Data</h2>
<p>The model is trained on 2000 synthetic normal traffic samples generated by <code>train_model.py</code>. The generator uses a fixed random seed (42) for reproducibility. The distribution is designed to reflect realistic API traffic:</p>
<ul>
  <li>Methods: 60% GET, 25% POST, 10% PUT, 5% DELETE</li>
  <li>Path depth: 1–3 segments</li>
  <li>Auth presence: 80% authenticated, 20% unauthenticated</li>
  <li>Status codes: 70% 200, 10% 201, 5% each for 400/401/404/422</li>
  <li>Response time: exponential distribution with mean 80ms</li>
  <li>Hour of day: uniform 0–23</li>
  <li><code>is_admin</code>: always 0 (normal traffic never hits /admin)</li>
  <li><code>is_debug</code>: always 0 (normal traffic never hits /debug)</li>
  <li><code>is_error</code>: derived from status code ≥ 400</li>
  <li><code>bola_suspected</code>: always 0 (normal traffic has matching JWT sub and URL ID)</li>
</ul>

<p>The model is trained with <code>contamination=0.05</code> — this tells IsolationForest to treat approximately 5% of its own training data as anomalies when setting the decision boundary. This calibrates the sensitivity of the detector.</p>

<h2 class="sub">6.3 Detection Layers</h2>
<p>Every proxied request passes through two layers. The rule layer fires first; if it matches, the ML layer is skipped entirely.</p>

<table>
  <tr><th>Layer</th><th>Trigger</th><th>Reason Code</th><th>Score</th></tr>
  <tr><td rowspan="5"><strong>Rule-based</strong><br>(fires first)</td><td>JWT sub ≠ user ID in /users/{id} AND status 200</td><td>bola_object_accessed</td><td>-0.8</td></tr>
  <tr><td>JWT sub ≠ user ID in /users/{id} AND status not 200</td><td>bola_attempt_detected</td><td>-0.8</td></tr>
  <tr><td>/debug in path</td><td>debug_endpoint_access</td><td>-0.9</td></tr>
  <tr><td>/admin in path</td><td>admin_endpoint_access</td><td>-0.7</td></tr>
  <tr><td>HTTP 429 response</td><td>rate_limit_triggered</td><td>-0.5</td></tr>
  <tr><td rowspan="4"><strong>ML</strong><br>(fires if no rule matched)</td><td>ML score below threshold AND status ≥ 400</td><td>elevated_error_rate</td><td>model score</td></tr>
  <tr><td>ML score below threshold AND response_ms > 2000</td><td>slow_response</td><td>model score</td></tr>
  <tr><td>ML score below threshold, other</td><td>unusual_pattern</td><td>model score</td></tr>
  <tr><td>ML score above threshold</td><td>normal</td><td>model score</td></tr>
</table>

<h2 class="sub">6.4 Limitations</h2>
<p>BOLA attacks (GET /users/2 instead of GET /users/1) are invisible to the ML layer alone because all 10 features are identical to legitimate traffic — both are authenticated GETs to a 2-segment path returning 200. This is why the rule-based BOLA detection (JWT sub comparison) was added as a first layer. This is an honest limitation of pure ML-based approaches to API security.</p>

<!-- ═══════════════════════════════════════════
     SECTION 7 — QUICK REFERENCE
═══════════════════════════════════════════ -->
<h1 class="section" id="s11">7. Quick Reference</h1>
<h2 class="sub">Credentials</h2>
<table>
  <tr><th>Account</th><th>Username</th><th>Password</th><th>Role</th></tr>
  <tr><td>Alice</td><td>alice</td><td>alice123</td><td>user</td></tr>
  <tr><td>Bob</td><td>bob</td><td>bob123</td><td>user</td></tr>
  <tr><td>Admin</td><td>admin</td><td>admin123</td><td>admin</td></tr>
  <tr><td>JWT weak secret</td><td colspan="3"><code>secret</code> (only on vulnerable API)</td></tr>
</table>

<h2 class="sub">URLs</h2>
<table>
  <tr><th>Resource</th><th>URL</th></tr>
  <tr><td>Shop App (demo UI)</td><td>http://localhost:8000/ui</td></tr>
  <tr><td>Vulnerable API docs (Swagger)</td><td>http://localhost:8000/docs</td></tr>
  <tr><td>Hardened API docs</td><td>Disabled -- returns 404</td></tr>
  <tr><td>Monitoring dashboard</td><td>http://localhost:9000/dashboard</td></tr>
  <tr><td>Service health check</td><td>http://localhost:9000/monitor/health</td></tr>
</table>

<h2 class="sub">Scripts (run from project root on host machine)</h2>
<table>
  <tr><th>Script</th><th>What it does</th><th>Requires</th></tr>
  <tr><td><code>python demo.py</code></td><td>Automated press-Enter CLI walkthrough of all 6 OWASP scenarios</td><td>httpx, rich, python-jose</td></tr>
  <tr><td><code>python rate_limit_demo.py</code></td><td>Interactive API4 brute-force demo -- choose a preset, watch 429s appear live on dashboard</td><td>httpx, rich</td></tr>
  <tr><td><code>python evaluate.py</code></td><td>Standalone comparison script -- runs all 7 attack scenarios against both APIs, generates HTML report</td><td>httpx, python-jose</td></tr>
  <tr><td><code>python generate_report.py</code></td><td>Regenerates this presenter guide as HTML and PDF</td><td>None (stdlib only)</td></tr>
</table>
<div class="callout callout-info">
  <strong>All demo scripts route through port 9000.</strong> Every host-side script that should appear on the monitoring dashboard targets <code>http://localhost:9000</code> (the proxy), not port 8000 or 8001 directly. Hardened-API requests add the header <code>X-Target: hardened</code>. Direct access to port 8001 bypasses logging entirely.
</div>

<!-- ═══════════════════════════════════════════
     SECTION 8 — START AND STOP
═══════════════════════════════════════════ -->
<h1 class="section" id="s12">8. How to Start and Stop</h1>

<h2 class="sub">Starting everything</h2>
<pre># From inside the api-security-project/ directory:

docker compose up -d --build</pre>
<p>The <code>-d</code> flag runs in detached mode (background). The <code>--build</code> flag rebuilds images — only needed the first time or after code changes. On subsequent starts, omit <code>--build</code> to use cached images and start faster.</p>

<pre># Verify all containers are running:
docker compose ps

# Check all three services are reachable:
curl http://localhost:9000/monitor/health</pre>

<h2 class="sub">Stopping everything</h2>
<pre># Stop and remove containers (data is preserved):
docker compose down

# Full reset — also wipes database and ML model:
docker compose down
del data\traffic.db
del data\model.joblib</pre>
<p>After a full reset, the model will retrain automatically on the next <code>docker compose up</code>.</p>

<h2 class="sub">Running the automated scanner</h2>
<pre># Brief report (default):
docker compose run --rm --profile tools testing-engine

# Detailed report (CVEs, PoC payloads, remediation):
docker compose run --rm --profile tools -e REPORT_DETAIL=detailed testing-engine</pre>

<h2 class="sub">Running the CLI demo script</h2>
<pre># Requires httpx and rich on the host machine:
pip install httpx rich python-jose

# From the project root (not the api-security-project folder):
python demo.py</pre>

<!-- ═══════════════════════════════════════════
     SECTION 9 — DEMONSTRATION WORKFLOWS
═══════════════════════════════════════════ -->
<h1 class="section" id="s13">9. Demonstration Workflows</h1>

<h2 class="sub">Workflow A — CLI Demo Script (Recommended for presentations)</h2>
<p>Best for showing a structured walkthrough of all six attacks in sequence. Takes roughly 10–12 minutes.</p>
<ol>
  <li>Start containers: <code>docker compose up -d</code></li>
  <li>Open <code>http://localhost:9000/dashboard</code> in a browser and position it on half the screen</li>
  <li>Open a terminal in the <code>api-security-project</code> parent directory and run <code>python demo.py</code></li>
  <li>Press Enter to advance. After each scenario, point to the dashboard and show the anomaly being logged in real time</li>
  <li>At the end, <code>demo.py</code> calls the comparison endpoint and prints a link to the HTML report</li>
  <li>Open the report link and walk through the scoring cards</li>
</ol>
<div class="callout callout-good"><strong>Tip:</strong> Reset the dashboard logs first (<em>Reset Logs</em> button, top right) so only the demo traffic is visible.</div>

<h2 class="sub">Workflow B — Interactive Shop App (Best for BOLA and debug demos)</h2>
<ol>
  <li>Open <code>http://localhost:8000/ui</code> and <code>http://localhost:9000/dashboard</code> side by side</li>
  <li>Log in as <strong>alice</strong> / <strong>alice123</strong> — watch the login request appear on the dashboard</li>
  <li>In the <strong>BOLA</strong> panel, enter user ID <strong>2</strong> and click Fetch User — it returns bob's email, balance, and role. Switch to the Dashboard Anomalies tab — it shows <code>bola_object_accessed</code></li>
  <li>Click the <strong>Debug Config</strong> tab and press <strong>GET /debug/config</strong> — the response shows the JWT secret key in plain text. The dashboard logs <code>debug_endpoint_access</code></li>
  <li>In the <strong>Mass Assignment</strong> panel, fill in Role: <code>admin</code> and Balance: <code>999999</code>, then Save Changes — the response shows alice is now an admin</li>
  <li>Toggle to <strong>Hardened</strong> mode using the nav bar switch. Repeat steps 3–5 and show each being blocked (403, 404, fields ignored)</li>
</ol>

<h2 class="sub">Workflow C — Comparison Report</h2>
<ol>
  <li>On the dashboard → <strong>Reports</strong> tab → <strong>Run Comparison</strong> panel → click <strong>Run Comparison</strong></li>
  <li>Wait ~15 seconds for all 7 scenarios to run against both APIs</li>
  <li>The score cards appear: typically Vulnerable API ~17% vs Hardened API ~100%, with an improvement of ~83 pp</li>
  <li>Click <strong>View Report</strong> to open the full HTML with per-scenario attack/result/fix cards</li>
</ol>

<h2 class="sub">Workflow D — Automated Scan Report</h2>
<ol>
  <li>Run: <code>docker compose run --rm --profile tools testing-engine</code></li>
  <li>Watch the terminal output as each OWASP category is tested</li>
  <li>When complete, open the dashboard Reports tab — the new report appears at the top</li>
  <li>Open the HTML report and walk through the security score, vulnerability cards, and (in detailed mode) the CVE badges, PoC payloads, and remediation steps</li>
</ol>

<h2 class="sub">Workflow E — API4 Rate Limit Demo (rate_limit_demo.py)</h2>
<p>Use this workflow specifically for API4. It is faster and clearer than demo.py for this vulnerability because the results appear one line at a time as the requests fire.</p>
<ol>
  <li>Ensure containers are running: <code>docker compose up -d</code></li>
  <li>Open <code>http://localhost:9000/dashboard</code> in a browser, go to the <strong>Anomalies</strong> tab</li>
  <li>Click <strong>Reset Logs</strong> to clear previous traffic so the demo is clean</li>
  <li>Open a terminal at the project root and run: <code>python rate_limit_demo.py</code></li>
  <li>Select preset <strong>1</strong> (Light -- 6 requests) for a quick demo or <strong>3</strong> (Heavy -- 20 requests) for maximum effect</li>
  <li>The terminal shows each attempt one line at a time. The vulnerable API shows <code>401 wrong creds</code> every time. The hardened API shows <code>401 wrong creds</code> for the first 5 attempts, then <code>429 BLOCKED</code> from attempt 6 onward</li>
  <li>Switch to the browser. Within 10 seconds the Anomalies tab shows <code>rate_limit_triggered</code> entries for every 429 response</li>
  <li>At the end the script prints a summary table showing total blocked vs total sent for both APIs side by side</li>
</ol>
<div class="callout callout-info">
  <strong>Why it uses port 9000:</strong> The script routes all requests through the monitoring proxy at <code>http://localhost:9000/auth/login</code>. Hardened-API requests include the header <code>X-Target: hardened</code> which the proxy reads and internally forwards to port 8001. Direct access to port 8001 would bypass the proxy and nothing would appear on the dashboard.
</div>

<!-- ═══════════════════════════════════════════
     SECTION 10 — Q&A
═══════════════════════════════════════════ -->
<h1 class="section" id="s14">10. Likely Lecturer Questions &amp; Answers</h1>

<div class="qa-item">
  <div class="qa-q">Why use a transparent proxy for monitoring instead of instrumenting each API directly?</div>
  <div class="qa-a">A transparent proxy is agnostic to the application it monitors. It can be deployed in front of any API without changing a single line of application code. This models how real-world API gateways and WAFs work — they sit at the network edge, not inside the application. It also means the vulnerable API stays purely vulnerable with no monitoring logic mixed in, which keeps the demonstration clean and the code straightforward to read.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Why IsolationForest rather than a supervised classifier?</div>
  <div class="qa-a">Supervised classifiers require labelled data — you need examples of both normal traffic and attack traffic before training. In a real deployment you cannot know all attack signatures in advance, and collecting labelled attack examples is difficult. IsolationForest is unsupervised: it learns what normal traffic looks like from unlabelled data and flags deviations. This mirrors how real SIEM and anomaly-detection systems work. The trade-off is higher false-positive rates compared to a well-trained supervised classifier, but much lower barrier to deployment.</div>
</div>

<div class="qa-item">
  <div class="qa-q">How does BOLA detection work if GET /users/2 and GET /users/1 look identical to a machine learning model?</div>
  <div class="qa-a">They do look identical — same method, same path depth, same auth flag, similar status code and response time. This is an honest acknowledged limitation of pure ML anomaly detection for BOLA. The solution implemented here is a rule-based pre-check: the monitoring proxy base64-decodes the JWT payload (without verifying the signature — only the claims matter here) to extract the <code>sub</code> field, which is the authenticated user's numeric ID. It then uses a regular expression to extract the numeric user ID from the URL path <code>/users/{id}</code>. If these two numbers differ, <code>bola_suspected</code> is set to True and the rule layer flags it before the ML model is ever consulted.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What is the security score and how is it calculated?</div>
  <div class="qa-a">The security score is <code>(number of test scenarios passed / total scenarios) × 100</code>, expressed as a percentage. A scenario is passed if the API correctly prevented the attack — for example, returning 403 on a BOLA attempt, 429 on rate limiting, or 404 for a missing debug endpoint. The vulnerable API typically scores 0–17% because it passes only the health check and some basic connectivity tests. The hardened API typically scores 83–100%.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What is the contamination parameter in IsolationForest and how did you choose 0.05?</div>
  <div class="qa-a">Contamination tells the IsolationForest what fraction of the training data to treat as anomalies when setting the decision boundary. A value of 0.05 means the model expects roughly 5% of traffic to be anomalous. Setting it too low makes the detector insensitive — it flags almost nothing. Setting it too high creates excessive false positives that make the anomaly log noisy and hard to interpret. 0.05 was chosen as a standard starting value for low-noise environments. In a production deployment this parameter would be tuned against historical data.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Why does the Pydantic model approach work for preventing mass assignment? Couldn't a determined attacker bypass it?</div>
  <div class="qa-a">FastAPI's Pydantic validation happens in the framework before the handler function is called. The framework deserialises the JSON body into the declared model, discarding any fields not present in the model definition. This is enforced at the framework level, not in application code — a bypass would require a bug in FastAPI or Pydantic itself. The attacker cannot send extra fields that survive into the handler because the model definition is the contract. This is structurally different from manually checking a whitelist in code, which a developer might forget to update; the absence of a field from the model makes it impossible to process even if the developer doesn't think about it.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What is the difference between API1 (BOLA) and API5 (Broken Function Level Authorization)?</div>
  <div class="qa-a">BOLA is about accessing someone else's data object — the resource type is one you are normally allowed to access (e.g., user profiles), but you access a specific instance belonging to another user. Broken Function Level Auth is about calling a function you are not supposed to have access to at all — in this case, admin-only endpoints. BOLA is a horizontal privilege escalation (same role, different user's data); Broken Function Level Auth is a vertical privilege escalation (gaining functionality reserved for a higher role).</div>
</div>

<div class="qa-item">
  <div class="qa-q">Why doesn't the hardened API return the user's balance in GET /users/{id}, even for admin?</div>
  <div class="qa-a">Financial data is in a separate sensitivity class from profile data. Even administrators performing user lookups through an API do not typically need to see individual account balances in a GET response — that would be a separate financial reporting endpoint with its own access controls and audit logging. Excluding it from the general user endpoint is defence in depth: even if an admin token is compromised, the attacker cannot bulk-exfiltrate financial data through the general user listing endpoint.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Does the system work offline? What if there is no internet at the presentation venue?</div>
  <div class="qa-a">Yes, completely offline. All APIs and the monitoring service run in local Docker containers. The SQLite database and trained ML model are stored in the <code>./data/</code> volume on the host. Generated report HTML files are self-contained with no external scripts. Chart.js, which powers the dashboard graphs, is bundled inside the monitoring Docker image at <code>/static/chart.min.js</code> and served locally at <code>http://localhost:9000/static/chart.min.js</code> — the CDN URL was removed. The only time internet is needed is during <code>docker compose build</code>, which pulls the base Python image and installs pip packages. Once built, the images are cached and the system is fully self-contained.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Why is the JWT secret loaded at startup and what happens if it is missing?</div>
  <div class="qa-a">Loading at startup with a hard fail is a security design pattern called "fail-fast on misconfiguration." The line <code>if not SECRET_KEY: raise RuntimeError("JWT_SECRET env var must be set")</code> means the server refuses to start rather than silently running with a weak or empty secret. This prevents a misconfigured production deployment from being accidentally insecure. In Docker Compose, the <code>.env</code> file supplies this value; in a cloud deployment it would come from a secrets manager. The pattern forces the operator to consciously provide the secret rather than relying on a default.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What would an attacker do with the JWT secret leaked from /debug/config?</div>
  <div class="qa-a">With the secret <code>"secret"</code>, an attacker can forge an arbitrary JWT using any standard JWT library. They can set any <code>sub</code> (user ID), any <code>username</code>, and critically <code>role: admin</code>. Since the vulnerable API validates tokens using this same secret, the forged token will pass validation and grant full admin access to every endpoint. The attacker never needs to know any user's password. This is exactly what the JWT forgery scenario in the testing engine and demo script demonstrates.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Why are the APIs using in-memory dictionaries instead of a real database?</div>
  <div class="qa-a">Simplicity and reproducibility. The in-memory dictionaries reset to their original state every time the container restarts, so the demo environment is always clean and consistent regardless of what was done in a previous session. A real database would require migrations, seeds, and reset scripts to achieve the same reproducibility. The vulnerability demonstrations work identically whether the data is in memory or in PostgreSQL — the flaw is in the API layer (missing access controls), not the storage layer.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What does the X-Target header do and why is it stripped before forwarding?</div>
  <div class="qa-a">The <code>X-Target: hardened</code> header is an internal routing signal used only between the shop app browser and the monitoring proxy. When the monitoring proxy sees it, it routes the request to <code>http://hardened-api:8001</code> instead of the default vulnerable API. It is stripped from the forwarded request because it is an internal implementation detail that the upstream API should never see — sending non-standard headers to an API is itself a form of information leakage about the infrastructure, and the hardened API might reject requests with unknown headers. Stripping it keeps the upstream API's request exactly as the client intended.</div>
</div>

<div class="qa-item">
  <div class="qa-q">How does the testing engine know if a test passed or failed?</div>
  <div class="qa-a">Each test module returns a structured result object with a <code>vulnerable</code> boolean. The logic varies by test. For BOLA: the test logs in as alice, then requests bob's data — if the response is HTTP 200 with bob's data, the API is vulnerable. For rate limiting: 15 rapid login requests are sent — if any returns HTTP 429, the API is not vulnerable. For mass assignment: a PUT request with role and balance is sent — the response JSON is inspected to check whether <code>role</code> was actually changed. For the debug endpoint: a GET with no credentials is sent — HTTP 200 means vulnerable, HTTP 404 means hardened.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What is the profile: tools setting in docker-compose.yml and why is it used for the testing engine?</div>
  <div class="qa-a">Docker Compose profiles allow services to be selectively started. Services without a profile are started by <code>docker compose up</code>. Services with a profile are excluded from <code>up</code> and only start when explicitly requested with <code>--profile tools</code>. The testing engine is given the <code>tools</code> profile because it is a run-once scanner, not a persistent service. Including it in the default <code>up</code> command would cause it to start, run its tests, and immediately exit — Docker Compose would then show it as exited, which looks like a failure. Keeping it behind a profile makes the default stack clean and the scanner available on demand.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What OWASP categories did you NOT implement and why?</div>
  <div class="qa-a">The OWASP API Top 10:2023 has ten categories. This framework covers API1 (BOLA), API2 (Broken Authentication), API3 (Mass Assignment), API4 (Unrestricted Resource Consumption), API5 (Broken Function Level Auth), and API8 (Security Misconfiguration). Not covered are API6 (Unrestricted Access to Sensitive Business Flows — e.g., account takeover through feature abuse), API7 (Server-Side Request Forgery), API9 (Improper Inventory Management — shadow APIs), and API10 (Unsafe Consumption of APIs — trusting third-party data). These were excluded primarily because they require a more complex application architecture to demonstrate meaningfully. SSRF for example needs an internal service for the forged request to reach; shadow APIs need multiple API versions co-running; unsafe consumption needs a third-party API dependency.</div>
</div>

<div class="qa-item">
  <div class="qa-q">How is the monitoring dashboard updated in real time? Does it use WebSockets?</div>
  <div class="qa-a">No WebSockets. The dashboard uses simple HTTP polling via the browser's <code>fetch</code> API. JavaScript <code>setInterval</code> functions call <code>/monitor/stats</code>, <code>/monitor/feed</code>, <code>/monitor/anomalies</code>, and <code>/monitor/timeline</code> every 10 seconds and update the UI using DOM manipulation. WebSockets would provide lower latency and eliminate unnecessary polling, but HTTP polling is simpler to implement, does not require a persistent connection, and is sufficient for a demonstration where the audience can wait one polling cycle (10 seconds) to see a result.</div>
</div>

<div class="qa-item">
  <div class="qa-q">What is the contamination rate's effect and what would happen if you set it to 0.01?</div>
  <div class="qa-a">Lowering contamination to 0.01 (1%) would raise the anomaly detection threshold — only the most extreme deviations from normal traffic would be flagged. The rule-based layer would still work because it doesn't use the ML threshold, but the ML fallback layer would produce far fewer positives. At 0.01, ordinary unusual traffic patterns (e.g., an unusually slow response, an unusual sequence of error codes) would be ignored. Raising contamination to 0.15 would produce many more ML flags, increasing false positives — legitimate bursts of 404 responses or slow endpoints would be flagged as anomalous. 0.05 balances sensitivity and specificity for a demonstration environment.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Why does rate_limit_demo.py target port 9000 instead of port 8001 directly for the hardened API?</div>
  <div class="qa-a">Port 9000 is the monitoring proxy — the single chokepoint through which all observable traffic must flow. If the script sent requests directly to port 8001, those requests would bypass the proxy entirely: they would never be logged to SQLite, never scored by the anomaly detector, and never appear on the dashboard. The proxy is the dashboard. The script routes hardened-API traffic through port 9000 using the header <code>X-Target: hardened</code>, which the proxy reads, strips, and uses to internally forward the request to <code>hardened-api:8001</code> on the Docker bridge network. This same principle applies to demo.py and evaluate.py — any host-side tool that needs to appear on the dashboard must go through port 9000. This was discovered when the script was initially written targeting ports 8000 and 8001 directly: the 429 responses were returned correctly but nothing appeared on the dashboard, because the proxy had never seen the traffic.</div>
</div>

<div class="qa-item">
  <div class="qa-q">Could someone deploy the hardened API in production? What is still missing?</div>
  <div class="qa-a">The hardened API demonstrates the fixes for the six covered vulnerabilities, but it is a demonstration tool, not a production-ready system. Missing for production: persistent database (PostgreSQL/MySQL), HTTPS/TLS termination, input sanitisation beyond Pydantic validation, password reset flows, email verification, account lockout after failed attempts (beyond rate limiting by IP), proper logging and audit trails, secrets rotation, container non-root user, health checks with restart policies, and horizontal scaling considerations. It also uses an in-memory user store that resets on restart. The purpose is to show the security concepts, not to be a deployable product.</div>
</div>

</div><!-- end .content -->

</body>
</html>"""

# ── write HTML ──────────────────────────────────────────────────────────────
script_dir = os.path.dirname(os.path.abspath(__file__))
html_path  = os.path.join(script_dir, "CY384_Presenter_Guide.html")
pdf_path   = os.path.join(script_dir, "CY384_Presenter_Guide.pdf")

with open(html_path, "w", encoding="utf-8") as f:
    f.write(HTML)
print(f"HTML written -> {html_path}")

# ── convert to PDF via Edge headless ────────────────────────────────────────
edge_candidates = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]
chrome_candidates = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

browser = None
for p in edge_candidates + chrome_candidates:
    if os.path.exists(p):
        browser = p
        break

if browser:
    file_url = "file:///" + html_path.replace("\\", "/")
    result = subprocess.run([
        browser,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--print-to-pdf={pdf_path}",
        "--no-pdf-header-footer",
        "--print-to-pdf-no-header",
        file_url,
    ], capture_output=True, timeout=60)
    if os.path.exists(pdf_path):
        size_kb = os.path.getsize(pdf_path) // 1024
        print(f"PDF written  -> {pdf_path}  ({size_kb} KB)")
    else:
        print("PDF conversion attempted but file not found.")
        print("Open the HTML in your browser and press Ctrl+P → Save as PDF.")
else:
    print("No Edge or Chrome found.")
    print(f"Open this file in your browser and press Ctrl+P → Save as PDF:")
    print(f"  {html_path}")
