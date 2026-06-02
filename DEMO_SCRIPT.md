# CY384 API Security Framework — Demo Script

**Team One | Topic #27 | University of Mines and Technology, Ghana**

---

## Prerequisites

| Requirement | Check |
|---|---|
| Docker Desktop is running | `docker info` |
| Terminal open inside `api-security-project/` | `pwd` shows the right folder |
| Python + httpx + rich installed on host | `pip install httpx rich python-jose` |
| Browser open | Chrome / Edge recommended |

---

## Step 1 — Start the stack

```bash
docker compose up -d --build
```

`-d` runs containers in the background. `--build` is only needed the first time or after code changes. On subsequent starts, omit `--build` for a faster startup.

Wait about 15 seconds, then verify:

```bash
docker compose ps
```

All three containers should show `running`:

| Container | URL | Purpose |
|---|---|---|
| `vulnerable-api` | http://localhost:8000 | Intentionally flawed API + Shop App |
| `hardened-api` | http://localhost:8001 | Same API with all fixes applied |
| `monitoring` | http://localhost:9000 | Proxy + dashboard + anomaly detection |

Health check (all three at once):

```
http://localhost:9000/monitor/health
```

---

## Step 2 — Open the monitoring dashboard

Open **http://localhost:9000/dashboard** in your browser and keep it visible alongside the terminal or the Shop App throughout the demo. Every request you make appears here within 10 seconds.

Use the **Reset Logs** button (top-right, red) before each demo run to start with a clean slate.

---

## Step 3 — Option A: Automated CLI Demo (recommended for presentations)

Runs all six OWASP scenarios in sequence with press-Enter pacing and coloured result tables.

```bash
# Run from the api-security-project parent directory
python demo.py
```

- Press **Enter** to advance through each scenario.
- Each scenario shows the attack payload, the result on the Vulnerable API, and the result on the Hardened API side by side.
- Switch to the browser dashboard between scenarios to show anomalies being logged in real time.
- At the end, `demo.py` automatically calls the comparison endpoint and prints a link to the HTML report.

---

## Step 4 — Option B: Interactive Shop App Demo

Best for showing individual vulnerabilities hands-on. Open both URLs side by side:

- **Shop App:** http://localhost:8000/ui
- **Dashboard:** http://localhost:9000/dashboard

Log in as **alice / alice123**. The nav bar shows **INTENTIONALLY VULNERABLE** in red.

### API1 — BOLA (Broken Object Level Authorization)

1. Go to the **BOLA** panel in the left sidebar.
2. The user ID field defaults to **2** (bob's account). Click **Fetch User**.
3. The response returns bob's email, role, and balance — data alice should never be able to access.
4. Try ID **3** to get the admin's account details.
5. Toggle to **Hardened** mode (nav bar top). Repeat — both return **403 Forbidden**.
6. Dashboard → **Anomalies** tab shows `bola_object_accessed` for each attempt.

### API3 — Mass Assignment

1. Go to the **Profile** panel and click **My Profile** to load alice's data.
2. In the **Update Profile** section, fill in **Role:** `admin` and **Balance:** `999999`.
3. Click **Save Changes**.
4. The vulnerable API accepts these fields and promotes alice to admin with 999999 balance.
5. Toggle to **Hardened** mode. Repeat — the response shows only email/password were accepted; role and balance are silently ignored.

### API5 — Broken Function Level Authorization

1. Click the **Admin Endpoints** tab (right panel).
2. Click **GET /admin/users** while logged in as alice (a regular user).
3. The vulnerable API returns the full user list including the admin's data.
4. Toggle to **Hardened** mode. Repeat — returns **403 Forbidden**.
5. Dashboard logs `admin_endpoint_access` for each attempt.

### API8 — Security Misconfiguration (Debug Endpoint)

1. Click the **Debug Config** tab (right panel).
2. Click **GET /debug/config** — no login is required to call this.
3. The response exposes: the JWT signing secret (`"secret"`), the algorithm, user count, and debug_mode.
4. Toggle to **Hardened** mode. Repeat — returns **404 Not Found**.
5. Dashboard logs `debug_endpoint_access` (score -0.9, the highest severity).

**What to say:** *"An attacker who finds this endpoint gets the JWT secret. They can now forge any token with any role without knowing any user's password."*

### API2 — JWT Forgery (using the leaked secret)

After the debug config demo:

```python
# In a Python shell (python-jose installed):
from jose import jwt
forged = jwt.encode(
    {"sub": "1", "username": "alice", "role": "admin"},
    "secret",        # the key we just leaked from /debug/config
    algorithm="HS256"
)
print(forged)
```

Use the forged token in a request:

```bash
curl http://localhost:8000/admin/users -H "Authorization: Bearer <paste_token>"
```

The vulnerable API accepts it as a valid admin session. The hardened API rejects it with 401 because it uses a different secret from the `.env` file.

---

## Step 5 — API4 Rate Limiting Demo

API4 cannot be shown from the Shop App UI because brute-forcing from a browser is slow and clunky. Use the dedicated demo script instead:

```bash
python rate_limit_demo.py
```

You will be shown four presets to choose from:

| Preset | Requests | Delay | Best for |
|---|---|---|---|
| 1 — Light | 6 | 0.3 s | Quick classroom demo |
| 2 — Medium | 12 | 0.1 s | Password-spray simulation |
| 3 — Heavy | 20 | None | Rapid brute-force demo |
| 4 — Burst | 30 | None | Full sustained attack demo |

The script hits **both APIs** with wrong-password login attempts and prints each HTTP response code as it arrives. The vulnerable API returns 401 every time. The hardened API starts returning **429 Too Many Requests** after the 5th attempt within a minute.

At the end it prints a summary table showing exactly when blocking kicked in.

**Keep the dashboard open** — 429 responses are automatically flagged as `rate_limit_triggered` (anomaly score -0.5) and appear in the Anomalies tab.

---

## Step 6 — Automated Scanner Report

Runs all six OWASP test modules in sequence and produces a scored HTML report.

```bash
# Brief report (default):
docker compose run --rm --profile tools testing-engine

# Detailed report (CVEs, PoC payloads, remediation steps):
docker compose run --rm --profile tools -e REPORT_DETAIL=detailed testing-engine
```

When done:
1. Open the dashboard → **Reports** tab.
2. The new report appears at the top with a **Brief** or **Detailed** badge.
3. Click **Open Report** to view the full HTML with the security score and per-vulnerability results.

---

## Step 7 — Side-by-Side Comparison Report

Runs all seven attack scenarios against both APIs simultaneously and generates a comparison HTML report.

**Via the dashboard:**
1. Open http://localhost:9000/dashboard → **Reports** tab.
2. Find the **Run Comparison** panel and click **Run Comparison**.
3. Wait ~15 seconds.
4. Score cards appear: Vulnerable API score vs Hardened API score + improvement in percentage points.
5. Click **View Report** to open the full comparison HTML.

**Via command line:**
```bash
python evaluate.py
```

---

## Step 8 — Teardown

```bash
# Stop and remove containers (database and reports are preserved):
docker compose down

# Full reset — also clears the traffic database and ML model:
docker compose down
del data\traffic.db
del data\model.joblib
```

After a full reset, the ML model retrains automatically on the next `docker compose up`.

---

## Quick Reference

### Credentials

| Account | Username | Password | Role |
|---|---|---|---|
| Alice | alice | alice123 | user |
| Bob | bob | bob123 | user |
| Admin | admin | admin123 | admin |
| JWT weak secret (vulnerable only) | — | `secret` | — |

### URLs

| Resource | URL |
|---|---|
| Shop App (interactive demo) | http://localhost:8000/ui |
| Vulnerable API Swagger docs | http://localhost:8000/docs |
| Hardened API docs | Disabled — 404 by design |
| Monitoring dashboard | http://localhost:9000/dashboard |
| Scanner UI | http://localhost:9000/scan-ui |
| Service health check | http://localhost:9000/monitor/health |

### Scripts

| Script | What it does |
|---|---|
| `python demo.py` | Automated press-Enter CLI presentation (all 6 scenarios) |
| `python rate_limit_demo.py` | Interactive API4 rate-limit brute-force demo with presets |
| `python evaluate.py` | Standalone comparison script (runs outside Docker) |
| `python generate_report.py` | Regenerates the PDF presenter guide |

### Anomaly reason codes (what you'll see on the dashboard)

| Reason code | Triggered by | Score |
|---|---|---|
| `bola_object_accessed` | JWT sub != URL user ID, request succeeded (200) | -0.8 |
| `bola_attempt_detected` | JWT sub != URL user ID, request blocked | -0.8 |
| `debug_endpoint_access` | Any request to `/debug/*` | -0.9 |
| `admin_endpoint_access` | Any request to `/admin/*` | -0.7 |
| `rate_limit_triggered` | Upstream returned HTTP 429 | -0.5 |
| `elevated_error_rate` | ML-flagged, status >= 400 | ML score |
| `unusual_pattern` | ML-flagged, no specific reason | ML score |
