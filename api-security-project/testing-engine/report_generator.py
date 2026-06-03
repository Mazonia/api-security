"""Generate HTML, JSON, and SARIF reports from OWASP test results."""
import json
import os
from datetime import datetime
from jinja2 import Template

# ── Compliance mapping ────────────────────────────────────────────────────────
COMPLIANCE_MAP = {
    "API1:2023 - Broken Object Level Authorization":          {"pci_dss": ["6.2.4","8.2.3"],    "gdpr": ["Art. 5(1)(f)","Art. 32"],   "iso27001": ["A.9.4.1","A.14.2.5"]},
    "API2:2023 - Broken Authentication":                      {"pci_dss": ["8.2.1","8.3.1"],    "gdpr": ["Art. 32(1)(b)"],            "iso27001": ["A.9.4.3","A.10.1.1"]},
    "API3:2023 - Broken Object Property Level Authorization": {"pci_dss": ["6.2.4"],            "gdpr": ["Art. 5(1)(c)","Art. 25"],   "iso27001": ["A.14.2.5","A.18.1.3"]},
    "API4:2023 - Unrestricted Resource Consumption":          {"pci_dss": ["6.2.4","6.3.1"],    "gdpr": ["Art. 32"],                  "iso27001": ["A.12.6.1","A.17.2.1"]},
    "API5:2023 - Broken Function Level Authorization":        {"pci_dss": ["7.1.1","7.2.1"],    "gdpr": ["Art. 32(4)"],               "iso27001": ["A.9.2.3","A.9.4.1"]},
    "API8:2023 - Security Misconfiguration":                  {"pci_dss": ["6.3.3","6.4.1"],    "gdpr": ["Art. 32"],                  "iso27001": ["A.14.1.3","A.18.1.3"]},
    "API9:2023 - Improper Inventory Management (GraphQL)":    {"pci_dss": ["6.3.3"],            "gdpr": ["Art. 32"],                  "iso27001": ["A.12.6.1"]},
    "CWE-312 / GDPR - PII Exposure in API Responses":        {"pci_dss": ["3.4.1","4.2.1"],    "gdpr": ["Art. 5","Art. 17","Art. 25","Art. 32","Art. 83(4)"], "iso27001": ["A.18.1.4","A.8.2.3"]},
}

def _get_compliance(category: str) -> dict:
    for key, val in COMPLIANCE_MAP.items():
        if category == key or category.startswith(key.split(" - ")[0]):
            return val
    return {}


def generate_sarif(results: list, target: str) -> dict:
    """Generate a SARIF 2.1.0 document from test results."""
    seen_rules: set = set()
    rules = []
    for cat in results:
        cat_id = cat["category"].replace(" ", "-").replace("/", "-")[:64]
        if cat_id not in seen_rules:
            seen_rules.add(cat_id)
            rules.append({
                "id": cat_id,
                "name": cat["category"].split(" - ")[0],
                "shortDescription": {"text": cat["category"].split(" - ", 1)[-1]},
                "helpUri": "https://owasp.org/API-Security/",
                "properties": {"tags": ["security", "api"]},
            })

    sarif_results = []
    for cat in results:
        cat_id = cat["category"].replace(" ", "-").replace("/", "-")[:64]
        for t in cat["tests"]:
            if not t.get("vulnerable"):
                continue
            sarif_results.append({
                "ruleId": cat_id,
                "level": "error" if t.get("severity") in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f"{t['test']}: {t['actual']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": target, "uriBaseId": "TARGETROOT"}}}],
                "properties": {
                    "severity": t.get("severity"),
                    "expected": t.get("expected"),
                    "compliance": _get_compliance(cat["category"]),
                },
            })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MazAPI Testing Engine",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/Mazonia/api-security",
                    "rules": rules,
                }
            },
            "results": sarif_results,
            "properties": {"target": target, "scannedAt": datetime.utcnow().isoformat()},
        }],
    }

try:
    from cve_data import CVE_DB
except ImportError:
    CVE_DB = {}

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Security Test Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:40px;text-align:center}
.header h1{color:#58a6ff;font-size:2.4em;margin-bottom:8px}
.header p{color:#8b949e}
.detail-badge{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.4);padding:4px 12px;border-radius:6px;font-size:.5em;font-weight:700;vertical-align:middle;margin-left:10px;text-transform:uppercase;letter-spacing:.06em}
.container{max-width:1200px;margin:0 auto;padding:30px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:22px;text-align:center}
.card .num{font-size:2.4em;font-weight:700}
.card .lbl{color:#8b949e;font-size:.85em;margin-top:6px}
.red{color:#f85149}.green{color:#3fb950}.blue{color:#58a6ff}.yellow{color:#e3b341}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}
.cbox{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px}
.cbox h3{color:#58a6ff;margin-bottom:14px;font-size:1em}
.cat{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:18px}
.cat-hdr{padding:18px 20px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.cat-hdr h2{font-size:1.1em;color:#e6edf3}
.badge{padding:4px 12px;border-radius:20px;font-size:.82em;font-weight:700}
.bv{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.bs{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid #3fb950}
.sev-CRITICAL{background:rgba(188,30,30,.2);color:#ff6b6b;border:1px solid #ff6b6b}
.sev-HIGH{background:rgba(248,81,73,.15);color:#f85149;border:1px solid #f85149}
.sev-MEDIUM{background:rgba(227,179,65,.15);color:#e3b341;border:1px solid #e3b341}
.sev-LOW{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid #58a6ff}
table{width:100%;border-collapse:collapse}
th{background:#0d1117;padding:11px 14px;text-align:left;font-size:.8em;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
td{padding:11px 14px;border-top:1px solid #21262d;font-size:.87em;word-break:break-word}
code{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:.88em}
.vY{color:#f85149;font-weight:700}.vN{color:#3fb950}
.sC{color:#f85149;font-weight:700}.sH{color:#e3b341}.sM{color:#58a6ff}.sL{color:#8b949e}
.cve-panel{padding:18px 20px;border-top:1px solid #21262d;background:#0d1117}
.cve-panel h4{color:#8b949e;font-size:.8em;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px}
.cve-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center}
.cve-badge{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:4px 10px;font-size:.8em;font-family:monospace;color:#58a6ff;text-decoration:none}
.cve-badge:hover{border-color:#58a6ff}
.owasp-link{font-size:.82em;color:#8b949e;text-decoration:none;margin-left:auto}
.owasp-link:hover{color:#58a6ff}
.vuln-desc{font-size:.87em;color:#8b949e;margin-bottom:14px;line-height:1.5}
.fixes h5{font-size:.82em;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin-bottom:8px}
.fixes ol{padding-left:18px}
.fixes li{font-size:.85em;color:#c9d1d9;line-height:1.6;padding:3px 0}
.fixes li code{color:#79c0ff}
.no-cve{font-size:.82em;color:#8b949e;padding:14px 20px}
/* ── Detailed mode blocks ── */
.detail-section{padding:18px 20px;border-top:2px solid #1c2128;background:#0a0d10}
.impact-block{margin-bottom:18px}
.impact-block h4{color:#e3b341;font-size:.8em;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;display:flex;align-items:center;gap:6px}
.impact-block h4::before{content:'⚠';font-style:normal}
.impact-block p{font-size:.86em;color:#c9d1d9;line-height:1.65}
.poc-block{margin-bottom:18px}
.poc-block h5{font-size:.78em;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin-bottom:8px}
.poc-block ol{padding-left:18px}
.poc-block li{font-size:.84em;color:#c9d1d9;line-height:1.7;padding:3px 0}
.code-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.code-pane{}
.code-label{font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.07em;padding:4px 10px;display:inline-block;border-radius:4px 4px 0 0}
.code-label.vuln-lbl{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3);border-bottom:none}
.code-label.fix-lbl{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.3);border-bottom:none}
pre.code-pre{background:#0d1117;border:1px solid #21262d;border-radius:0 6px 6px 6px;padding:14px;font-size:.82em;font-family:Consolas,'Courier New',monospace;color:#c9d1d9;overflow-x:auto;white-space:pre;margin:0;line-height:1.6}
.footer{text-align:center;padding:28px;color:#8b949e;font-size:.82em;border-top:1px solid #21262d;margin-top:32px}
</style>
</head>
<body>
<div class="header">
  <h1>API Security Test Report{% if detail == 'detailed' %}<span class="detail-badge">Detailed</span>{% endif %}</h1>
  <p>Target: {{ target }} &nbsp;|&nbsp; {{ timestamp }} &nbsp;|&nbsp; OWASP API Top 10:2023</p>
</div>
<div class="container">
  <div class="cards">
    <div class="card"><div class="num red">{{ total_vuln }}</div><div class="lbl">Vulnerabilities Found</div></div>
    <div class="card"><div class="num blue">{{ total_tests }}</div><div class="lbl">Tests Executed</div></div>
    <div class="card"><div class="num green">{{ total_tests - total_vuln }}</div><div class="lbl">Tests Passed</div></div>
    <div class="card"><div class="num yellow">{{ "%.0f"|format(score) }}%</div><div class="lbl">Security Score</div></div>
  </div>
  <div class="charts">
    <div class="cbox"><h3>Vulnerabilities by Category</h3><canvas id="barChart" height="220"></canvas></div>
    <div class="cbox"><h3>Overall Results</h3><canvas id="pieChart" height="220"></canvas></div>
  </div>
  {% for cat in categories %}
  {% set cve = cve_db.get(cat.category, {}) %}
  <div class="cat">
    <div class="cat-hdr">
      <h2>{{ cat.category }}</h2>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        {% if cve %}
        <span class="badge sev-{{ cve.severity }}">{{ cve.severity }}</span>
        {% endif %}
        <span class="badge {% if cat.vulnerable_count > 0 %}bv{% else %}bs{% endif %}">
          {{ cat.vulnerable_count }}/{{ cat.total }} Vulnerable
        </span>
      </div>
    </div>
    <table>
      <tr><th>Test</th><th>Request</th><th>Expected</th><th>Actual</th><th>Severity</th><th>Result</th></tr>
      {% for t in cat.tests %}
      <tr>
        <td>{{ t.test }}</td>
        <td><code>{{ t.request }}</code></td>
        <td>{{ t.expected }}</td>
        <td>{{ t.actual }}</td>
        <td class="s{{ t.severity[0] }}">{{ t.severity }}</td>
        <td class="{% if t.vulnerable %}vY{% else %}vN{% endif %}">{{ "VULNERABLE" if t.vulnerable else "SECURE" }}</td>
      </tr>
      {% endfor %}
    </table>
    {% if cve %}
    <div class="cve-panel">
      <h4>CVE References &amp; Remediation</h4>
      <div class="cve-row">
        {% for cve_id in cve.cves %}
        <a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{{ cve_id }}" target="_blank" rel="noopener">{{ cve_id }}</a>
        {% endfor %}
        <a class="owasp-link" href="{{ cve.owasp_ref }}" target="_blank" rel="noopener">OWASP Reference &rarr;</a>
      </div>
      <p class="vuln-desc">{{ cve.description }}</p>
      <div class="fixes">
        <h5>Remediation Steps</h5>
        <ol>
          {% for fix in cve.fixes %}
          <li>{{ fix }}</li>
          {% endfor %}
        </ol>
      </div>
    </div>
    {% if detail == 'detailed' and cve.impact %}
    <div class="detail-section">
      <div class="impact-block">
        <h4>Impact Assessment</h4>
        <p>{{ cve.impact }}</p>
      </div>
      {% if cve.poc_steps %}
      <div class="poc-block">
        <h5>Proof of Concept — Attack Steps</h5>
        <ol>
          {% for step in cve.poc_steps %}
          <li>{{ step }}</li>
          {% endfor %}
        </ol>
      </div>
      {% endif %}
      {% if cve.code_before %}
      <div class="code-grid">
        <div class="code-pane">
          <div class="code-label vuln-lbl">Vulnerable Code</div>
          <pre class="code-pre">{{ cve.code_before|e }}</pre>
        </div>
        <div class="code-pane">
          <div class="code-label fix-lbl">Fixed Code</div>
          <pre class="code-pre">{{ cve.code_after|e }}</pre>
        </div>
      </div>
      {% endif %}
    </div>
    {% endif %}
    {% else %}
    <p class="no-cve">No CVE data available for this category.</p>
    {% endif %}
  </div>
  {% endfor %}
</div>
<div class="footer">CY384 API Security Project &nbsp;|&nbsp; University of Mines and Technology, Ghana &nbsp;|&nbsp; OWASP API Security Top 10:2023</div>
<script>
const labels = {{ cat_labels|tojson }};
const vulns  = {{ vuln_counts|tojson }};
new Chart(document.getElementById('barChart'),{type:'bar',data:{labels,datasets:[{label:'Vulnerable',data:vulns,backgroundColor:'rgba(248,81,73,.7)',borderColor:'#f85149',borderWidth:1}]},options:{plugins:{legend:{labels:{color:'#c9d1d9'}}},scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},y:{ticks:{color:'#8b949e',stepSize:1},grid:{color:'#21262d'}}}}});
new Chart(document.getElementById('pieChart'),{type:'doughnut',data:{labels:['Vulnerable','Secure'],datasets:[{data:[{{ total_vuln }},{{ total_tests - total_vuln }}],backgroundColor:['rgba(248,81,73,.7)','rgba(63,185,80,.7)'],borderColor:['#f85149','#3fb950'],borderWidth:2}]},options:{plugins:{legend:{labels:{color:'#c9d1d9'}}}}});
</script>
</body>
</html>"""


def generate(results: list, target: str, report_dir: str = "/reports", detail: str = "brief") -> tuple:
    ts_label = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ts_file  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    total_vuln  = sum(r["vulnerable_count"] for r in results)
    total_tests = sum(r["total"] for r in results)
    score = max(0.0, (1 - total_vuln / total_tests) * 100) if total_tests else 100.0

    cat_labels  = [r["category"].split(" - ")[0] for r in results]
    vuln_counts = [r["vulnerable_count"] for r in results]

    os.makedirs(report_dir, exist_ok=True)
    slug = target.replace("http://", "").replace(":", "-").replace("/", "_")

    # Enrich results with compliance mapping
    for cat in results:
        compliance = _get_compliance(cat["category"])
        if compliance:
            cat["compliance"] = compliance

    suffix = f"_{detail}" if detail != "brief" else ""
    json_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.json")
    with open(json_path, "w") as f:
        json.dump({"target": target, "timestamp": ts_label,
                   "score": round(score, 1), "detail": detail, "results": results}, f, indent=2)

    html_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.html")
    html = Template(_TEMPLATE).render(
        target=target, timestamp=ts_label, categories=results,
        total_vuln=total_vuln, total_tests=total_tests, score=score,
        cat_labels=cat_labels, vuln_counts=vuln_counts,
        cve_db=CVE_DB,
        detail=detail,
    )
    with open(html_path, "w") as f:
        f.write(html)

    # SARIF export (always generated alongside JSON/HTML)
    sarif_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.sarif")
    with open(sarif_path, "w") as f:
        json.dump(generate_sarif(results, target), f, indent=2)

    return json_path, html_path, sarif_path
