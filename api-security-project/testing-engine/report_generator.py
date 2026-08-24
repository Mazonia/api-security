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
                "message": {"text": f"{t['test']}: {t.get('actual', t.get('detail', 'Vulnerability detected'))}"},
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Security Test Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg: #090d16;
  --surface: #111827;
  --surface2: #1f293d;
  --border: rgba(255,255,255,0.08);
  --border-glow: rgba(99,102,241,0.25);
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --emerald: #10b981;
  --emerald-dim: rgba(16,185,129,0.12);
  --indigo: #6366f1;
  --indigo-dim: rgba(99,102,241,0.12);
  --rose: #f43f5e;
  --rose-dim: rgba(244,63,94,0.12);
  --amber: #f59e0b;
  --amber-dim: rgba(245,158,11,0.12);
  --purple: #8b5cf6;
  --radius: 12px;
  --radius-sm: 6px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;padding-bottom:40px}
.header{
  background:linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #090d16 100%);
  padding:48px 24px;text-align:center;border-bottom:1px solid var(--border);
  box-shadow:0 10px 30px rgba(0,0,0,0.5);position:relative;overflow:hidden;
}
.header::before{
  content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;
  background:radial-gradient(circle, rgba(16,185,129,0.06) 0%, transparent 60%);
  pointer-events:none;
}
.header h1{
  color:#fff;font-size:2.5em;font-weight:800;letter-spacing:-0.02em;margin-bottom:8px;
  display:inline-flex;align-items:center;gap:12px;
}
.header p{color:var(--text-muted);font-size:0.95em;font-weight:500}
.header p span{color:var(--emerald);font-weight:600}
.detail-badge{
  background:var(--indigo-dim);color:var(--indigo);border:1px solid rgba(99,102,241,0.4);
  padding:4px 12px;border-radius:20px;font-size:0.45em;font-weight:700;
  vertical-align:middle;text-transform:uppercase;letter-spacing:0.08em;
}
.container{max-width:1240px;margin:0 auto;padding:36px 24px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:32px}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px 18px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,0.2);
  transition:transform 0.2s, border-color 0.2s;position:relative;overflow:hidden;
}
.card:hover{transform:translateY(-2px);border-color:var(--border-glow)}
.card::top-line{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.card .num{font-size:2.6em;font-weight:800;line-height:1}
.card .lbl{color:var(--text-muted);font-size:0.78em;font-weight:600;margin-top:8px;text-transform:uppercase;letter-spacing:0.06em}
.red{color:var(--rose)}.green{color:var(--emerald)}.indigo{color:var(--indigo)}.yellow{color:var(--amber)}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-bottom:36px}
.cbox{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px;box-shadow:0 4px 20px rgba(0,0,0,0.2);
}
.cbox h3{color:var(--text);font-weight:700;margin-bottom:18px;font-size:1.05em;display:flex;align-items:center;gap:8px}
.cbox h3::before{content:'';display:inline-block;width:4px;height:16px;background:var(--emerald);border-radius:2px}
.cat{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  margin-bottom:24px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.25);
  transition:border-color 0.2s;
}
.cat:hover{border-color:var(--border-glow)}
.cat-hdr{
  padding:20px 24px;border-bottom:1px solid var(--border);background:var(--surface2);
  display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;
}
.cat-hdr h2{font-size:1.15em;font-weight:700;color:#fff}
.badge{padding:4px 12px;border-radius:20px;font-size:0.78em;font-weight:700;letter-spacing:0.03em}
.bv{background:var(--rose-dim);color:var(--rose);border:1px solid rgba(244,63,94,0.4)}
.bs{background:var(--emerald-dim);color:var(--emerald);border:1px solid rgba(16,185,129,0.4)}
.sev-CRITICAL{background:rgba(244,63,94,0.2);color:#fb7185;border:1px solid var(--rose)}
.sev-HIGH{background:var(--rose-dim);color:var(--rose);border:1px solid rgba(244,63,94,0.5)}
.sev-MEDIUM{background:var(--amber-dim);color:var(--amber);border:1px solid rgba(245,158,11,0.5)}
.sev-LOW{background:var(--indigo-dim);color:var(--indigo);border:1px solid rgba(99,102,241,0.5)}
table{width:100%;border-collapse:collapse}
th{
  background:rgba(0,0,0,0.3);padding:12px 18px;text-align:left;
  font-size:0.76em;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:0.07em;
}
td{padding:13px 18px;border-top:1px solid var(--border);font-size:0.88em;word-break:break-word}
code{font-family:'Fira Code','SF Mono',monospace;background:rgba(0,0,0,0.4);color:#60a5fa;padding:3px 8px;border-radius:4px;font-size:0.86em}
.vY{color:var(--rose);font-weight:700}.vN{color:var(--emerald);font-weight:600}
.sC{color:var(--rose);font-weight:700}.sH{color:var(--amber);font-weight:600}.sM{color:var(--indigo)}.sL{color:var(--text-muted)}
.cve-panel{padding:22px 24px;border-top:1px solid var(--border);background:rgba(0,0,0,0.25)}
.cve-panel h4{color:var(--text-muted);font-size:0.78em;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:14px}
.cve-row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;align-items:center}
.cve-badge{
  background:var(--indigo-dim);border:1px solid rgba(99,102,241,0.3);border-radius:6px;
  padding:5px 12px;font-size:0.82em;font-family:'Fira Code',monospace;color:var(--indigo);
  text-decoration:none;transition:all 0.15s;
}
.cve-badge:hover{background:var(--indigo);color:#fff}
.owasp-link{font-size:0.84em;color:var(--emerald);text-decoration:none;margin-left:auto;font-weight:600}
.owasp-link:hover{text-decoration:underline}
.vuln-desc{font-size:0.9em;color:var(--text-muted);margin-bottom:16px;line-height:1.6}
.fixes h5{font-size:0.8em;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-muted);margin-bottom:10px}
.fixes ol{padding-left:20px}
.fixes li{font-size:0.88em;color:var(--text);line-height:1.7;padding:3px 0}
.fixes li code{color:var(--emerald)}
.no-cve{font-size:0.85em;color:var(--text-muted);padding:18px 24px}
.detail-section{padding:24px;border-top:2px solid var(--surface2);background:rgba(0,0,0,0.3)}
.impact-block{margin-bottom:20px}
.impact-block h4{color:var(--amber);font-size:0.82em;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.impact-block h4::before{content:'⚠️'}
.impact-block p{font-size:0.9em;color:var(--text);line-height:1.7}
.poc-block{margin-bottom:20px}
.poc-block h5{font-size:0.8em;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-muted);margin-bottom:10px}
.poc-block ol{padding-left:20px}
.poc-block li{font-size:0.88em;color:var(--text);line-height:1.7;padding:3px 0}
.code-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:12px}
.code-label{font-size:0.75em;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;padding:5px 12px;display:inline-block;border-radius:6px 6px 0 0}
.code-label.vuln-lbl{background:var(--rose-dim);color:var(--rose);border:1px solid rgba(244,63,94,0.3);border-bottom:none}
.code-label.fix-lbl{background:var(--emerald-dim);color:var(--emerald);border:1px solid rgba(16,185,129,0.3);border-bottom:none}
pre.code-pre{
  background:#050811;border:1px solid var(--border);border-radius:0 8px 8px 8px;
  padding:16px;font-size:0.84em;font-family:'Fira Code','SF Mono',monospace;color:#e2e8f0;
  overflow-x:auto;white-space:pre;margin:0;line-height:1.65;
}
.footer{text-align:center;padding:32px;color:var(--text-muted);font-size:0.84em;border-top:1px solid var(--border);margin-top:40px}
.footer span{color:var(--emerald);font-weight:600}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ API Security Test Report{% if detail == 'detailed' %}<span class="detail-badge">Detailed Analysis</span>{% endif %}</h1>
  <p>Target Endpoint: <span>{{ target }}</span> &nbsp;•&nbsp; {{ timestamp }} &nbsp;•&nbsp; OWASP API Top 10:2023 Standard</p>
</div>
<div class="container">
  <div class="cards">
    <div class="card"><div class="num red">{{ total_vuln }}</div><div class="lbl">Vulnerabilities Found</div></div>
    <div class="card"><div class="num indigo">{{ total_tests }}</div><div class="lbl">Total Tests Executed</div></div>
    <div class="card"><div class="num green">{{ total_tests - total_vuln }}</div><div class="lbl">Tests Passed</div></div>
    <div class="card"><div class="num yellow">{{ "%.0f"|format(score) }}%</div><div class="lbl">Security Score</div></div>
  </div>
  <div class="charts">
    <div class="cbox"><h3>Vulnerabilities by Category</h3><canvas id="barChart" height="220"></canvas></div>
    <div class="cbox"><h3>Overall Security Posture</h3><canvas id="pieChart" height="220"></canvas></div>
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
      <tr><th>Test Vector</th><th>Request Payload / Path</th><th>Expected Result</th><th>Actual Result</th><th>Severity</th><th>Status</th></tr>
      {% for t in cat.tests %}
      <tr>
        <td style="font-weight:600;color:var(--text)">{{ t.test }}</td>
        <td><code>{{ t.request }}</code></td>
        <td style="color:var(--text-muted)">{{ t.expected }}</td>
        <td>{{ t.actual }}</td>
        <td class="s{{ t.severity[0] }}">{{ t.severity }}</td>
        <td class="{% if t.vulnerable %}vY{% else %}vN{% endif %}">{{ "VULNERABLE" if t.vulnerable else "SECURE" }}</td>
      </tr>
      {% endfor %}
    </table>
    {% if cve %}
    <div class="cve-panel">
      <h4>CVE References &amp; Remediation Guidance</h4>
      <div class="cve-row">
        {% for cve_id in cve.cves %}
        <a class="cve-badge" href="https://nvd.nist.gov/vuln/detail/{{ cve_id }}" target="_blank" rel="noopener">{{ cve_id }}</a>
        {% endfor %}
        <a class="owasp-link" href="{{ cve.owasp_ref }}" target="_blank" rel="noopener">OWASP Documentation &rarr;</a>
      </div>
      <p class="vuln-desc">{{ cve.description }}</p>
      <div class="fixes">
        <h5>Recommended Fixes</h5>
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
        <h5>Proof of Concept — Attack Execution Steps</h5>
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
          <div class="code-label vuln-lbl">Vulnerable Code Implementation</div>
          <pre class="code-pre">{{ cve.code_before|e }}</pre>
        </div>
        <div class="code-pane">
          <div class="code-label fix-lbl">Hardened Code Remediation</div>
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
<div class="footer">MazAPI Security Scanner &nbsp;•&nbsp; <span>CY384 Cybersecurity Lab Work II</span> &nbsp;•&nbsp; University of Mines and Technology, Ghana</div>
<script>
const labels = {{ cat_labels|tojson }};
const vulns  = {{ vuln_counts|tojson }};
new Chart(document.getElementById('barChart'),{
  type:'bar',
  data:{
    labels,
    datasets:[{
      label:'Vulnerabilities',
      data:vulns,
      backgroundColor:'rgba(244,63,94,0.75)',
      borderColor:'#f43f5e',
      borderWidth:1,
      borderRadius:6
    }]
  },
  options:{
    plugins:{legend:{labels:{color:'#f3f4f6',font:{family:'Inter'}}}},
    scales:{
      x:{ticks:{color:'#9ca3af',font:{family:'Inter'}},grid:{color:'rgba(255,255,255,0.05)'}},
      y:{ticks:{color:'#9ca3af',stepSize:1,font:{family:'Inter'}},grid:{color:'rgba(255,255,255,0.05)'}}
    }
  }
});
new Chart(document.getElementById('pieChart'),{
  type:'doughnut',
  data:{
    labels:['Vulnerable','Secure'],
    datasets:[{
      data:[{{ total_vuln }},{{ total_tests - total_vuln }}],
      backgroundColor:['rgba(244,63,94,0.8)','rgba(16,185,129,0.8)'],
      borderColor:['#f43f5e','#10b981'],
      borderWidth:2
    }]
  },
  options:{
    plugins:{legend:{labels:{color:'#f3f4f6',font:{family:'Inter'}}}}
  }
});
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
    with open(json_path, "w", encoding="utf-8") as f:
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
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # SARIF export (always generated alongside JSON/HTML)
    sarif_path = os.path.join(report_dir, f"report_{slug}_{ts_file}{suffix}.sarif")
    with open(sarif_path, "w", encoding="utf-8") as f:
        json.dump(generate_sarif(results, target), f, indent=2)

    return json_path, html_path, sarif_path
