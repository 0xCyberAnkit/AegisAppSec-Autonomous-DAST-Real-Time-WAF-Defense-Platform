import time
from typing import Dict, Any, List
from jinja2 import Template

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AegisAppSec - Executive Security Audit Report</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-card: #111827;
            --border-color: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-cyan: #06b6d4;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #3b82f6;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 40px;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        .header {
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .brand {
            font-size: 24px;
            font-weight: 800;
            color: var(--accent-cyan);
            letter-spacing: 1px;
        }
        .meta-box {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 30px 0;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        .stat-val {
            font-size: 28px;
            font-weight: 700;
            margin-top: 5px;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid var(--crit); }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
        .badge-medium { background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid var(--med); }
        .badge-low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
        .finding-item {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 15px;
        }
        pre {
            background: #000;
            color: #10b981;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: Consolas, monospace;
            font-size: 13px;
        }
        .code-title {
            color: var(--accent-cyan);
            font-size: 12px;
            font-weight: bold;
            margin-top: 10px;
        }
        .print-btn {
            background: var(--accent-cyan);
            color: #000;
            border: none;
            padding: 10px 20px;
            font-weight: bold;
            border-radius: 6px;
            cursor: pointer;
        }
        @media print {
            .print-btn { display: none; }
            body { background: #fff; color: #000; }
            .card, .finding-item { background: #fff; border: 1px solid #ccc; color: #000; }
            pre { background: #f3f4f6; color: #111; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">AEGIS // APPSEC INTELLIGENCE</div>
                <div style="color: var(--text-secondary); margin-top: 5px;">Dynamic Application Security Testing (DAST) Audit Report</div>
            </div>
            <div>
                <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
            </div>
        </div>

        <div class="meta-box">
            <div class="card">
                <div style="color: var(--text-secondary); font-size: 12px;">TARGET HOST</div>
                <div class="stat-val" style="font-size: 16px; word-break: break-all;">{{ summary.target_url }}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-secondary); font-size: 12px;">SCAN ID</div>
                <div class="stat-val" style="font-size: 16px;">{{ summary.scan_id }}</div>
            </div>
            <div class="card">
                <div style="color: var(--text-secondary); font-size: 12px;">SCAN DURATION</div>
                <div class="stat-val">{{ summary.duration_seconds }}s</div>
            </div>
            <div class="card">
                <div style="color: var(--text-secondary); font-size: 12px;">VULNERABILITIES FOUND</div>
                <div class="stat-val" style="color: var(--crit);">{{ summary.findings_count }}</div>
            </div>
        </div>

        <h2>Detailed Vulnerability Findings (OWASP Top 10)</h2>
        {% for f in summary.findings %}
        <div class="finding-item">
            <div class="finding-header">
                <div>
                    <span class="badge badge-{{ f.severity.lower() }}">{{ f.severity }}</span>
                    <strong style="font-size: 18px; margin-left: 12px;">{{ f.title }}</strong>
                </div>
                <div>
                    <span style="color: var(--accent-cyan); font-weight: bold;">CVSS {{ f.cvss_score }}</span>
                    <span style="color: var(--text-secondary); font-size: 12px; margin-left: 8px;">{{ f.cwe_id }}</span>
                </div>
            </div>

            <p><strong>Endpoint:</strong> <code>{{ f.method }} {{ f.endpoint }}</code></p>
            {% if f.parameter %}<p><strong>Vulnerable Parameter:</strong> <code>{{ f.parameter }}</code></p>{% endif %}
            <p><strong>CVSS Vector:</strong> <code>{{ f.cvss_vector }}</code></p>
            <p><strong>Evidence:</strong> {{ f.evidence }}</p>

            <div class="code-title">Proof-of-Concept Exploit (cURL):</div>
            <pre>{{ f.curl_command }}</pre>

            <div class="code-title">Remediation Guidance:</div>
            <p style="color: #a7f3d0; background: rgba(16, 185, 129, 0.1); padding: 10px; border-radius: 6px; border-left: 3px solid #10b981;">
                {{ f.remediation_summary }}
            </p>
        </div>
        {% endfor %}
    </div>
</body>
</html>
"""

class ReportGenerator:
    """Generates JSON and HTML Executive Audit Reports."""

    @staticmethod
    def generate_json(summary_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "generator": "AegisAppSec Enterprise DAST v1.0",
                "framework_compliance": ["OWASP Top 10 (2021)", "CWE Top 25", "CVSS v3.1"]
            },
            "scan_summary": summary_data
        }

    @staticmethod
    def generate_html(summary_data: Dict[str, Any]) -> str:
        template = Template(HTML_REPORT_TEMPLATE)
        return template.render(summary=summary_data)

    @staticmethod
    def generate_markdown(summary_data: Dict[str, Any]) -> str:
        md = []
        md.append("# AegisAppSec // Executive Security Audit Report\n")
        md.append(f"**Target URL:** `{summary_data.get('target_url', 'N/A')}`  ")
        md.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  ")
        md.append(f"**Total Vulnerabilities:** {summary_data.get('findings_count', 0)}  ")
        md.append(f"**Critical:** {summary_data.get('critical_count', 0)} | **High:** {summary_data.get('high_count', 0)} | **Medium:** {summary_data.get('medium_count', 0)} | **Low:** {summary_data.get('low_count', 0)}\n")
        md.append("## Vulnerability Findings\n")
        for f in summary_data.get("findings", []):
            md.append(f"### [{f.get('severity')}] {f.get('title')}")
            md.append(f"- **Endpoint:** `{f.get('method', 'GET')} {f.get('endpoint')}`")
            if f.get('parameter'):
                md.append(f"- **Parameter:** `{f.get('parameter')}`")
            md.append(f"- **CVSS v3.1:** {f.get('cvss_score')} (`{f.get('cvss_vector', 'N/A')}`)")
            md.append(f"- **CWE:** {f.get('cwe_id')}")
            md.append(f"- **Evidence:** {f.get('evidence')}\n")
            md.append("#### Reproduction cURL")
            md.append(f"```bash\n{f.get('curl_command')}\n```\n")
            md.append("#### Remediation")
            md.append(f"> {f.get('remediation_summary')}\n\n---\n")
        return "\n".join(md)

    @staticmethod
    def generate_csv(summary_data: Dict[str, Any]) -> str:
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Title", "Severity", "CVSS_Score", "CWE_ID", "Endpoint", "Parameter", "Evidence", "Remediation"])
        for i, f in enumerate(summary_data.get("findings", []), 1):
            writer.writerow([
                f"FIND-{i:03d}",
                f.get("title", ""),
                f.get("severity", ""),
                f.get("cvss_score", ""),
                f.get("cwe_id", ""),
                f.get("endpoint", ""),
                f.get("parameter", ""),
                f.get("evidence", ""),
                f.get("remediation_summary", "")
            ])
        return output.getvalue()

    @staticmethod
    def generate_sarif(summary_data: Dict[str, Any]) -> Dict[str, Any]:
        rules = []
        results = []
        rule_indices = {}

        for f in summary_data.get("findings", []):
            cwe = f.get("cwe_id", "CWE-Unknown")
            if cwe not in rule_indices:
                rule_indices[cwe] = len(rules)
                rules.append({
                    "id": cwe,
                    "name": f.get("vuln_type", "vulnerability").replace("_", " ").title(),
                    "shortDescription": {"text": f.get("title", "")},
                    "fullDescription": {"text": f.get("remediation_summary", f.get("title", ""))},
                    "defaultConfiguration": {
                        "level": "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning"
                    },
                    "properties": {
                        "cvss": f.get("cvss_score", 0.0),
                        "cvssVector": f.get("cvss_vector", "")
                    }
                })

            results.append({
                "ruleId": cwe,
                "ruleIndex": rule_indices[cwe],
                "level": "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                "message": {
                    "text": f"{f.get('title')}: {f.get('evidence', '')}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("endpoint", "/api/shop")
                        }
                    }
                }]
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AegisAppSec Autonomous DAST",
                        "version": "2.6.0",
                        "informationUri": "https://aegisappsec.io",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }
