"""Report generation service: HTML, JSON and CSV exports for a completed scan."""

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_json_report(results: dict[str, Any]) -> str:
    return json.dumps(results, indent=2, default=str)


def generate_csv_report(results: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip_address", "hostname", "port", "protocol", "state",
                     "service", "product", "version", "cve_id", "cvss_score", "severity"])
    for host in results.get("hosts", []):
        for port in host.get("ports", []):
            services = port.get("services") or [{}]
            for svc in services:
                vulns = svc.get("vulnerabilities") or [{}]
                for vuln in vulns:
                    writer.writerow([
                        host.get("ip_address"), host.get("hostname") or "",
                        port.get("port_number"), port.get("protocol"), port.get("state"),
                        svc.get("service_name", ""), svc.get("product") or "",
                        svc.get("version") or "", vuln.get("cve_id") or "",
                        vuln.get("cvss_score") if vuln.get("cvss_score") is not None else "",
                        vuln.get("severity") or "",
                    ])
    return buf.getvalue()


def generate_html_report(results: dict[str, Any]) -> str:
    scan = results.get("scan", {})
    hosts = results.get("hosts", [])
    findings = sorted(
        results.get("findings", []),
        key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 5),
    )

    esc = html.escape
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for host in hosts:
        for port in host.get("ports", []):
            svc_names = ", ".join(
                filter(None, [s.get("service_name") for s in port.get("services", [])])
            ) or "—"
            vuln_count = sum(len(s.get("vulnerabilities", [])) for s in port.get("services", []))
            rows.append(
                f"<tr><td>{esc(host.get('ip_address', ''))}</td>"
                f"<td>{esc(host.get('hostname') or '')}</td>"
                f"<td>{port.get('port_number', '')}/{esc(port.get('protocol', ''))}</td>"
                f"<td>{esc(svc_names)}</td>"
                f"<td>{vuln_count}</td></tr>"
            )

    finding_cards = []
    for f in findings:
        finding_cards.append(
            f"<div class='finding {esc((f.get('severity') or 'info').lower())}'>"
            f"<span class='badge'>{esc((f.get('severity') or 'info').upper())}</span>"
            f"<h3>{esc(f.get('title', ''))}</h3>"
            f"<p>{esc(f.get('description') or '')}</p>"
            f"<p class='fix'><strong>Fix:</strong> {esc(f.get('recommendation') or '—')}</p>"
            f"</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetSentinel Report — {esc(scan.get('target', 'scan'))}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #e5e7eb; background: #0b0f19; }}
  h1 {{ color: #7c8cff; }} h2 {{ margin-top: 2rem; border-bottom: 1px solid #26304a; padding-bottom: .3rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
  th, td {{ border: 1px solid #26304a; padding: .45rem .6rem; text-align: left; }}
  th {{ background: #131a2c; }}
  .meta {{ color: #94a3b8; font-size: .9rem; }}
  .finding {{ border: 1px solid #26304a; border-radius: 8px; padding: .8rem 1rem; margin: .6rem 0; }}
  .finding.critical {{ border-color: #ef4444; }} .finding.high {{ border-color: #f97316; }}
  .finding.medium {{ border-color: #eab308; }} .finding.low {{ border-color: #38bdf8; }}
  .badge {{ font-size: .7rem; padding: .15rem .5rem; border-radius: 999px; background: #1f2937; letter-spacing: .05em; }}
  .fix {{ color: #86efac; }}
</style>
</head>
<body>
<h1>NetSentinel Scan Report</h1>
<p class="meta">Target: <strong>{esc(scan.get('target', ''))}</strong> ·
Type: {esc(scan.get('scan_type', ''))} ·
Status: {esc(scan.get('status', ''))} ·
Generated: {generated}</p>

<h2>Findings ({len(findings)})</h2>
{''.join(finding_cards) if finding_cards else '<p>No findings.</p>'}

<h2>Hosts &amp; Services ({len(hosts)} hosts)</h2>
<table>
<tr><th>IP</th><th>Hostname</th><th>Port</th><th>Service</th><th>Vulns</th></tr>
{''.join(rows)}
</table>
</body>
</html>"""


REPORT_GENERATORS = {
    "html": generate_html_report,
    "json": generate_json_report,
    "csv": generate_csv_report,
}


def generate_report(report_type: str, results: dict[str, Any]) -> str:
    gen = REPORT_GENERATORS.get(report_type)
    if not gen:
        raise ValueError(f"Unsupported report type: {report_type}")
    return gen(results)
