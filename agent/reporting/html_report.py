"""Local HTML report writer (standalone: agent has no backend access needed)."""

import html
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_html_report(results: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    scan = results.get("scan", {})
    scan_id = scan.get("id", "local")
    path = out_dir / f"netsentinel-{str(scan_id)[:8]}.html"

    esc = html.escape
    findings = sorted(
        results.get("findings", []),
        key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 5),
    )
    rows = []
    for host in results.get("hosts", []):
        for port in host.get("ports", []):
            svc_names = ", ".join(filter(None, [
                s.get("service_name") for s in port.get("services", [])
            ])) or "—"
            vulns = sum(len(s.get("vulnerabilities", [])) for s in port.get("services", []))
            rows.append(
                f"<tr><td>{esc(host.get('ip_address', ''))}</td>"
                f"<td>{port.get('port_number', '')}/{esc(port.get('protocol', ''))}</td>"
                f"<td>{esc(svc_names)}</td><td>{vulns}</td></tr>"
            )

    cards = "".join(
        f"<div class='finding {esc((f.get('severity') or 'info').lower())}'>"
        f"<span class='badge'>{esc((f.get('severity') or 'info').upper())}</span> "
        f"<strong>{esc(f.get('title', ''))}</strong>"
        f"<p>{esc(f.get('description') or '')}</p></div>"
        for f in findings
    )

    path.write_text(f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>NetSentinel Report</title><style>
body{{font-family:system-ui;max-width:900px;margin:2rem auto;color:#e5e7eb;background:#0b0f19}}
h1{{color:#7c8cff}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #26304a;padding:.4rem .6rem;text-align:left}}
.finding{{border:1px solid #26304a;border-radius:8px;padding:.7rem;margin:.5rem 0}}
.finding.critical{{border-color:#ef4444}}.finding.high{{border-color:#f97316}}
.finding.medium{{border-color:#eab308}}.finding.low{{border-color:#38bdf8}}
.badge{{font-size:.7rem;background:#1f2937;padding:.1rem .5rem;border-radius:999px}}
</style></head><body>
<h1>NetSentinel Scan Report</h1>
<p>Target: {esc(scan.get('target', ''))} · Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</p>
<h2>Findings ({len(findings)})</h2>{cards or '<p>No findings.</p>'}
<h2>Hosts ({len(results.get('hosts', []))})</h2>
<table><tr><th>IP</th><th>Port</th><th>Service</th><th>Vulns</th></tr>{''.join(rows)}</table>
</body></html>""")
    return path
