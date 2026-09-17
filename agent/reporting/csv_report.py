"""Local CSV report writer."""

import csv
from pathlib import Path


def write_csv_report(results: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    scan_id = (results.get("scan") or {}).get("id", "local")
    path = out_dir / f"netsentinel-{str(scan_id)[:8]}.csv"

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip_address", "hostname", "port", "protocol", "state",
                         "service", "product", "version", "cve_id", "severity"])
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
                            vuln.get("severity") or "",
                        ])
    return path
