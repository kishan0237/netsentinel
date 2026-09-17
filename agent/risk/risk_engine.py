"""Agent-side risk engine — mirrors the backend's rules."""

from typing import Any

CVSS_BANDS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]

SERVICE_RISK_NOTES: dict[str, tuple[str, str, str, str]] = {
    "telnet": ("Telnet service exposed", "Telnet transmits all data, including credentials, in cleartext.",
               "Disable Telnet and use SSH with key-based authentication.", "high"),
    "ftp": ("FTP service exposed", "FTP transmits credentials in cleartext and often allows anonymous access.",
            "Replace FTP with SFTP/FTPS or disable if unused.", "medium"),
    "http": ("Web server on plain HTTP", "HTTP traffic is unencrypted and can be intercepted or modified.",
             "Enable HTTPS with a valid certificate and redirect HTTP to HTTPS.", "low"),
    "vnc": ("VNC remote control exposed", "VNC commonly uses weak or no authentication.",
            "Restrict VNC to localhost/VPN or replace with RDP over VPN.", "high"),
    "rdp": ("RDP exposed on network", "Exposed RDP is a common ransomware entry point.",
            "Require VPN/NLA and strong credentials for RDP access.", "high"),
    "redis": ("Redis service detected", "Redis often runs unauthenticated and can be abused for RCE.",
              "Enable requirepass and bind to localhost.", "high"),
    "mongodb": ("MongoDB without binding restrictions", "MongoDB instances on LAN often run without authentication.",
                "Enable authentication and bind to a restricted interface.", "high"),
}


def cvss_to_severity(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    for floor, name in CVSS_BANDS:
        if s >= floor:
            return name
    return "info"


def generate_findings(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build findings from vulnerabilities + risky services across all hosts."""
    findings: list[dict[str, Any]] = []
    for host in hosts:
        ip = host.get("ip_address", "")
        for port in host.get("ports", []):
            port_no = port.get("port_number")
            for svc in port.get("services", []):
                for vuln in svc.get("vulnerabilities", []):
                    findings.append({
                        "title": f"{vuln.get('cve_id')} on {svc.get('product') or svc.get('service_name')} {ip}:{port_no}",
                        "description": vuln.get("description"),
                        "severity": vuln.get("severity") or cvss_to_severity(vuln.get("cvss_score")),
                        "recommendation": vuln.get("solution"),
                        "ip_address": ip,
                    })
                note = SERVICE_RISK_NOTES.get((svc.get("service_name") or "").lower())
                if note:
                    findings.append({
                        "title": f"{note[0]} ({ip}:{port_no})",
                        "description": note[1],
                        "severity": note[3],
                        "recommendation": note[2],
                        "ip_address": ip,
                    })
    return findings


def severity_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[(f.get("severity") or "info").lower()] = \
            counts.get((f.get("severity") or "info").lower(), 0) + 1
    return counts


def overall_risk_score(findings: list[dict[str, Any]]) -> float:
    weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
    if not findings:
        return 0.0
    raw = sum(weights.get((f.get("severity") or "info").lower(), 1.0) for f in findings) / len(findings)
    criticals = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
    return round(min(10.0, raw + min(1.0, criticals * 0.5)), 1)
