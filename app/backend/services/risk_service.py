"""Risk engine: converts scan results + vulnerabilities into prioritized findings."""

from typing import Any

CVSS_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]

# Services that should never be exposed / are inherently risky when detected
SERVICE_RISK_NOTES: dict[str, tuple[str, str, str]] = {
    # service_name_lower: (title, description, recommendation, severity)
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
    "mongodb": ("MongoDB without binding restrictions", "MongoDB instances on LAN often run without authentication.",
                "Enable authentication and bind to localhost or a restricted interface.", "high"),
    "redis": ("Redis service detected", "Redis often runs unauthenticated and can be abused for RCE.",
              "Enable requirepass and bind to localhost.", "high"),
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


def service_findings(host_ip: str, port_number: int, service: dict[str, Any],
                     vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate findings for one service: CVE-driven + policy-driven."""
    findings: list[dict[str, Any]] = []
    service_name = (service.get("service_name") or "").lower()
    product = service.get("product") or ""
    version = service.get("version") or ""

    for vuln in vulnerabilities:
        title = f"{vuln.get('cve_id')} on {product or service_name} {host_ip}:{port_number}"
        desc = vuln.get("description") or "Known vulnerability matched for this service."
        findings.append({
            "title": title,
            "description": desc,
            "severity": vuln.get("severity") or cvss_to_severity(vuln.get("cvss_score")),
            "recommendation": vuln.get("solution"),
            "ip_address": host_ip,
        })

    note = SERVICE_RISK_NOTES.get(service_name)
    if note:
        findings.append({
            "title": f"{note[0]} ({host_ip}:{port_number})",
            "description": note[1],
            "severity": note[3],
            "recommendation": note[2],
            "ip_address": host_ip,
        })

    return findings


def summarize_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def overall_risk_score(findings: list[dict[str, Any]]) -> float:
    """0-10 weighted risk score from finding severities."""
    weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
    if not findings:
        return 0.0
    total = sum(weights.get((f.get("severity") or "info").lower(), 1.0) for f in findings)
    raw = total / len(findings)
    # Scale up if there are critical items
    criticals = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
    bonus = min(1.0, criticals * 0.5)
    return round(min(10.0, raw + bonus), 1)
