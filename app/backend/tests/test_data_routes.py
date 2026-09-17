"""Tests for read routes: hosts, ports, services, vulnerabilities, findings, reports."""

from test_scans import RESULTS_PAYLOAD


def _completed_scan(client, registered_agent, auth_headers):
    scan = client.post("/api/scans", json={
        "agent_id": registered_agent["agent_id"],
        "target": "192.168.1.0/24", "scan_type": "standard",
    }).json()
    client.post("/api/scans/claim", headers=auth_headers)
    client.post(f"/api/scans/{scan['id']}/results", json=RESULTS_PAYLOAD, headers=auth_headers)
    return scan


def test_hosts_route(client, registered_agent, auth_headers):
    scan = _completed_scan(client, registered_agent, auth_headers)
    resp = client.get(f"/api/hosts?scan_id={scan['id']}")
    assert resp.status_code == 200
    hosts = resp.json()
    assert {h["ip_address"] for h in hosts} == {"192.168.1.1", "192.168.1.10"}


def test_ports_route(client, registered_agent, auth_headers):
    scan = _completed_scan(client, registered_agent, auth_headers)
    hosts = client.get(f"/api/hosts?scan_id={scan['id']}").json()
    host_10 = next(h for h in hosts if h["ip_address"] == "192.168.1.10")
    resp = client.get(f"/api/ports?host_id={host_10['id']}")
    assert resp.status_code == 200
    ports = resp.json()
    assert sorted(p["port_number"] for p in ports) == [22, 80]


def test_services_route(client, registered_agent, auth_headers):
    scan = _completed_scan(client, registered_agent, auth_headers)
    hosts = client.get(f"/api/hosts?scan_id={scan['id']}").json()
    host_10 = next(h for h in hosts if h["ip_address"] == "192.168.1.10")
    ports = client.get(f"/api/ports?host_id={host_10['id']}").json()
    port_22 = next(p for p in ports if p["port_number"] == 22)
    resp = client.get(f"/api/services?port_id={port_22['id']}")
    assert resp.status_code == 200
    services = resp.json()
    assert services[0]["service_name"] == "ssh"
    assert services[0]["product"] == "OpenSSH"


def test_vulnerabilities_route(client, registered_agent, auth_headers):
    scan = _completed_scan(client, registered_agent, auth_headers)
    hosts = client.get(f"/api/hosts?scan_id={scan['id']}").json()
    host_10 = next(h for h in hosts if h["ip_address"] == "192.168.1.10")
    ports = client.get(f"/api/ports?host_id={host_10['id']}").json()
    port_22 = next(p for p in ports if p["port_number"] == 22)
    services = client.get(f"/api/services?port_id={port_22['id']}").json()
    resp = client.get(f"/api/vulnerabilities?service_id={services[0]['id']}")
    assert resp.status_code == 200
    vulns = resp.json()
    assert len(vulns) == 1
    assert vulns[0]["cve_id"] == "CVE-2024-6387"
    assert vulns[0]["severity"] == "critical"


def test_findings_route(client, registered_agent, auth_headers):
    scan = _completed_scan(client, registered_agent, auth_headers)
    resp = client.get(f"/api/findings?scan_id={scan['id']}")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2
    assert {f["severity"] for f in findings} == {"critical", "info"}

    crit = client.get(f"/api/findings?scan_id={scan['id']}&severity=critical").json()
    assert len(crit) == 1
    assert crit[0]["title"].startswith("CVE-2024-6387")


def test_report_generation_and_download(client, registered_agent, auth_headers):
    scan = _completed_scan(client, registered_agent, auth_headers)

    for rtype, media in (("html", "text/html"), ("json", "application/json"), ("csv", "text/csv")):
        gen = client.post(f"/api/reports/generate/{scan['id']}?report_type={rtype}")
        assert gen.status_code == 201, gen.text
        report = gen.json()
        assert report["report_type"] == rtype
        assert report["scan_id"] == scan["id"]

        dl = client.get(f"/api/reports/download/{report['id']}")
        assert dl.status_code == 200
        assert media in dl.headers["content-type"]
        assert len(dl.content) > 100

    html = client.get("/api/reports").json()
    assert len(html) >= 3


def test_report_rejects_incomplete_scan(client, registered_agent):
    scan = client.post("/api/scans", json={
        "agent_id": registered_agent["agent_id"],
        "target": "10.0.0.0/30", "scan_type": "quick",
    }).json()
    resp = client.post(f"/api/reports/generate/{scan['id']}")
    assert resp.status_code == 400
