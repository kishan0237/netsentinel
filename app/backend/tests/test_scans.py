"""Scan lifecycle tests: create -> claim -> progress -> results -> stats."""

RESULTS_PAYLOAD = {
    "hosts": [
        {
            "ip_address": "192.168.1.10",
            "hostname": "router.local",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "status": "up",
            "os_estimate": "Linux 5.x",
            "ports": [
                {
                    "port_number": 22, "protocol": "tcp", "state": "open",
                    "services": [{
                        "service_name": "ssh", "product": "OpenSSH", "version": "8.2",
                        "vulnerabilities": [
                            {"cve_id": "CVE-2024-6387", "severity": "critical",
                             "cvss_score": 8.1, "confidence": "medium",
                             "description": "regreSSHion RCE", "solution": "Upgrade to 9.8p1"},
                        ],
                    }],
                },
                {
                    "port_number": 80, "protocol": "tcp", "state": "open",
                    "services": [{
                        "service_name": "http", "product": "nginx", "version": "1.18.0",
                        "vulnerabilities": [],
                    }],
                },
            ],
        },
        {"ip_address": "192.168.1.1", "status": "up", "ports": []},
    ],
    "findings": [
        {"title": "CVE-2024-6387 on OpenSSH 192.168.1.10:22",
         "description": "regreSSHion", "severity": "critical",
         "recommendation": "Upgrade OpenSSH", "ip_address": "192.168.1.10"},
        {"title": "SSH service exposed", "severity": "info",
         "ip_address": "192.168.1.10"},
    ],
}


def _create_scan(client, agent_id, target="192.168.1.0/24", scan_type="standard", ports=None):
    resp = client.post("/api/scans", json={
        "agent_id": agent_id, "target": target, "scan_type": scan_type, "ports": ports,
    })
    return resp


def test_create_scan(client, registered_agent):
    resp = _create_scan(client, registered_agent["agent_id"])
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["status"] == "pending"
    assert scan["progress"] == 0
    assert scan["agent_id"] == registered_agent["agent_id"]


def test_create_scan_rejects_injection(client, registered_agent):
    resp = _create_scan(client, registered_agent["agent_id"], target="192.168.1.1; rm -rf /")
    assert resp.status_code == 422


def test_create_scan_rejects_bad_cidr(client, registered_agent):
    resp = _create_scan(client, registered_agent["agent_id"], target="999.999.1.0/24")
    assert resp.status_code == 422


def test_create_scan_rejects_unknown_agent(client):
    resp = client.post("/api/scans", json={
        "agent_id": "00000000-0000-0000-0000-000000000000",
        "target": "192.168.1.0/30", "scan_type": "quick",
    })
    assert resp.status_code == 422


def test_custom_scan_port_validation(client, registered_agent):
    ok = _create_scan(client, registered_agent["agent_id"], scan_type="custom", ports="22,80,443")
    assert ok.status_code == 201
    bad = _create_scan(client, registered_agent["agent_id"], scan_type="custom", ports="22;80")
    assert bad.status_code == 422


def test_full_scan_lifecycle(client, registered_agent, auth_headers):
    scan = _create_scan(client, registered_agent["agent_id"]).json()

    # Agent claims
    claimed = client.post("/api/scans/claim", headers=auth_headers)
    assert claimed.status_code == 200
    ids = [s["id"] for s in claimed.json()]
    assert scan["id"] in ids
    assert next(s for s in claimed.json() if s["id"] == scan["id"])["status"] == "running"

    # Progress update
    prog = client.post(f"/api/scans/{scan['id']}/progress",
                       json={"progress": 45, "current_stage": "service_detection"},
                       headers=auth_headers)
    assert prog.status_code == 200
    assert prog.json()["progress"] == 45
    assert prog.json()["current_stage"] == "service_detection"

    # Progress from wrong agent rejected
    rogue = client.post(f"/api/scans/{scan['id']}/progress",
                        json={"progress": 90},
                        headers={"X-Agent-UUID": "NS-REG-AAAA", "Authorization": "Bearer x"})
    assert rogue.status_code in (401, 403)

    # Submit results
    res = client.post(f"/api/scans/{scan['id']}/results", json=RESULTS_PAYLOAD, headers=auth_headers)
    assert res.status_code == 201, res.text
    counts = res.json()["counts"]
    assert counts["hosts"] == 2
    assert counts["ports"] == 2
    assert counts["services"] == 2
    assert counts["vulnerabilities"] == 1
    assert counts["findings"] == 2

    # Scan completed
    detail = client.get(f"/api/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["progress"] == 100


def test_claim_requires_auth(client):
    assert client.post("/api/scans/claim").status_code == 401


def test_get_scan_results(client, registered_agent, auth_headers):
    scan = _create_scan(client, registered_agent["agent_id"]).json()
    client.post("/api/scans/claim", headers=auth_headers)
    client.post(f"/api/scans/{scan['id']}/results", json=RESULTS_PAYLOAD, headers=auth_headers)

    results = client.get(f"/api/scans/{scan['id']}/results").json()
    assert results["scan"]["id"] == scan["id"]
    assert len(results["hosts"]) == 2
    host = next(h for h in results["hosts"] if h["ip_address"] == "192.168.1.10")
    assert host["ports"][0]["port_number"] == 22
    assert host["ports"][0]["services"][0]["service_name"] == "ssh"
    assert host["ports"][0]["services"][0]["vulnerabilities"][0]["cve_id"] == "CVE-2024-6387"
    assert len(results["findings"]) == 2


def test_scan_stats(client, registered_agent, auth_headers):
    scan = _create_scan(client, registered_agent["agent_id"]).json()
    client.post("/api/scans/claim", headers=auth_headers)
    client.post(f"/api/scans/{scan['id']}/results", json=RESULTS_PAYLOAD, headers=auth_headers)

    stats = client.get(f"/api/scans/{scan['id']}/stats").json()
    assert stats["hosts"] == 2
    assert stats["open_ports"] == 2
    assert stats["services"] == 2
    assert stats["vulnerabilities"] == 1
    assert stats["findings"] == 2
    assert stats["severity_counts"]["critical"] == 1


def test_results_wrong_agent_rejected(client, registered_agent):
    scan = _create_scan(client, registered_agent["agent_id"]).json()
    resp = client.post(f"/api/scans/{scan['id']}/results", json=RESULTS_PAYLOAD,
                       headers={"X-Agent-UUID": "NS-REG-AAAA", "Authorization": "Bearer x"})
    assert resp.status_code in (401, 403)


def test_cancel_scan(client, registered_agent):
    scan = _create_scan(client, registered_agent["agent_id"]).json()
    resp = client.post(f"/api/scans/{scan['id']}/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


def test_fail_scan(client, registered_agent, auth_headers):
    scan = _create_scan(client, registered_agent["agent_id"]).json()
    client.post("/api/scans/claim", headers=auth_headers)
    resp = client.post(f"/api/scans/{scan['id']}/fail",
                       json={"error": "nmap not installed"}, headers=auth_headers)
    assert resp.status_code == 200
    detail = client.get(f"/api/scans/{scan['id']}").json()
    assert detail["status"] == "failed"
    assert "nmap" in detail["error"]


def test_results_with_binary_banner_sql_safe(client, registered_agent, auth_headers):
    """Regression: real LAN devices answer with binary banners (e.g. a MySQL
    handshake full of NUL bytes). PostgreSQL rejects NULs and psycopg rejects
    lone surrogates, so submission used to 500. The server must sanitize and
    still persist the useful part of the banner."""
    poison = "J\x00\x00\x00\n8.0.46\x00\x14\x00\x00\x00N9e\tfx\x7f/\x00\x02\x15"
    payload = {
        "hosts": [{
            "ip_address": "192.168.29.34", "status": "up",
            "ports": [{
                "port_number": 3306, "protocol": "tcp", "state": "open",
                "services": [{
                    "service_name": "mysql", "product": "MySQL", "version": "8.0.46",
                    "banner": poison, "vulnerabilities": [],
                }],
            }],
        }],
        "findings": [],
    }
    scan = _create_scan(client, registered_agent["agent_id"],
                        target="192.168.29.34", scan_type="quick").json()
    client.post("/api/scans/claim", headers=auth_headers)
    resp = client.post(f"/api/scans/{scan['id']}/results", json=payload, headers=auth_headers)
    assert resp.status_code == 201, resp.text

    stored = client.get(f"/api/scans/{scan['id']}/results").json()
    assert stored["scan"]["status"] == "completed"

    # Banner isn't exposed in the API schema; verify the stored (sanitized) value
    from app.backend.database.database import SessionLocal
    from app.backend.database.models import Service
    with SessionLocal() as db:
        banner = db.query(Service).filter(Service.service_name == "mysql").first().banner
    assert banner, "sanitized banner should not be empty"
    assert "8.0.46" in banner, "useful banner content must survive sanitization"
    for ch in banner:
        assert ord(ch) >= 32 or ch in "\t\n\r", f"DB-unsafe char persisted: {ch!r}"


def test_list_scans(client, registered_agent):
    _create_scan(client, registered_agent["agent_id"])
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
