"""Agent endpoint tests."""


def test_register_agent(client):
    resp = client.post("/api/agents/register", json={
        "agent_uuid": "NS-REG-AAAA",
        "agent_name": "Register Test",
        "platform": "windows",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["agent"]["agent_uuid"] == "NS-REG-AAAA"
    assert body["agent"]["status"] == "online"
    assert len(body["agent_token"]) >= 32


def test_register_agent_idempotent(client, registered_agent):
    resp = client.post("/api/agents/register", json={
        "agent_uuid": "NS-TEST-0001",
        "agent_name": "Renamed Agent",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["agent"]["id"] == registered_agent["agent_id"]
    assert body["agent"]["agent_name"] == "Renamed Agent"
    assert body["agent_token"] != registered_agent["token"]  # re-issued


def test_heartbeat_requires_auth(client):
    resp = client.post("/api/agents/heartbeat", json={})
    assert resp.status_code == 401


def test_heartbeat_bad_token(client):
    resp = client.post(
        "/api/agents/heartbeat",
        json={},
        headers={"X-Agent-UUID": "NS-TEST-0001", "Authorization": "Bearer wrong"},
    )
    assert resp.status_code == 401


def test_heartbeat_ok(client, auth_headers):
    resp = client.post("/api/agents/heartbeat", json={"agent_version": "1.0.1"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "online"
    assert resp.json()["agent_version"] == "1.0.1"


def test_list_agents(client, registered_agent):
    resp = client.get("/api/agents")
    assert resp.status_code == 200
    uuids = [a["agent_uuid"] for a in resp.json()]
    assert registered_agent["agent_uuid"] in uuids


def test_get_agent_detail(client, registered_agent):
    resp = client.get(f"/api/agents/{registered_agent['agent_uuid']}")
    assert resp.status_code == 200
    assert resp.json()["agent_uuid"] == registered_agent["agent_uuid"]


def test_get_agent_404(client):
    assert client.get("/api/agents/NS-NOPE-0000").status_code == 404


def test_delete_agent_requires_admin_key(client, registered_agent):
    resp = client.delete(f"/api/agents/{registered_agent['agent_uuid']}")
    assert resp.status_code == 403
