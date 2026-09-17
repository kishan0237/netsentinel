#!/usr/bin/env python3
"""End-to-end smoke test against a running NetSentinel API.

Simulates the full agent lifecycle in one process:
register -> heartbeat -> create scan -> claim -> run pipeline (localhost)
-> submit results -> verify results/report.

Usage:
    python scripts/smoke_test.py [API_URL]     # default http://localhost:8000
"""

import sys
import time
import uuid

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")

sys.path.insert(0, ".")  # project root, so the agent package is importable


def main() -> int:
    # 1. Health
    r = requests.get(f"{BASE}/api/health", timeout=10)
    assert r.status_code == 200 and r.json()["status"] == "ok", r.text
    print("[1/7] health OK")

    # 2. Register agent
    agent_uuid = f"NS-SMOKE-{uuid.uuid4().hex[:4].upper()}"
    r = requests.post(f"{BASE}/api/agents/register", json={
        "agent_uuid": agent_uuid, "agent_name": "Smoke Agent",
        "hostname": "smoketest", "platform": "ci", "agent_version": "1.0.0",
    }, timeout=10)
    assert r.status_code == 201, r.text
    token = r.json()["agent_token"]
    agent_id = r.json()["agent"]["id"]
    headers = {"X-Agent-UUID": agent_uuid, "Authorization": f"Bearer {token}"}
    print(f"[2/7] registered {agent_uuid}")

    # 3. Heartbeat
    r = requests.post(f"{BASE}/api/agents/heartbeat", json={}, headers=headers, timeout=10)
    assert r.status_code == 200 and r.json()["status"] == "online", r.text
    print("[3/7] heartbeat OK")

    # 4. Create scan (single-host quick scan of loopback)
    r = requests.post(f"{BASE}/api/scans", json={
        "agent_id": agent_id, "target": "127.0.0.1", "scan_type": "quick",
    }, timeout=10)
    assert r.status_code == 201, r.text
    scan = r.json()
    print(f"[4/7] scan created {scan['id'][:8]} (pending)")

    # 5. Claim as agent
    r = requests.post(f"{BASE}/api/scans/claim", json={}, headers=headers, timeout=10)
    assert r.status_code == 200, r.text
    assert any(s["id"] == scan["id"] for s in r.json()), "scan not claimed"
    print("[5/7] scan claimed (running)")

    # 6. Run the real local pipeline on loopback
    from agent.scanner.pipeline import run_scan

    def progress(pct, stage):
        requests.post(f"{BASE}/api/scans/{scan['id']}/progress",
                      json={"progress": pct, "current_stage": stage},
                      headers=headers, timeout=10)

    results = run_scan("127.0.0.1", "quick", on_progress=progress)
    r = requests.post(f"{BASE}/api/scans/{scan['id']}/results",
                      json=results, headers=headers, timeout=30)
    assert r.status_code == 201, r.text
    counts = r.json()["counts"]
    print(f"[6/7] pipeline ran locally: {counts}")

    # 7. Verify results + report download
    r = requests.get(f"{BASE}/api/scans/{scan['id']}/results", timeout=10)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scan"]["status"] == "completed"
    assert body["scan"]["progress"] == 100
    r = requests.get(f"{BASE}/api/scans/{scan['id']}/report?format=html", timeout=10)
    assert r.status_code == 200 and "NetSentinel" in r.text
    print("[7/7] results + report verified")

    print(f"\nSMOKE TEST PASSED — full flow works on {BASE}")
    print(f"View in dashboard: scan {scan['id']}")
    return 0


if __name__ == "__main__":
    time.sleep(0)  # noqa: keep imports tidy
    sys.exit(main())
