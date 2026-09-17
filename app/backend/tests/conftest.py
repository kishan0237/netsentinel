"""Shared pytest fixtures: SQLite test DB, TestClient, agent registration helper."""

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["DATABASE_URL"] = "sqlite:///./test_netsentinel.db"
os.environ["AUTO_CREATE_TABLES"] = "true"
# Disable rate limits for the test suite (tests share one client IP)
os.environ["RATE_LIMIT_GENERAL"] = "100000"
os.environ["RATE_LIMIT_SCAN_CREATE"] = "100000"
os.environ["RATE_LIMIT_REGISTER"] = "100000"
os.environ["RATE_LIMIT_HEARTBEAT"] = "100000"

from fastapi.testclient import TestClient  # noqa: E402

from app.backend.database.database import SessionLocal, init_db  # noqa: E402
from app.backend.database.models import Agent, Finding, Host, Port, Report, Scan, Service, Vulnerability  # noqa: E402
from app.backend.main import app  # noqa: E402
from app.backend.utils.secrets_management import _agent_tokens  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    init_db()
    yield
    for table in (Report, Finding, Vulnerability, Service, Port, Host, Scan, Agent):
        with SessionLocal() as db:
            db.query(table).delete()
            db.commit()


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def registered_agent(client):
    """Register an agent and return (agent_uuid, token, agent_id)."""
    resp = client.post("/api/agents/register", json={
        "agent_uuid": "NS-TEST-0001",
        "agent_name": "Test Agent",
        "hostname": "testbox",
        "platform": "linux",
        "agent_version": "1.0.0",
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return {
        "agent_uuid": body["agent"]["agent_uuid"],
        "agent_id": body["agent"]["id"],
        "token": body["agent_token"],
    }


@pytest.fixture
def auth_headers(registered_agent):
    return {
        "X-Agent-UUID": registered_agent["agent_uuid"],
        "Authorization": f"Bearer {registered_agent['token']}",
    }
