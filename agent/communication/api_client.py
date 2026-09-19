"""Agent REST client for the NetSentinel API (Render).

All agent->server communication is plain HTTPS (configurable http:// for dev).
Requests carry X-Agent-UUID + Authorization: Bearer <agent_token>.
"""

import os
from typing import Any, Optional

import requests

DEFAULT_REMOTE = "https://netsentinel-api.onrender.com"
TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BACKOFF = 2.0  # seconds, exponential


def default_api_url() -> str:
    return os.environ.get("NETSENTINEL_API_URL", DEFAULT_REMOTE).rstrip("/")


def _headers(agent_uuid: str, token: str) -> dict:
    headers = {"X-Agent-UUID": agent_uuid, "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _post(url: str, payload: dict, agent_uuid: str = "", token: str = "",
          retries: int = MAX_RETRIES) -> tuple[bool, Optional[dict | int]]:
    """POST with retries on network errors AND server errors (5xx).

    Client errors (4xx) are returned immediately — retrying cannot help.
    Returns (ok, data_or_status).
    """
    last_exc: Exception | None = None
    last_status: int | None = None
    for attempt in range(retries):
        try:
            r = requests.post(url, json=payload, headers=_headers(agent_uuid, token),
                              timeout=TIMEOUT)
            if r.status_code < 400:
                return True, (r.json() if r.content else None)
            if r.status_code >= 500:
                last_status = r.status_code  # server error: worth retrying
            else:
                return False, r.status_code
        except requests.RequestException as e:
            last_exc = e
        if attempt < retries - 1:
            import time
            time.sleep(RETRY_BACKOFF ** attempt)
    return False, last_status if last_status is not None else str(last_exc)


def _get(url: str, agent_uuid: str = "", token: str = "") -> tuple[bool, Optional[dict | int]]:
    try:
        r = requests.get(url, headers=_headers(agent_uuid, token), timeout=TIMEOUT)
        if r.status_code < 400:
            return True, r.json()
        return False, r.status_code
    except requests.RequestException as e:
        return False, str(e)


# ---------------------------------------------------------------------- API --
def register(api_url: str, agent_uuid: str, hostname: str, platform_name: str,
             version: str) -> tuple[bool, Optional[dict]]:
    return _post(
        f"{api_url}/api/agents/register",
        {
            "agent_uuid": agent_uuid,
            "agent_name": f"NetSentinel Agent ({hostname})",
            "hostname": hostname,
            "platform": platform_name,
            "agent_version": version,
        },
    )


def heartbeat(api_url: str, agent_uuid: str, token: str, version: str) -> int:
    """Send a heartbeat; return the HTTP status (0 on network error)."""
    ok, data = _post(f"{api_url}/api/agents/heartbeat",
                     {"agent_version": version}, agent_uuid, token, retries=1)
    if ok:
        return 200
    return data if isinstance(data, int) else 0


def claim_scans(api_url: str, agent_uuid: str, token: str) -> dict:
    ok, data = _post(f"{api_url}/api/scans/claim", {}, agent_uuid, token, retries=2)
    if ok:
        return {"ok": True, "data": data or []}
    return {"ok": False, "status": data}


def update_progress(api_url: str, scan_id: str, agent_uuid: str, token: str,
                    progress: int, stage: str) -> None:
    _post(f"{api_url}/api/scans/{scan_id}/progress",
          {"progress": progress, "current_stage": stage},
          agent_uuid, token, retries=1)


def submit_results(api_url: str, scan_id: str, agent_uuid: str, token: str,
                   results: dict) -> tuple[bool, Optional[dict]]:
    return _post(f"{api_url}/api/scans/{scan_id}/results", results, agent_uuid, token)


def fail_scan(api_url: str, scan_id: str, agent_uuid: str, token: str, error: str) -> None:
    _post(f"{api_url}/api/scans/{scan_id}/fail",
          {"error": error[:2000]}, agent_uuid, token, retries=1)
