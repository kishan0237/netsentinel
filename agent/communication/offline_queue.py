"""Offline queue: when the API is unreachable, results are persisted to disk
and re-submitted on the next successful poll (simple durability)."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("netsentinel.agent")

QUEUE_DIR = Path(__import__("os").environ.get("NETSENTINEL_HOME", Path.home() / ".netsentinel")) / "queue"


def enqueue(scan_id: str, agent_uuid: str, token: str, results: dict) -> Path:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    path = QUEUE_DIR / f"{scan_id}.json"
    path.write_text(json.dumps({
        "scan_id": scan_id, "agent_uuid": agent_uuid, "token": token, "results": results,
    }))
    return path


def dequeue_all() -> list[dict[str, Any]]:
    if not QUEUE_DIR.exists():
        return []
    items = []
    for f in sorted(QUEUE_DIR.glob("*.json")):
        try:
            items.append(json.loads(f.read_text()))
        except (OSError, ValueError):
            continue
    return items


def ack(scan_id: str) -> None:
    (QUEUE_DIR / f"{scan_id}.json").unlink(missing_ok=True)
