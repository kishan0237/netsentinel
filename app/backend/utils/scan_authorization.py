"""Scan authorization: which agent may act on which scan.

The architecture has no users, so "authorization" here means: an agent may
only claim/result its own scans. Scan creation from the web dashboard picks a
random online agent; the agent picks up pending scans on its next poll.
"""

from typing import Optional

from fastapi import HTTPException, status

from app.backend.database.models import Agent, Scan
from app.backend.utils.secrets_management import verify_agent_token


def require_agent(scan: Scan, agent_uuid: str, token: Optional[str]) -> Agent:
    """Verify the caller is the scan's owning agent with a valid token."""
    owner = scan.agent
    if owner is None or owner.agent_uuid != agent_uuid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scan does not belong to this agent",
        )
    if not verify_agent_token(agent_uuid, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing agent token",
        )
    return owner


def resolve_scan_or_404(db, scan_id) -> Scan:
    scan = db.get(Scan, str(scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def pick_online_agent(db) -> Optional[Agent]:
    """Pick a random online agent for a new scan (first available wins)."""
    agent = db.query(Agent).filter(Agent.status == "online").first()
    return agent
