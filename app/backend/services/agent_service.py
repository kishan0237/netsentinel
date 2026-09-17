"""Agent lifecycle service: register, heartbeat, status updates."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.backend.database.models import Agent
from app.backend.schemas import AgentRegister
from app.backend.utils.secrets_management import issue_agent_token


def register_agent(db: Session, payload: AgentRegister) -> tuple[Agent, str]:
    """Create or update an agent registration.

    Returns (agent, agent_token). The token is regenerated on every register
    call from the same agent_uuid — it acts as an installation credential.
    """
    agent = db.query(Agent).filter(Agent.agent_uuid == payload.agent_uuid).first()
    if agent is None:
        agent = Agent(agent_uuid=payload.agent_uuid)
        db.add(agent)

    agent.agent_name = payload.agent_name or agent.agent_name
    agent.hostname = payload.hostname or agent.hostname
    agent.platform = payload.platform or agent.platform
    agent.agent_version = payload.agent_version or agent.agent_version
    agent.status = "online"
    agent.last_heartbeat = datetime.now(timezone.utc)

    db.commit()
    db.refresh(agent)

    token = issue_agent_token(agent.agent_uuid)
    return agent, token


def heartbeat_agent(db: Session, agent: Agent, version: Optional[str] = None) -> Agent:
    agent.status = "online"
    agent.last_heartbeat = datetime.now(timezone.utc)
    if version:
        agent.agent_version = version
    db.commit()
    db.refresh(agent)
    return agent


def mark_offline_if_stale(db: Session, stale_after_minutes: int = 2) -> int:
    """Flip agents whose last heartbeat is older than the threshold to offline.

    Called opportunistically from heartbeat endpoints; keeps the dashboard
    honest without a background scheduler.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_after_minutes)
    stale = (
        db.query(Agent)
        .filter(Agent.status == "online")
        .filter(Agent.last_heartbeat.isnot(None))
        .filter(Agent.last_heartbeat < cutoff)
        .all()
    )
    for agent in stale:
        agent.status = "offline"
    if stale:
        db.commit()
    return len(stale)


def delete_agent(db: Session, agent: Agent) -> None:
    from app.backend.utils.secrets_management import revoke_agent_token

    revoke_agent_token(agent.agent_uuid)
    db.delete(agent)
    db.commit()
