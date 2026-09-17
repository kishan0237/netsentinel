"""Agent routes: registration, heartbeat, listing."""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Agent
from app.backend.routes.deps import get_current_agent
from app.backend.schemas import AgentHeartbeat, AgentOut, AgentRegister
from app.backend.services import agent_service
from app.backend.utils.rate_limiting import get_client_ip, heartbeat_limiter, register_limiter
from app.backend.utils.secrets_management import verify_admin_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
def register_agent(
    request: Request,
    payload: AgentRegister,
    db: Session = Depends(get_db),
):
    """Register an installation. Returns the agent + its token.

    Idempotent per agent_uuid: re-registering the same installation updates
    metadata and re-issues the agent token.
    """
    register_limiter.check(get_client_ip(request), "register")
    agent, token = agent_service.register_agent(db, payload)
    logger.info("agent_registered %s", agent.agent_uuid)
    return {"agent": AgentOut.model_validate(agent).model_dump(mode="json"), "agent_token": token}


@router.post("/heartbeat", response_model=AgentOut)
def heartbeat(
    request: Request,
    payload: AgentHeartbeat,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Agent keepalive. Also lazily flips stale agents to offline."""
    heartbeat_limiter.check(get_client_ip(request), "heartbeat")
    agent_service.mark_offline_if_stale(db)
    updated = agent_service.heartbeat_agent(db, agent, payload.agent_version)
    return AgentOut.model_validate(updated).model_dump(mode="json")


@router.get("", response_model=List[AgentOut])
def list_agents(db: Session = Depends(get_db)):
    """All registered agents (used by the dashboard)."""
    agent_service.mark_offline_if_stale(db)
    agents = db.query(Agent).order_by(Agent.created_at.desc()).all()
    return [AgentOut.model_validate(a).model_dump(mode="json") for a in agents]


@router.get("/{agent_uuid}", response_model=AgentOut)
def get_agent(agent_uuid: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.agent_uuid == agent_uuid).first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    return AgentOut.model_validate(agent).model_dump(mode="json")


@router.delete("/{agent_uuid}", status_code=204)
def delete_agent(
    agent_uuid: str,
    x_admin_key: str | None = None,
    db: Session = Depends(get_db),
):
    """Remove an agent (requires ADMIN_API_KEY)."""
    if not verify_admin_key(x_admin_key):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin key required or invalid")
    agent = db.query(Agent).filter(Agent.agent_uuid == agent_uuid).first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    agent_service.delete_agent(db, agent)
