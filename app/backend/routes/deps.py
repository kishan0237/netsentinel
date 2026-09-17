"""Shared route dependencies."""

from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Agent
from app.backend.utils.secrets_management import verify_agent_token


def bearer_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    """Extract Bearer token from the Authorization header."""
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def get_current_agent(
    x_agent_uuid: Optional[str] = Header(None),
    token: Optional[str] = Depends(bearer_token),
    db: Session = Depends(get_db),
) -> Agent:
    """Authenticate an agent: X-Agent-UUID header + Bearer agent token.

    Tokens are issued at registration (POST /api/agents/register). Agents
    re-register automatically if the token is rejected (e.g. API restart).
    """
    if not x_agent_uuid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-Agent-UUID header")
    agent = db.query(Agent).filter(Agent.agent_uuid == x_agent_uuid).first()
    if not agent:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown agent")
    if not verify_agent_token(x_agent_uuid, token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing agent token")
    return agent
