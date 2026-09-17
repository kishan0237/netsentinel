"""Secrets management: agent token + admin API key verification.

The agent identity model (per the architecture): "this request belongs to this
installed NetSentinel agent". On registration the server issues an opaque
agent token. The agent sends it as `Authorization: Bearer <agent_token>` on
subsequent agent calls; the dashboard/UI endpoints use the public `agent_uuid`
for read-only identification.

ADMIN_API_KEY guards destructive/internal endpoints (e.g., deleting agents).
"""

import os
import secrets
import shlex
from typing import Optional

import hmac

_agent_tokens: dict[str, str] = {}


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def get_admin_api_key() -> Optional[str]:
    return os.getenv("ADMIN_API_KEY")


def verify_admin_key(provided: Optional[str]) -> bool:
    expected = get_admin_api_key()
    if not expected:
        return False  # admin endpoints disabled unless key configured
    if not provided:
        return False
    return _constant_time_eq(provided, expected)


def issue_agent_token(agent_uuid: str) -> str:
    """Generate and remember a fresh token for an agent (called on register/re-auth)."""
    token = secrets.token_urlsafe(32)
    _agent_tokens[agent_uuid] = token
    return token


def verify_agent_token(agent_uuid: str, provided: Optional[str]) -> bool:
    expected = _agent_tokens.get(agent_uuid)
    if not expected:
        return False
    if not provided:
        return False
    return _constant_time_eq(provided, expected)


def revoke_agent_token(agent_uuid: str) -> None:
    _agent_tokens.pop(agent_uuid, None)


def generate_installation_id() -> str:
    """Generate an NS-XXXX-XXXX installation ID (agent side; kept here for tests)."""
    raw = secrets.token_hex(4).upper()
    return f"NS-{raw[:4]}-{raw[4:8]}"


def redact_secrets(payload: dict) -> dict:
    """Return a copy of payload with secret-looking keys redacted (for logging)."""
    secret_keys = {"token", "agent_token", "admin_key", "api_key", "password", "secret"}
    out = {}
    for k, v in payload.items():
        if any(sk in k.lower() for sk in secret_keys):
            out[k] = "***"
        else:
            out[k] = v
    return out


def safe_shell_join(args: list) -> str:
    """Join args for logging; never used for execution."""
    return shlex.join(str(a) for a in args)
