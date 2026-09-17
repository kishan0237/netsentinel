"""Agent identity: installation-generated ID + token, persisted locally.

The identity file lives next to the agent (or ~/.netsentinel). It contains no
user data — just the installation ID, hostname/platform metadata and the token
issued by the server at registration.
"""

import json
import os
import platform
import socket
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path(os.environ.get("NETSENTINEL_HOME", Path.home() / ".netsentinel"))
CONFIG_FILE = CONFIG_DIR / "agent.json"


def generate_installation_id() -> str:
    """NS-XXXX-XXXX using a crypto-strong RNG."""
    import secrets as _secrets

    raw = _secrets.token_hex(4).upper()
    return f"NS-{raw[:4]}-{raw[4:8]}"


class AgentIdentity:
    def __init__(self) -> None:
        self.agent_uuid: str = ""
        self.token: str = ""
        self.hostname: str = socket.gethostname()
        self.platform_name: str = f"{platform.system()} {platform.release()}".strip()

    def override_id(self, agent_uuid: str) -> None:
        self.agent_uuid = agent_uuid
        self.token = ""

    def load_or_create(self) -> dict:
        if not self.agent_uuid:
            data = self._read()
            if data:
                self.agent_uuid = data.get("agent_uuid", "")
                self.token = data.get("token", "")
        if not self.agent_uuid:
            self.agent_uuid = generate_installation_id()
            self.token = ""
            logger_new = __import__("logging").getLogger("netsentinel.agent")
            logger_new.info("Generating new installation ID...")
            self.save()
        return {
            "agent_uuid": self.agent_uuid,
            "hostname": self.hostname,
            "platform": self.platform_name,
        }

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps({
            "agent_uuid": self.agent_uuid,
            "token": self.token,
        }, indent=2))
        try:
            CONFIG_FILE.chmod(0o600)  # owner-only on POSIX
        except OSError:
            pass

    def _read(self) -> Optional[dict]:
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (OSError, ValueError):
            return None
