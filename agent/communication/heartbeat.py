"""Background heartbeat thread (60s interval, daemon)."""

import logging
import threading
import time

from agent.communication import api_client

logger = logging.getLogger("netsentinel.agent")

INTERVAL = 60


class HeartbeatThread(threading.Thread):
    def __init__(self, api_url: str, agent_uuid: str, token: str, version: str,
                 reauth_event: threading.Event | None = None):
        super().__init__(daemon=True, name="netsentinel-heartbeat")
        self.api_url = api_url
        self.agent_uuid = agent_uuid
        self.token = token
        self.version = version
        # Set when the server rejects the token (401/403) so the main loop
        # can re-register instead of silently staying "offline" forever.
        self.reauth_event = reauth_event or threading.Event()
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.wait(INTERVAL):
            try:
                status = api_client.heartbeat(self.api_url, self.agent_uuid, self.token, self.version)
                if status in (401, 403):
                    logger.warning("Heartbeat rejected (%s) — signalling re-registration", status)
                    self.reauth_event.set()
                elif status == 0:
                    logger.debug("Heartbeat network error — will retry")
            except Exception as e:  # never die
                logger.debug("Heartbeat error: %s", e)

    def stop(self) -> None:
        self._stop_event.set()
