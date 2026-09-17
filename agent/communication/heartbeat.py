"""Background heartbeat thread (60s interval, daemon)."""

import logging
import threading
import time

from agent.communication import api_client

logger = logging.getLogger("netsentinel.agent")

INTERVAL = 60


class HeartbeatThread(threading.Thread):
    def __init__(self, api_url: str, agent_uuid: str, token: str, version: str):
        super().__init__(daemon=True, name="netsentinel-heartbeat")
        self.api_url = api_url
        self.agent_uuid = agent_uuid
        self.token = token
        self.version = version
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.wait(INTERVAL):
            try:
                if not api_client.heartbeat(self.api_url, self.agent_uuid, self.token, self.version):
                    logger.debug("Heartbeat rejected — agent may need re-registration")
            except Exception as e:  # never die
                logger.debug("Heartbeat error: %s", e)

    def stop(self) -> None:
        self._stop_event.set()
