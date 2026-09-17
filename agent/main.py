#!/usr/bin/env python3
"""NetSentinel Agent v1.0.0

Runs on the user's machine. Registers with the Render API using a persistent
installation ID, polls for scan jobs, executes the scanning pipeline locally
and streams progress/results back. No user account required.
"""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

# Allow `python main.py` from any directory: put the project root on sys.path
# so the `agent` package resolves.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.communication import api_client  # noqa: E402
from agent.communication import offline_queue  # noqa: E402
from agent.communication.heartbeat import HeartbeatThread
from agent.scanner.pipeline import ScanPipeline
from agent.security.agent_identity import AgentIdentity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netsentinel.agent")

VERSION = "1.0.0"
POLL_INTERVAL = int(__import__("os").environ.get("AGENT_POLL_INTERVAL", "3"))


class NetSentinelAgent:
    def __init__(self, api_url: str):
        self.api_url = api_url.rstrip("/")
        self.identity = AgentIdentity()
        self.pipeline = ScanPipeline()
        self.heartbeat: HeartbeatThread | None = None
        self._stop = False

    def start(self) -> None:
        logger.info("NetSentinel Agent v%s", VERSION)
        logger.info("API: %s", self.api_url)

        identity = self.identity.load_or_create()
        logger.info("Installation ID: %s", identity["agent_uuid"])

        if not self._register():
            logger.error("Registration failed — check API URL and network. Retrying on next loop.")
            return self._run_loop(register_first=True)

        self.heartbeat = HeartbeatThread(
            self.api_url, identity["agent_uuid"], self.identity.token, VERSION
        )
        self.heartbeat.start()
        logger.info("Agent registered. Waiting for scan jobs...")
        self._run_loop()

    def _register(self) -> bool:
        identity = self.identity.load_or_create()
        ok, data = api_client.register(
            self.api_url,
            identity["agent_uuid"],
            identity["hostname"],
            identity["platform"],
            VERSION,
        )
        if ok and data:
            self.identity.token = data.get("agent_token", "")
            self.identity.save()
            logger.info("Registered with server.")
            return True
        logger.warning("Registration failed: %s", data)
        return False

    def _run_loop(self, register_first: bool = False) -> None:
        backoff = 5
        while not self._stop:
            try:
                if register_first:
                    register_first = False
                    time.sleep(POLL_INTERVAL)
                    if self._register():
                        self.heartbeat = HeartbeatThread(
                            self.api_url, self.identity.agent_uuid, self.identity.token, VERSION
                        )
                        self.heartbeat.start()
                    continue

                self._poll_once()
                backoff = 5
            except KeyboardInterrupt:
                break
            except Exception as e:  # keep the agent alive no matter what
                logger.warning("Poll error: %s — retrying in %ss", e, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)

    def _poll_once(self) -> None:
        if not self.identity.token:
            if not self._register():
                time.sleep(POLL_INTERVAL)
                return

        # Retry any results that failed to submit earlier (offline queue)
        self._flush_offline_queue()

        claimed = api_client.claim_scans(
            self.api_url, self.identity.agent_uuid, self.identity.token
        )
        if not claimed.get("ok"):
            # Token likely invalidated (API restart) — re-register once
            if claimed.get("status") in (401, 403):
                self.identity.token = ""
                if not self._register():
                    time.sleep(POLL_INTERVAL)
            return

        for scan in claimed.get("data") or []:
            self._run_scan(scan)

    def _flush_offline_queue(self) -> None:
        for item in offline_queue.dequeue_all():
            ok, _ = api_client.submit_results(
                self.api_url, item["scan_id"], item["agent_uuid"], item["token"],
                item["results"],
            )
            if ok:
                offline_queue.ack(item["scan_id"])
                logger.info("Flushed queued results for scan %s", item["scan_id"][:8])
            else:
                break  # server still unreachable; try again next poll

    def _run_scan(self, scan: dict) -> None:
        scan_id = scan["id"]
        target = scan["target"]
        scan_type = scan.get("scan_type", "standard")
        ports = scan.get("ports")
        logger.info("Starting scan %s on %s (%s)", scan_id[:8], target, scan_type)

        def on_progress(pct: int, stage: str) -> None:
            api_client.update_progress(
                self.api_url, scan_id, self.identity.agent_uuid, self.identity.token, pct, stage
            )
            logger.info("[%s] %s — %d%%", scan_id[:8], stage, pct)

        try:
            results = self.pipeline.run(target, scan_type, ports, on_progress)
        except Exception as e:
            logger.error("Scan %s failed: %s", scan_id[:8], e)
            api_client.fail_scan(
                self.api_url, scan_id, self.identity.agent_uuid, self.identity.token, str(e)
            )
            return

        ok, data = api_client.submit_results(
            self.api_url, scan_id, self.identity.agent_uuid, self.identity.token, results
        )
        if ok:
            counts = (data or {}).get("counts", {})
            logger.info(
                "Scan %s complete: %s hosts, %s ports, %s services, %s vulns, %s findings",
                scan_id[:8], counts.get("hosts", "?"), counts.get("ports", "?"),
                counts.get("services", "?"), counts.get("vulnerabilities", "?"),
                counts.get("findings", "?"),
            )
        else:
            # Persist locally so the next poll retries the submission
            offline_queue.enqueue(scan_id, self.identity.agent_uuid, self.identity.token, results)
            logger.error(
                "Result submission failed (%s) — queued locally, will retry every poll", data
            )

    def stop(self, *_args) -> None:
        logger.info("Shutting down...")
        self._stop = True
        if self.heartbeat:
            self.heartbeat.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="NetSentinel Agent")
    parser.add_argument("--api-url", default=api_client.default_api_url(),
                        help="Base URL of the NetSentinel API (Render)")
    parser.add_argument("--id", help="Override installation ID (NS-XXXX-XXXX)")
    args = parser.parse_args()

    agent = NetSentinelAgent(args.api_url)
    if args.id:
        agent.identity.override_id(args.id)
    signal.signal(signal.SIGINT, agent.stop)
    signal.signal(signal.SIGTERM, agent.stop)

    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
    return sys.exit(0)


if __name__ == "__main__":
    main()
