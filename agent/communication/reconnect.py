"""Reconnection helper: exponential backoff wrapper around registration."""

import logging
import time
from typing import Callable

logger = logging.getLogger("netsentinel.agent")


def retry_with_backoff(fn: Callable[[], bool], max_wait: int = 60) -> bool:
    """Call fn() until it returns True, doubling waits up to max_wait."""
    wait = 2
    while True:
        try:
            if fn():
                return True
        except Exception as e:
            logger.warning("retry_with_backoff: %s", e)
        logger.info("Reconnecting in %ss...", wait)
        time.sleep(wait)
        wait = min(wait * 2, max_wait)
