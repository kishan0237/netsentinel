"""Simple token-bucket rate limiter for FastAPI routes.

Backed by an in-process dict. Fine for a single Render instance; for multiple
instances swap the storage for Redis later without changing the interface.
"""

import os
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple

from fastapi import HTTPException, Request, status


class TokenBucketLimiter:
    """Fixed-window sliding limiter keyed by (client_ip, bucket_name)."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: Tuple[str, str], now: float) -> None:
        window_start = now - self.window_seconds
        dq = self._hits[key]
        while dq and dq[0] < window_start:
            dq.popleft()

    def check(self, client_ip: str, bucket: str = "default") -> None:
        """Raise 429 if the client has exceeded the limit for this bucket."""
        now = time.monotonic()
        key = (client_ip, bucket)
        with self._lock:
            self._prune(key, now)
            dq = self._hits[key]
            if len(dq) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (now - dq[0])))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Retry in {retry_after}s.",
                )
            dq.append(now)

    def dependency(self, bucket: str = "default") -> Callable[[Request], None]:
        """Return a FastAPI dependency bound to a named bucket."""

        def _dep(request: Request) -> None:
            self.check(request.client.host if request.client else "unknown", bucket)

        return _dep


def _limit(env_var: str, default: int) -> int:
    try:
        return int(os.getenv(env_var, str(default)))
    except ValueError:
        return default


# Shared limiters, used via Depends(). Tunable via env for tests/deployments.
general_limiter = TokenBucketLimiter(_limit("RATE_LIMIT_GENERAL", 120), 60)
scan_create_limiter = TokenBucketLimiter(_limit("RATE_LIMIT_SCAN_CREATE", 10), 60)
register_limiter = TokenBucketLimiter(_limit("RATE_LIMIT_REGISTER", 20), 60)
heartbeat_limiter = TokenBucketLimiter(_limit("RATE_LIMIT_HEARTBEAT", 240), 60)


def get_client_ip(request: Request) -> str:
    """Client IP honoring Render/Vercel proxy headers."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"
