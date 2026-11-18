import hmac
import os
import re
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from fastapi import Header, HTTPException, Request, status

SCAN_ID_PATTERN = re.compile(r"^scan-[a-f0-9]{8}$")


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter per client IP and route group."""

    def __init__(self, group: str, env_var: str, default_limit: int, window_seconds: int = 60):
        self.group = group
        self.env_var = env_var
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _get_limit(self) -> int:
        raw = os.getenv(self.env_var, str(self.default_limit))
        try:
            return max(1, int(raw))
        except ValueError:
            return self.default_limit

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def check(self, client_key: str) -> None:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        limit = self._get_limit()

        with self._lock:
            bucket = self._hits[client_key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Terlalu banyak permintaan (Rate limit exceeded). Silakan coba lagi nanti.",
                )

            bucket.append(now)

    def __call__(self, request: Request) -> None:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        elif request.client and request.client.host:
            client_ip = request.client.host
        else:
            client_ip = "unknown"

        self.check(f"{self.group}:{client_ip}")


rate_limit_analyze = SlidingWindowRateLimiter(
    group="analyze",
    env_var="RATE_LIMIT_ANALYZE",
    default_limit=30,
    window_seconds=60,
)

rate_limit_history = SlidingWindowRateLimiter(
    group="history",
    env_var="RATE_LIMIT_HISTORY",
    default_limit=60,
    window_seconds=60,
)


def verify_admin_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """Require valid administrator API Key configured in ADMIN_API_KEY env var."""
    expected_key = os.getenv("ADMIN_API_KEY", "").strip()
    if not expected_key or not x_api_key or not hmac.compare_digest(x_api_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak: Endpoint ini memerlukan X-API-Key administrator yang valid.",
        )
    return x_api_key


def validate_scan_id(scan_id: str) -> str:
    """Ensure scan_id adheres strictly to 'scan-xxxxxxxx' hex format."""
    if not SCAN_ID_PATTERN.match(scan_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Format scan_id tidak valid. Harus mengikuti pola 'scan-xxxxxxxx'.",
        )
    return scan_id
