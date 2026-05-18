from __future__ import annotations

import os
import time
from collections import defaultdict, deque

RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "12"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

_BUCKETS: dict[str, deque] = defaultdict(deque)

def check_rate_limit(client_key: str) -> dict:
    now = time.time()
    bucket = _BUCKETS[client_key]

    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_REQUESTS:
        retry_after = int(RATE_LIMIT_WINDOW_SECONDS - (now - bucket[0])) if bucket else RATE_LIMIT_WINDOW_SECONDS
        return {
            "allowed": False,
            "limit": RATE_LIMIT_REQUESTS,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "retry_after": max(retry_after, 1),
        }

    bucket.append(now)
    return {
        "allowed": True,
        "limit": RATE_LIMIT_REQUESTS,
        "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        "remaining": max(RATE_LIMIT_REQUESTS - len(bucket), 0),
    }
