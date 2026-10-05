import asyncio
import time
from collections import defaultdict, deque
from fastapi import HTTPException
from config.settings import settings

_events: dict[str, deque[float]] = defaultdict(deque)
_lock = asyncio.Lock()


async def enforce_scan_limit(subject: str) -> None:
    now = time.monotonic()
    cutoff = now - settings.scan_rate_window_seconds
    async with _lock:
        events = _events[subject]
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= settings.scan_rate_limit:
            raise HTTPException(status_code=429, detail='Scan limit reached. Wait briefly before scanning again.')
        events.append(now)

        if len(_events) > 10000:
            for key in list(_events):
                if not _events[key] or _events[key][-1] <= cutoff:
                    _events.pop(key, None)
