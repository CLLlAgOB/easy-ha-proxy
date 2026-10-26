"""The dot in the navigation that says software updates are waiting.

It is rendered with the page, so it never pops in after load. The answer
comes from the update broker's newest check and is kept for a minute per
worker: at most one small request a minute, with a short timeout, and a page
never waits on, or fails for, a broker that is busy or gone -- the dot is
simply not shown. Only a superadmin sees it, as only a superadmin can
install anything.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from flask import g

from .updated_client import updated_request


BADGE_TTL_SECONDS = 60.0
BADGE_TIMEOUT_SECONDS = 1.0
LEVELS = ("product", "os")

_lock = threading.Lock()
_cache: dict[str, Any] = {"at": None, "level": None}


def remember(summary: Any) -> Optional[str]:
    """Store what a broker answer says; the updates page calls this on
    every poll, so the dot follows a check or an installation at once."""
    level = summary.get("level") if isinstance(summary, dict) else None
    level = level if level in LEVELS else None
    with _lock:
        _cache["at"] = time.monotonic()
        _cache["level"] = level
    return level


def forget() -> None:
    with _lock:
        _cache["at"] = None
        _cache["level"] = None


def current_level() -> Optional[str]:
    """"product", "os" or None for the page being rendered."""
    if not getattr(g, "is_superadmin", False):
        return None
    with _lock:
        at = _cache["at"]
        if at is not None and time.monotonic() - at < BADGE_TTL_SECONDS:
            return _cache["level"]
    try:
        result = updated_request({"action": "summary"}, timeout=BADGE_TIMEOUT_SECONDS)
    except Exception:  # pylint: disable=broad-except - a nav dot must never cost a page
        result = None
    return remember(result if isinstance(result, dict) and result.get("ok") else None)
