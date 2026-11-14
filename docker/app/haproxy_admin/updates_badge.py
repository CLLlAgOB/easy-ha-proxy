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
_cache: dict[str, Any] = {"at": None, "level": None, "build": None}


def remember(summary: Any) -> Optional[str]:
    """Store what a broker answer says; the updates page calls this on
    every poll, so the dot follows a check or an installation at once.
    The same answer says which build the host runs, for the footer."""
    level = summary.get("level") if isinstance(summary, dict) else None
    level = level if level in LEVELS else None
    build = summary.get("build") if isinstance(summary, dict) else None
    with _lock:
        _cache["at"] = time.monotonic()
        _cache["level"] = level
        _cache["build"] = build if isinstance(build, dict) else None
    return level


def forget() -> None:
    with _lock:
        _cache["at"] = None
        _cache["level"] = None
        _cache["build"] = None


def _fresh() -> dict[str, Any]:
    """The cached broker answer, asked again when a minute old."""
    with _lock:
        at = _cache["at"]
        if at is not None and time.monotonic() - at < BADGE_TTL_SECONDS:
            return dict(_cache)
    try:
        result = updated_request({"action": "summary"}, timeout=BADGE_TIMEOUT_SECONDS)
    except Exception:  # pylint: disable=broad-except - a nav dot must never cost a page
        result = None
    remember(result if isinstance(result, dict) and result.get("ok") else None)
    with _lock:
        return dict(_cache)


def current_level() -> Optional[str]:
    """"product", "os" or None for the page being rendered."""
    if not getattr(g, "is_superadmin", False):
        return None
    return _fresh()["level"]


def host_build() -> Optional[dict[str, Any]]:
    """The build the host's managed source is at, as the broker reports it."""
    return _fresh()["build"]
