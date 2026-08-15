"""Deciding when an error has to be JSON, and what to put in it.

Kept apart from the application factory, and free of Flask, so the rule can
be read and tested on its own. The rule exists because of a real failure:
saving an off-host backup destination was refused fourteen times in a row on
a production gateway, and the operator saw "Не сохранено" every time. The
server had said exactly what was wrong -- `abort(400, description="the
destination name may use a-z, 0-9 and dashes")` -- but Flask renders an
abort as an HTML page, and the browser parses the body as JSON and falls
back to a generic message when that fails.
"""

from __future__ import annotations

# Everything under these answers machines, not browsers looking at pages.
API_PREFIXES = ("/api/", "/system/backups/api/", "/system/updates/api/")


def caller_parses_json(path: str, is_json: bool = False) -> bool:
    """Whether the caller will read the body as JSON.

    A request that arrived as JSON is answered as JSON wherever it was sent,
    which covers the endpoints that live outside the API prefixes.
    """
    return bool(path.startswith(API_PREFIXES) or is_json)


def error_reason(description: str | None, name: str | None) -> str:
    """The most specific thing that can be said about a rejection.

    `description` is what an `abort(..., description=...)` supplied and is
    the only part an operator can act on. `name` is the generic status text
    -- "Not Found" -- which is all a bare `abort(404)` leaves behind.
    """
    for candidate in (description, name):
        text = " ".join(str(candidate or "").split())
        if text:
            return text
    return "The request was refused"
