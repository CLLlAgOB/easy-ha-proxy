"""Which build the panel and the host run, for the footer.

The operator keeps several gateways and needs to see, on any page, what each
one runs. Two builds meet here: the panel image's, baked in when CI built it,
and the host source's, which the update broker reads from the managed
checkout. Each is a commit -- its time orders builds, its short hash names
one -- and each carries the fingerprint of the web files it holds, so the
footer can say when the panel was built from other web files than the host
has. A panel image reused for later commits (its web files unchanged) keeps
the commit it was first built from; the fingerprints still match.
"""

from __future__ import annotations

import datetime as dt
import os
import re
from typing import Any, Optional

from . import updates_badge

_REVISION_RE = re.compile(r"^[0-9a-f]{7,64}$")
_TREE_RE = re.compile(r"^[0-9a-f]{64}$")


def _when(value: Any) -> str:
    """A commit time in UTC, so builds compare the same on every gateway."""

    try:
        moment = dt.datetime.fromisoformat(str(value or ""))
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _build(revision: Any, committed_at: Any, web_tree: Any) -> Optional[dict[str, str]]:
    revision = str(revision or "").strip().lower()
    if not _REVISION_RE.fullmatch(revision):
        return None
    tree = str(web_tree or "").strip().lower()
    return {
        "revision": revision[:7],
        "when": _when(committed_at),
        "web_tree": tree if _TREE_RE.fullmatch(tree) else "",
    }


def panel_build() -> Optional[dict[str, str]]:
    """The image's own build, from what CI passed when it built it."""

    return _build(
        os.environ.get("EHP_BUILD_REVISION"),
        os.environ.get("EHP_BUILD_DATE"),
        os.environ.get("EHP_SOURCE_TREE"),
    )


def footer() -> dict[str, Any]:
    """Both builds, and whether the panel holds the host's web files.

    match is None when either fingerprint is missing -- an image built by
    hand, or a host the broker could not read -- because then nobody knows.
    """

    panel = panel_build()
    reported = updates_badge.host_build()
    host = (
        _build(reported.get("revision"), reported.get("committed_at"), reported.get("web_tree"))
        if isinstance(reported, dict)
        else None
    )
    match = None
    if panel and host and panel["web_tree"] and host["web_tree"]:
        match = panel["web_tree"] == host["web_tree"]
    return {"panel": panel, "host": host, "match": match}
