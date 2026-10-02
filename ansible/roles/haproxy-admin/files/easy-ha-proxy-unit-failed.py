#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report a failed systemd unit to the alert engine.

Every daemon here reports its own failures, which leaves one gap: a job that
dies before it reaches its daemon. The scheduled backup did exactly that for
weeks -- the runner could not make itself understood, the unit failed, and
because backupd was never asked to do anything, nothing had a failure to
report. systemd knew. Nobody else did.

Wired in as `OnFailure=`, this closes that gap for the jobs whose failure has
a rule in the catalogue. It is deliberately incapable of anything else: no
unit outside the map is reportable, and a missing token means a silent exit
rather than a retry loop.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from easy_ha_proxy_alert_client import AlertClient  # type: ignore[import]
except Exception:  # pragma: no cover - a gateway without the alert engine
    AlertClient = None  # type: ignore[assignment]


# Only units whose failure the catalogue already has a rule for. A unit that
# is not here is not reportable, which is safer than inventing a rule name
# the engine will reject anyway.
RULES = {
    "easy-ha-proxy-backup.service": ("backup.failed", "Scheduled backup failed"),
}

JOURNAL_LINES = 12
JOURNAL_TIMEOUT_SECONDS = 10
MAX_DETAIL_CHARS = 1200


def _properties(unit: str) -> dict:
    """systemd's verdict, and the id that isolates this one run.

    Result is the verdict -- exit-code, timeout, signal. InvocationID is what
    keeps last night's failure out of tonight's report.
    """
    try:
        output = subprocess.run(
            [
                "systemctl", "show", unit,
                "--property=Result",
                "--property=InvocationID",
            ],
            capture_output=True,
            text=True,
            timeout=JOURNAL_TIMEOUT_SECONDS,
            check=False,
        ).stdout
    except Exception:  # pylint: disable=broad-except
        return {}
    values = {}
    for line in output.splitlines():
        name, _, value = line.partition("=")
        if name:
            values[name.strip()] = value.strip()
    return values


def _result(unit: str) -> str:
    return _properties(unit).get("Result", "")


def _last_words(unit: str, invocation: str = "") -> str:
    """What the job itself said before it died.

    Not a plain tail: a service writes its stderr to the journal at INFO,
    while systemd's own "Failed with result" lines come in at warning and
    error. Filtering by priority therefore keeps the boilerplate and throws
    away the message -- which is the whole reason anyone reads this. Select
    by who wrote the line instead, and by which run it belongs to.
    """
    selector = (
        [f"_SYSTEMD_INVOCATION_ID={invocation}"] if invocation else ["--unit", unit]
    )
    try:
        output = subprocess.run(
            [
                "journalctl",
                *selector,
                "--lines", str(JOURNAL_LINES),
                "--no-pager",
                "--output", "json",
            ],
            capture_output=True,
            text=True,
            timeout=JOURNAL_TIMEOUT_SECONDS,
            check=False,
        ).stdout
    except Exception:  # pylint: disable=broad-except
        return ""

    lines = []
    for raw in output.splitlines():
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        # systemd narrates every unit; the unit's own words are the payload.
        if entry.get("SYSLOG_IDENTIFIER") == "systemd":
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, list):  # journald sends binary blobs as arrays
            continue
        message = str(message or "").strip()
        if message:
            lines.append(message)
    return " | ".join(lines[-JOURNAL_LINES:])[:MAX_DETAIL_CHARS]


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: easy-ha-proxy-unit-failed.py <unit>", file=sys.stderr)
        return 2
    unit = argv[1].strip()
    known = RULES.get(unit)
    if known is None:
        print(f"no alert rule is defined for {unit}", file=sys.stderr)
        return 0

    rule, title = known
    if AlertClient is None:
        print("the alert client is not installed", file=sys.stderr)
        return 0
    client = AlertClient(source="systemd")
    if not client.configured:
        print("the alert engine is not configured", file=sys.stderr)
        return 0

    properties = _properties(unit)
    result = properties.get("Result", "")
    detail = (
        _last_words(unit, properties.get("InvocationID", ""))
        or "see journalctl -u " + unit
    )
    summary = f"{title} ({result})" if result else title
    # An event, not a level: the job has already failed by the time systemd
    # runs this, and nothing will ever report it as no longer true.
    delivered = client.observe(rule, unit, summary=summary, detail=detail)
    if not delivered:
        print("the alert engine did not accept the report", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
