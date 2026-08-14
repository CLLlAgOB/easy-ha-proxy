#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ask the backup daemon to run the scheduled copy, and report its verdict.

Deliberately tiny: the timer needs an exit code and the daemon owns the
maintenance lock, the passphrase and the destinations. Nothing about the
backup itself is decided here.
"""

from __future__ import annotations

import json
import os
import socket
import sys

SOCKET_PATH = os.environ.get(
    "BACKUPD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock"
)
TIMEOUT_SECONDS = int(os.environ.get("BACKUPD_SCHEDULED_TIMEOUT", str(8 * 3600)))


def main() -> int:
    # The daemon reads one newline-terminated JSON line and refuses anything
    # else. Closing the write side is not a substitute for the terminator.
    request = (json.dumps({"action": "run_scheduled"}) + "\n").encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(TIMEOUT_SECONDS)
            client.connect(SOCKET_PATH)
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as exc:
        print(f"the backup daemon is unreachable: {exc}", file=sys.stderr)
        return 2

    try:
        answer = json.loads(b"".join(chunks).decode("utf-8"))
    except ValueError:
        print("the backup daemon returned an unreadable answer", file=sys.stderr)
        return 2

    if answer.get("skipped"):
        print(answer["skipped"])
        return 0
    if answer.get("ok"):
        print(
            f"backup {answer.get('backup_id', '')} copied to "
            f"{len(answer.get('uploads') or [])} destination(s)"
        )
        return 0
    for problem in answer.get("errors") or [answer.get("error", "unknown")]:
        print(problem, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
