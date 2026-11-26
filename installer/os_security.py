"""Managed OS security updates moved to the host agent ("os-security").

Update brokers installed before this change still look for this file and its
protocol markers; running it forwards the command line to easy-ha-proxy-agent.
The tiny read_json and local_time helpers stay until haproxy_package_migrate.py
moves to Go in Step 5.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import stat
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"
PROTOCOL = 1
SETTINGS_PROTOCOL = 1
MAX_JSON = 1024 * 1024


def local_time(now=None):
    return (dt.datetime.now() if now is None else now).astimezone()


def read_json(path):
    """Read a root-owned, non-symlink JSON object (used by haproxy_package_migrate)."""
    info = Path(path).lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or not 0 < info.st_size <= MAX_JSON
    ):
        raise ValueError("Unsafe OS security state")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("OS security state changed while opening")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_JSON + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_JSON:
        raise ValueError("Unsafe OS security state")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid OS security state")
    return value


def main(argv: list[str]) -> int:
    if not os.path.isfile(AGENT):
        print("os_security.py: the host agent is not installed", file=sys.stderr)
        return 2
    os.execv(AGENT, [AGENT, "os-security", *argv])
    return 2  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
