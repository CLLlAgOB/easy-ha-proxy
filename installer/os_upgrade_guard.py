"""The OS upgrade guard moved to the host agent ("os-upgrade-guard").

Older playbooks or operators invoking this script directly are forwarded to
easy-ha-proxy-agent with the same arguments.
"""

from __future__ import annotations

import os
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"


def main(argv: list[str]) -> int:
    if not os.path.isfile(AGENT):
        print("os_upgrade_guard.py: the host agent is not installed", file=sys.stderr)
        return 2
    os.execv(AGENT, [AGENT, "os-upgrade-guard", *argv])
    return 2  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
