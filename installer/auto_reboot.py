"""Scheduled automatic reboots moved to the host agent ("auto-reboot").

Update brokers installed before this change still look for this file and its
protocol markers; running it forwards the command line to easy-ha-proxy-agent.
Remove it once no supported gateway runs such a broker.
"""

from __future__ import annotations

import os
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"
AUTO_REBOOT_PROTOCOL = 1
SERVICE_REBOOT_PROTOCOL = 1


def main(argv: list[str]) -> int:
    if not os.path.isfile(AGENT):
        print("auto_reboot.py: the host agent is not installed", file=sys.stderr)
        return 2
    os.execv(AGENT, [AGENT, "auto-reboot", *argv])
    return 2  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
