"""HAProxy package migration and patching moved to the host agent ("haproxy-migrate").

Update brokers installed before this change still look for this file and its
protocol markers; running it forwards the command line to easy-ha-proxy-agent.
Remove it once no supported gateway runs such a broker.
"""

from __future__ import annotations

import os
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"
WEB_MIGRATION_PROTOCOL = 1
AUTOMATIC_MIGRATION_PROTOCOL = 1


def main(argv: list[str]) -> int:
    if not os.path.isfile(AGENT):
        print("haproxy_package_migrate.py: the host agent is not installed", file=sys.stderr)
        return 2
    os.execv(AGENT, [AGENT, "haproxy-migrate", *argv])
    return 2  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
