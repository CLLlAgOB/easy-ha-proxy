"""The encrypted full backup is the host agent's "full-backup" command.

Backup brokers installed before it moved there, and anyone used to running
this file, still find it: it hands the command line to the agent
("backup", "inspect" or "restore", with the same options). The archive
format is unchanged, so archives of either remain readable by the other.
Remove it once no supported gateway runs such a broker.
"""

from __future__ import annotations

import os
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"


def main(argv: list[str]) -> int:
    if not os.path.isfile(AGENT):
        print("full_backup.py: the host agent that makes and restores backups is not installed", file=sys.stderr)
        return 2
    os.execv(AGENT, [AGENT, "full-backup", *argv])
    return 2  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
