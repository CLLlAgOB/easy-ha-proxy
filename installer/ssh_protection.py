"""SSH protection (Fail2ban) management moved to the host agent ("ssh-protection").

Update brokers installed before this change still run this file; running it
forwards the command line to easy-ha-proxy-agent with the same arguments.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"
CLIENT = "/usr/bin/fail2ban-client"
DROP_IN = Path("/etc/fail2ban/jail.d/99-easy-ha-proxy-sshd.local")


def main(argv: list[str]) -> int:
    if not os.path.isfile(AGENT):
        print("ssh_protection.py: the host agent is not installed", file=sys.stderr)
        return 2
    os.execv(AGENT, [AGENT, "ssh-protection", *argv])
    return 2  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
