"""The update checker is the host agent's "update-plan" command.

Update brokers installed before it moved there -- the Python broker of the
1.1 releases and the Go broker before 1.2.0-alpha's checker -- run this file
to check the update they have just applied, from the source that update
installed. It hands their request to the agent that same update installed,
which prints the plan they expect. Remove it once no supported gateway runs
such a broker.
"""

from __future__ import annotations

import os
import sys

AGENT = "/usr/local/sbin/easy-ha-proxy-agent"


def main(argv: list[str]) -> int:
    arguments = list(argv)
    # Those brokers asked for the HAProxy component whenever its module was
    # in the source; it is part of the agent's checker now.
    if "--haproxy-status" not in arguments:
        arguments.append("--haproxy-status")
    if not os.path.isfile(AGENT):
        print("update_plan.py: the host agent that checks updates is not installed", file=sys.stderr)
        return 1
    os.execv(AGENT, [AGENT, "update-plan", *arguments])
    return 1  # not reached


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
