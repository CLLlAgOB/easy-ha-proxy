#!/usr/bin/env python3
"""Transitional shim: prepare-legacy-config moved into easy-ha-proxy-agent."""

from __future__ import annotations

import os
import sys

AGENT = os.environ.get("EASY_HA_PROXY_AGENT_BIN", "/usr/local/sbin/easy-ha-proxy-agent")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else list(argv)
    if not os.path.isfile(AGENT):
        print(
            f"ERROR: easy-ha-proxy-agent is not installed ({AGENT}).",
            file=sys.stderr,
        )
        return 2
    os.execv(AGENT, [AGENT, "prepare-legacy-config", *arguments])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
