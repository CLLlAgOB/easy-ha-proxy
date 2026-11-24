"""Authelia bans through the CLI helper (no bansd socket) and a missing log file."""
import os

ENV = {"AUTHELIA_BANS_SOCKET": "", "AUTHELIA_BANS_CMD": "/srv/bans.sh --flag 'two words'",
       "AUTHELIA_LOG_FILE": "/var/lib/easy-ha-proxy/missing.log"}

SCRIPT = """#!/bin/sh
echo "$@" >> /srv/bans.calls
case "$3" in
  list-users) printf 'ID  Username  Expires  Source  Reason\\n5   eve       never    admin   x\\n' ;;
  list-ips) grep -q revoke-user /srv/bans.calls &&{ echo "no db" >&2; exit 3; }; echo "No results." ;;
  revoke-user) echo done ;;
  revoke-ip) echo "denied" >&2; exit 4 ;;
esac
"""


def setup():
    with open("/srv/bans.sh", "w") as fh:
        fh.write(SCRIPT)
    os.chmod("/srv/bans.sh", 0o755)
    for p in ("/srv/bans.calls", "/srv/ips.fail"):
        if os.path.exists(p):
            os.unlink(p)


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("bans", "GET", "/authelia/bans"),
    ("unban user", "POST", "/authelia/bans", form(action="unban_user", username="eve")),
    ("unban ip", "POST", "/authelia/bans", form(action="unban_ip", ip="10.0.0.0/8")),
    ("bans flashes", "GET", "/authelia/bans"),
]
