"""Authelia users (usersd) and bans (bansd) with the Authelia log reader."""
import copy
import json
import os

LOG = "/var/lib/easy-ha-proxy/authelia.log"
ENV = {"AUTHELIA_BANS_SOCKET": "/run/easy-ha-proxy/authelia-bans.sock", "AUTHELIA_LOG_FILE": LOG, "AUTHELIA_LOG_LIMIT": "6"}

USERS = [
    {"username": "admin", "displayname": "Admin", "email": "a@example.com", "groups": ["admins", "superadmin"], "disabled": False},
    {"username": "bob", "displayname": None, "email": "b@example.com", "groups": "ops", "disabled": 1},
    {"username": "carol", "groups": None},
    "junk",
    {"displayname": "No Name", "groups": ["zeta", 5]},
]
USERS_TABLE = """ID   Username   Expires                         Source   Reason
1    bob        2026-11-24 10:00:00 +0000 UTC   regulation  Exceeded attempts
22   алиса      never                           admin    Manual
"""
IPS_TABLE = """ID  IP              Expires  Source      Reason
7   192.0.2.10      never    regulation  too many
"""
BASE = {
    "authelia-usersd": {
        "list": {"ok": True, "users": USERS},
        "get": {"ok": True, "user": {"username": "bob", "displayname": "Bob", "email": "b@example.com", "groups": ["ops", "dev"],
                                     "disabled": True}},
        "create": {"ok": True, "user": {"username": "new"}},
        "update": {"ok": True, "user": {}},
        "delete": {"ok": True},
    },
    "authelia-bans": {
        "list": {"ok": True, "users": USERS_TABLE, "ips": IPS_TABLE},
        "revoke-user": {"ok": True, "message": "revoked user"},
        "revoke-ip": {"ok": True},
    },
}
REPLIES = BASE


def with_(daemon, **kw):
    r = copy.deepcopy(BASE)
    r[daemon].update(kw)
    return r


LINES = [
    json.dumps({"time": "2026-11-20T10:00:00Z", "level": "info", "msg": "started", "provider": "file", "zz": [1, {"b": 2, "a": None}]}),
    'time="2026-11-20T10:01:00Z" level=error msg="Unsuccessful 1FA authentication attempt by user \'bob\'" remote_ip=192.0.2.10 method=POST path=/api/firstfactor',
    "plain junk line without equals",
    'time=1 level=warn msg="unterminated',
    json.dumps({"time": "2026-11-20T10:02:00Z", "level": "ERROR", "msg": "x", "error": "boom", "username": "Алиса", "remote_ip": "",
                "flag": True, "n": 5, "f": 1.5, "empty": "", "none": None, "providers": ["a"]}, ensure_ascii=False),
    "[1, 2]",
    json.dumps({"level": "debug", "msg": "lookup 192.0.2.10 done"}),
    "   ",
    "foo=bar baz=qux",
    json.dumps({"time": "t", "level": "info", "msg": "u", "username": "carol", "remote_ip": "198.51.100.7"}),
    json.dumps({"time": "t2", "level": "info", "msg": "u2", "username": "bob"}) + "\r",
    "\xff\xfe broken bytes level=info msg=bin",
]


def setup():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "wb") as fh:
        for line in LINES:
            fh.write(line.encode("utf-8", "surrogateescape") if "\xff" not in line else b"\xff\xfe broken bytes level=info msg=bin")
            fh.write(b"\n")


def form(**kw):
    kw.setdefault("csrf_token", "CSRF")
    return {"form": kw}


STEPS = [
    ("csrf", "GET", "/system/alerts"),
    ("users", "GET", "/authelia/users"),
    ("users msg", "GET", "/authelia/users?msg=Hello+%3Cb%3E"),
    ("users fail", "GET", "/authelia/users", {"replies": with_("authelia-usersd", list={"ok": False})}),
    ("users bad list", "GET", "/authelia/users", {"replies": with_("authelia-usersd", list={"ok": True, "users": {"a": 1}})}),
    ("new page", "GET", "/authelia/users/new", {"replies": BASE}),
    ("new page fail", "GET", "/authelia/users/new", {"replies": with_("authelia-usersd", list={"ok": False, "error": "down"})}),
    ("new no name", "POST", "/authelia/users/new", dict(form(username=" ", displayname="D"), replies=BASE)),
    ("new no display", "POST", "/authelia/users/new", form(username="u")),
    ("new no email", "POST", "/authelia/users/new", form(username="u", displayname="D")),
    ("new no pw", "POST", "/authelia/users/new", form(username="u", displayname="D", email="e@x")),
    ("new mismatch", "POST", "/authelia/users/new", {"form": {"csrf_token": "CSRF", "username": "u", "displayname": "D", "email": "e@x",
                                                              "password": "a", "password2": "b", "groups": ["ops", "admins"],
                                                              "groups_extra": "x, ,ops"}}),
    ("new ok", "POST", "/authelia/users/new", {"form": {"csrf_token": "CSRF", "username": " new ", "displayname": " D ",
                                                        "email": "e@x", "password": " p ", "password2": " p ",
                                                        "groups": ["ops", "admins", "ops"], "groups_extra": "z,a"}}),
    ("new fail", "POST", "/authelia/users/new", dict(form(username="new", displayname="D", email="e@x", password="p", password2="p"),
                                                     replies=with_("authelia-usersd", create={"ok": False, "error": "exists"}))),
    ("new fail noerr", "POST", "/authelia/users/new", dict(form(username="new", displayname="D", email="e@x", password="p",
                                                                password2="p"), replies=with_("authelia-usersd", create={"ok": False}))),
    ("new bad user", "POST", "/authelia/users/new", dict(form(username="new", displayname="D", email="e@x", password="p",
                                                              password2="p"), replies=with_("authelia-usersd", create={"ok": True, "user": [1]}))),
    ("users after", "GET", "/authelia/users", {"replies": BASE}),
    ("edit page", "GET", "/authelia/users/bob"),
    ("edit page space", "GET", "/authelia/users/%20bob%20"),
    ("edit page blank", "GET", "/authelia/users/%20"),
    ("edit page fail", "GET", "/authelia/users/zed", {"replies": with_("authelia-usersd", get={"ok": False, "error": "no such user"})}),
    ("edit page bad", "GET", "/authelia/users/zed", {"replies": with_("authelia-usersd", get={"ok": True, "user": "x"})}),
    ("edit page min", "GET", "/authelia/users/zed", {"replies": with_("authelia-usersd", get={"ok": True, "user": {"groups": "g"}})}),
    ("edit required", "POST", "/authelia/users/bob", dict({"form": {"csrf_token": "CSRF", "groups": ["new1", "ops"], "password": "x"}},
                                                          replies=BASE)),
    ("edit ok", "POST", "/authelia/users/bob", {"form": {"csrf_token": "CSRF", "displayname": "Bobby", "email": "b@example.com",
                                                         "groups": ["ops"], "groups_extra": "dev, qa", "disabled": "on"}}),
    ("edit ok pw", "POST", "/authelia/users/bob", {"form": {"csrf_token": "CSRF", "displayname": "Bob", "email": "b2@example.com",
                                                            "password": " s ", "password2": " s "}}),
    ("edit fail", "POST", "/authelia/users/bob", dict(form(displayname="B", email="e"),
                                                      replies=with_("authelia-usersd", update={"ok": False, "error": "locked"}))),
    ("edit prev fail", "POST", "/authelia/users/bob", dict(form(displayname="B", email="e"),
                                                           replies=with_("authelia-usersd", get={"ok": False}))),
    ("delete self", "POST", "/authelia/users/admin/delete", dict(form(), replies=BASE)),
    ("delete ok", "POST", "/authelia/users/bob/delete", form()),
    ("delete fail", "POST", "/authelia/users/bob/delete", dict(form(), replies=with_("authelia-usersd", delete={"ok": False,
                                                                                                             "error": "nope"}))),
    ("delete fail noerr", "POST", "/authelia/users/bob/delete", dict(form(), replies=with_("authelia-usersd", delete={"ok": False}))),
    ("users msgs", "GET", "/authelia/users", {"replies": BASE}),

    ("bans", "GET", "/authelia/bans"),
    ("bans filter ip", "GET", "/authelia/bans?log_ip=192.0.2.10"),
    ("bans filter user", "GET", "/authelia/bans?log_user=%D0%B0%D0%BB%D0%B8%D1%81%D0%B0"),
    ("bans filter level", "GET", "/authelia/bans?log_level=ERROR"),
    ("bans filter none", "GET", "/authelia/bans?log_ip=203.0.113.1&log_level=info"),
    ("bans list fail", "GET", "/authelia/bans", {"replies": with_("authelia-bans", list={
        "ok": False, "error": " failed ", "rc_users": 1, "rc_ips": 0, "stderr_users": "a\n  b", "stdout_ips": "x" * 1200})}),
    ("bans list fail2", "GET", "/authelia/bans", {"replies": with_("authelia-bans", list={"ok": False, "rc_users": False,
                                                                                          "rc_ips": "0"})}),
    ("bans raw", "GET", "/authelia/bans", {"replies": with_("authelia-bans", list={"ok": True, "users": "No results.",
                                                                                    "ips": "something else\nentirely"})}),
    ("bans bad header", "GET", "/authelia/bans", {"replies": with_("authelia-bans", list={
        "ok": True, "users": "ID Name Expires Source Reason\n1 a b c d", "ips": "ID IP Expires Source Reason\n   \n"})}),
    ("bans short row", "GET", "/authelia/bans", {"replies": with_("authelia-bans", list={
        "ok": True, "users": "ID   Username   Expires   Source   Reason\n1", "ips": None})}),
    ("unban user", "POST", "/authelia/bans?log_ip=1.2.3.4&log_level=", dict(form(action="unban_user", username=" bob "), replies=BASE)),
    ("unban user bad", "POST", "/authelia/bans", form(action="unban_user", username="bo b")),
    ("unban user empty", "POST", "/authelia/bans", form(action="unban_user")),
    ("unban ip", "POST", "/authelia/bans?log_user=x&log_level=info", form(action="unban_ip", ip="192.0.2.0/24")),
    ("unban ip host bits", "POST", "/authelia/bans", form(action="unban_ip", ip="192.0.2.1/24")),
    ("unban ip bad", "POST", "/authelia/bans", form(action="unban_ip", ip="1.2.3")),
    ("unban ip chars", "POST", "/authelia/bans", form(action="unban_ip", ip="host")),
    ("unban ip empty", "POST", "/authelia/bans", form(action="unban_ip", ip=" ")),
    ("unban ip v6", "POST", "/authelia/bans", form(action="unban_ip", ip="2001:db8::/32")),
    ("unban fail", "POST", "/authelia/bans", dict(form(action="unban_ip", ip="10.0.0.1"),
                                                  replies=with_("authelia-bans", **{"revoke-ip": {"ok": False}}))),
    ("unban fail msg", "POST", "/authelia/bans", dict(form(action="unban_user", username="u"),
                                                      replies=with_("authelia-bans", **{"revoke-user": {"ok": False, "error": "e"}}))),
    ("unban unknown", "POST", "/authelia/bans", dict(form(action="zzz"), replies=BASE)),
    ("bans flashes", "GET", "/authelia/bans"),
]
